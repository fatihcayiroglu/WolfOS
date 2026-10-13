//! P1 x86-64 GDT, TSS/IST, IDT and CPU exception diagnostics.
//! Single-core boot only. External IRQs stay masked; SMP is not initialized.
//! A dedicated double-fault IST stack protects against common stack failures.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;

use x86_64::instructions::segmentation::{CS, DS, ES, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};
use x86_64::structures::idt::{
    InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode,
};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::{VirtAddr, registers::control::Cr2};

use crate::serial;

const DOUBLE_FAULT_IST_INDEX: u16 = 0;
const DOUBLE_FAULT_STACK_SIZE: usize = 4096 * 5;

#[repr(align(16))]
struct AlignedStack([u8; DOUBLE_FAULT_STACK_SIZE]);

// SAFETY: the stack is referenced only by its raw address. It is exclusively
// used by the CPU for double-fault handling; never read/written through Rust.
static mut DOUBLE_FAULT_STACK: AlignedStack = AlignedStack([0; DOUBLE_FAULT_STACK_SIZE]);

/// One-time boot storage. No other CPU or interrupt handler may initialize it.
struct BootCell<T>(UnsafeCell<MaybeUninit<T>>);

// SAFETY: initialization occurs once on the boot CPU with interrupts disabled.
// No mutable references escape once the object has been installed in the CPU.
unsafe impl<T> Sync for BootCell<T> {}

impl<T> BootCell<T> {
    const fn new() -> Self {
        Self(UnsafeCell::new(MaybeUninit::uninit()))
    }

    /// # Safety
    /// Call precisely once and only during serialized early boot. The
    /// returned address must outlive every CPU table reference to it.
    unsafe fn initialize(&'static self, value: T) -> &'static T {
        // SAFETY: one-time initialization under the boot-only contract.
        unsafe {
            (*self.0.get()).write(value);
            &*(*self.0.get()).as_ptr()
        }
    }
}

static TSS_STORAGE: BootCell<TaskStateSegment> = BootCell::new();
static GDT_STORAGE: BootCell<GlobalDescriptorTable> = BootCell::new();
static IDT_STORAGE: BootCell<InterruptDescriptorTable> = BootCell::new();

pub fn initialize() {
    // Interrupts remain off until an APIC/PIC routing/EOI design exists.
    x86_64::instructions::interrupts::disable();

    let stack_base = (&raw mut DOUBLE_FAULT_STACK).cast::<u8>() as usize;
    let stack_top = stack_base + DOUBLE_FAULT_STACK_SIZE;
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
        VirtAddr::new(stack_top as u64);

    // SAFETY: boot path is single-threaded and never calls initialize twice.
    let tss_ref = unsafe { TSS_STORAGE.initialize(tss) };

    let mut gdt = GlobalDescriptorTable::new();
    let kernel_cs = gdt.append(Descriptor::kernel_code_segment());
    let kernel_ds = gdt.append(Descriptor::kernel_data_segment());
    let tss_sel = gdt.append(Descriptor::tss_segment(tss_ref));
    // SAFETY: object has static backing and is immutable after loading.
    let gdt_ref = unsafe { GDT_STORAGE.initialize(gdt) };
    gdt_ref.load();
    // SAFETY: selectors are valid entries in the loaded, permanent GDT.
    unsafe {
        CS::set_reg(kernel_cs);
        SS::set_reg(kernel_ds);
        DS::set_reg(kernel_ds);
        ES::set_reg(kernel_ds);
        load_tss(tss_sel);
    }
    serial::write_fmt(format_args!(
        "WOLFOS_GDT_OK tss=loaded ist=0 cs={:#x} ss={:#x}\n",
        CS::get_reg().0, SS::get_reg().0
    ));

    let mut idt = InterruptDescriptorTable::new();
    idt.divide_error.set_handler_fn(divide_error);
    idt.breakpoint.set_handler_fn(breakpoint);
    idt.invalid_opcode.set_handler_fn(invalid_opcode);
    idt.general_protection_fault.set_handler_fn(general_protection_fault);
    idt.page_fault.set_handler_fn(page_fault);
    // SAFETY: TSS IST 0 has a statically allocated, distinct 20 KiB stack.
    unsafe {
        idt.double_fault.set_handler_fn(double_fault)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    }
    // SAFETY: table stays in permanent storage for the life of the kernel.
    let idt_ref = unsafe { IDT_STORAGE.initialize(idt) };
    idt_ref.load();
    serial::write_line("WOLFOS_IDT_OK");

    // Breakpoint returns through IRETQ, proving the installed IDT can
    // deliver an exception and restore the interrupted execution context.
    x86_64::instructions::interrupts::int3();
    serial::write_line("WOLFOS_BREAKPOINT_RETURN_OK");
}

extern "x86-interrupt" fn breakpoint(_frame: InterruptStackFrame) {
    serial::write_line("WOLFOS_EXCEPTION_BP vector=3");
}

extern "x86-interrupt" fn divide_error(frame: InterruptStackFrame) {
    serial::write_fmt(format_args!("WOLFOS_EXCEPTION_DE vector=0 rip={:?}\n", frame.instruction_pointer));
    crate::halt_forever();
}

extern "x86-interrupt" fn invalid_opcode(frame: InterruptStackFrame) {
    serial::write_fmt(format_args!("WOLFOS_EXCEPTION_UD vector=6 rip={:?}\n", frame.instruction_pointer));
    #[cfg(feature = "exception-smoke")]
    serial::qemu_exit_success();
    #[cfg(not(feature = "exception-smoke"))]
    crate::halt_forever();
}

extern "x86-interrupt" fn general_protection_fault(frame: InterruptStackFrame, code: u64) {
    serial::write_fmt(format_args!(
        "WOLFOS_EXCEPTION_GP vector=13 error={:#x} rip={:?}\n",
        code, frame.instruction_pointer
    ));
    crate::halt_forever();
}

extern "x86-interrupt" fn page_fault(frame: InterruptStackFrame, code: PageFaultErrorCode) {
    let address = Cr2::read();
    serial::write_fmt(format_args!(
        "WOLFOS_EXCEPTION_PF vector=14 address={:?} flags={:?} rip={:?}\n",
        address, code, frame.instruction_pointer
    ));
    #[cfg(feature = "paging-fault-smoke")]
    if matches!(address, Ok(fault_address) if fault_address.as_u64() == crate::paging::TEST_VIRTUAL_ADDRESS)
        && !code.contains(PageFaultErrorCode::PROTECTION_VIOLATION)
    {
        serial::write_line("WOLFOS_PAGING_FAULT_OK");
        serial::qemu_exit_success();
    }
    crate::halt_forever();
}

extern "x86-interrupt" fn double_fault(frame: InterruptStackFrame, code: u64) -> ! {
    serial::write_fmt(format_args!(
        "WOLFOS_EXCEPTION_DF vector=8 error={:#x} rip={:?}\n",
        code, frame.instruction_pointer
    ));
    crate::halt_forever()
}

#[cfg(feature = "exception-smoke")]
pub fn trigger_invalid_opcode() -> ! {
    serial::write_line("WOLFOS_EXCEPTION_TEST_BEGIN vector=6");
    // SAFETY: only the isolated QEMU exception smoke test enables this.
    unsafe { core::arch::asm!("ud2", options(noreturn)); }
}
