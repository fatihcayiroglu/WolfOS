//! P1 x86-64 GDT, TSS/IST, IDT and CPU exception diagnostics.
//! Boot CPU and parked APs have independent GDT/TSS and double-fault IST stacks.
//! External IRQs remain masked; an SMP scheduler and IPIs are not initialized.
//! A dedicated double-fault IST stack protects against common stack failures.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use x86_64::instructions::segmentation::{CS, DS, ES, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};
use x86_64::structures::idt::{
    InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode,
};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::{VirtAddr, registers::control::Cr2};

use crate::serial;
use crate::smp::MAX_BOOT_CPUS;

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
static IDT_READY: AtomicBool = AtomicBool::new(false);

/// AP stacks must be disjoint. Each processor owns exactly one distinct slot.
struct ApIstBank(UnsafeCell<[AlignedStack; MAX_BOOT_CPUS]>);

// SAFETY: only a uniquely assigned AP touches its IST slot. The BSP never
// mutates AP stack storage after releasing any AP.
unsafe impl Sync for ApIstBank {}

static AP_IST_BANK: ApIstBank =
    ApIstBank(UnsafeCell::new([const { AlignedStack([0; DOUBLE_FAULT_STACK_SIZE]) }; MAX_BOOT_CPUS]));
static AP_TSS: [BootCell<TaskStateSegment>; MAX_BOOT_CPUS] =
    [const { BootCell::new() }; MAX_BOOT_CPUS];
static AP_GDT: [BootCell<GlobalDescriptorTable>; MAX_BOOT_CPUS] =
    [const { BootCell::new() }; MAX_BOOT_CPUS];
static AP_IDT: [BootCell<InterruptDescriptorTable>; MAX_BOOT_CPUS] =
    [const { BootCell::new() }; MAX_BOOT_CPUS];
static AP_BREAKPOINTS: AtomicUsize = AtomicUsize::new(0);

/// BSP-only observation of the number of APs that completed #BP handlers.
pub fn ap_breakpoint_count() -> usize {
    AP_BREAKPOINTS.load(Ordering::Acquire)
}

/// Install private GDT, TSS, IST and IDT, and verify the AP's INT3 returns.
/// No external IRQs, task scheduling, serial output, PMM access or APIC.
/// Called exactly once on the unique AP owning index.
pub fn initialize_secondary(index: usize) -> bool {
    x86_64::instructions::interrupts::disable();
    if index >= MAX_BOOT_CPUS || !IDT_READY.load(Ordering::Acquire) {
        return false;
    }

    // SAFETY: index validated, each AP owns one slot and writes only its
    // private exception stack. Address belongs to permanent kernel BSS.
    let stack_address = unsafe {
        core::ptr::addr_of_mut!((*AP_IST_BANK.0.get())[index]) as usize
    };
    let stack_top = stack_address + DOUBLE_FAULT_STACK_SIZE;
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
        VirtAddr::new(stack_top as u64);
    // SAFETY: exactly one AP initializes the unique indexed TSS.
    let tss_ref = unsafe { AP_TSS[index].initialize(tss) };

    let mut gdt = GlobalDescriptorTable::new();
    let code = gdt.append(Descriptor::kernel_code_segment());
    let data = gdt.append(Descriptor::kernel_data_segment());
    let tss_selector = gdt.append(Descriptor::tss_segment(tss_ref));
    // SAFETY: each AP writes its private permanent GDT once.
    let gdt_ref = unsafe { AP_GDT[index].initialize(gdt) };
    gdt_ref.load();
    // SAFETY: segment selectors belong to this processor's loaded GDT.
    // TSS descriptor is unique, so the busy bit cannot race another CPU.
    unsafe {
        CS::set_reg(code);
        SS::set_reg(data);
        DS::set_reg(data);
        ES::set_reg(data);
        load_tss(tss_selector);
    }

    let mut idt = InterruptDescriptorTable::new();
    idt.divide_error.set_handler_fn(ap_divide_error);
    idt.breakpoint.set_handler_fn(ap_breakpoint);
    idt.invalid_opcode.set_handler_fn(ap_invalid_opcode);
    idt.general_protection_fault.set_handler_fn(ap_general_protection_fault);
    idt.page_fault.set_handler_fn(ap_page_fault);
    // SAFETY: AP owns a unique, permanently reserved double-fault IST.
    unsafe {
        idt.double_fault.set_handler_fn(ap_double_fault)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    }
    // SAFETY: each AP initializes and owns its own static IDT exactly once.
    let idt_ref = unsafe { AP_IDT[index].initialize(idt) };
    idt_ref.load();

    // No AP serial I/O: its own #BP handler records an atomic acknowledgment.
    x86_64::instructions::interrupts::int3();
    CS::get_reg().0 == code.0 && SS::get_reg().0 == data.0
}


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
    #[cfg(feature = "timer-smoke")]
    idt[crate::timer::TIMER_VECTOR].set_handler_fn(crate::timer::irq0);
    #[cfg(feature = "apic-timer-smoke")]
    idt[crate::apic_timer_smoke::TIMER_VECTOR]
        .set_handler_fn(crate::apic_timer_smoke::irq);
    #[cfg(feature = "apic-timer-smoke")]
    idt[crate::apic_timer_smoke::SPURIOUS_VECTOR]
        .set_handler_fn(crate::apic_timer_smoke::spurious);
    // SAFETY: TSS IST 0 has a statically allocated, distinct 20 KiB stack.
    unsafe {
        idt.double_fault.set_handler_fn(double_fault)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    }
    // SAFETY: table stays in permanent storage for the life of the kernel.
    let idt_ref = unsafe { IDT_STORAGE.initialize(idt) };
    idt_ref.load();
    IDT_READY.store(true, Ordering::Release);
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


// Secondary processors must not use BSP's non-reentrant serial fault logger.
// These AP handlers either acknowledge INT3 or fail-stop without unwinding.
extern "x86-interrupt" fn ap_breakpoint(_frame: InterruptStackFrame) {
    AP_BREAKPOINTS.fetch_add(1, Ordering::Release);
}

extern "x86-interrupt" fn ap_divide_error(_frame: InterruptStackFrame) {
    crate::halt_forever();
}

extern "x86-interrupt" fn ap_invalid_opcode(_frame: InterruptStackFrame) {
    crate::halt_forever();
}

extern "x86-interrupt" fn ap_general_protection_fault(
    _frame: InterruptStackFrame, _code: u64
) {
    crate::halt_forever();
}

extern "x86-interrupt" fn ap_page_fault(
    _frame: InterruptStackFrame, _code: PageFaultErrorCode
) {
    crate::halt_forever();
}

extern "x86-interrupt" fn ap_double_fault(
    _frame: InterruptStackFrame, _code: u64
) -> ! {
    crate::halt_forever()
}
