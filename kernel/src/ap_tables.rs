//! Permanent per-AP x86-64 GDT/TSS/IDT and independent double-fault IST.
//!
//! Each AP installs its own CPU descriptor tables before running a controlled
//! INT3 exception. AP handlers never use the global polling serial port.
//! APs remain parked afterward; external IRQs remain disabled.
//!
//! Boot-only storage, fixed maximum of 256 CPUs. Do not enable SMP scheduling,
//! external IRQs or memory reclamation without a later audited design.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::arch::asm;

use x86_64::instructions::segmentation::{CS, DS, ES, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};
use x86_64::structures::idt::{
    InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode,
};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

use crate::smp::MAX_BOOT_CPUS;

const DF_IST_INDEX: u16 = 0;
const DF_STACK_SIZE: usize = 4096 * 5;

#[repr(align(16))]
struct AlignedStack([u8; DF_STACK_SIZE]);

struct ApStorage {
    tss: UnsafeCell<MaybeUninit<TaskStateSegment>>,
    gdt: UnsafeCell<MaybeUninit<GlobalDescriptorTable>>,
    idt: UnsafeCell<MaybeUninit<InterruptDescriptorTable>>,
    df_ist: UnsafeCell<AlignedStack>,
}

// SAFETY: A unique Limine CPU-directory index owns each slot during
// bootstrap; indices are validated for uniqueness before any AP is released.
// Each slot is initialized once on its owning AP and kept forever, and
// is never modified by BSP or other CPUs.
unsafe impl Sync for ApStorage {}

impl ApStorage {
    const fn new() -> Self {
        Self {
            tss: UnsafeCell::new(MaybeUninit::uninit()),
            gdt: UnsafeCell::new(MaybeUninit::uninit()),
            idt: UnsafeCell::new(MaybeUninit::uninit()),
            df_ist: UnsafeCell::new(AlignedStack([0; DF_STACK_SIZE])),
        }
    }
}

static AP_STORAGE: [ApStorage; MAX_BOOT_CPUS] =
    [const { ApStorage::new() }; MAX_BOOT_CPUS];
static AP_BREAKPOINTS: AtomicUsize = AtomicUsize::new(0);

/// # Safety
/// Each slot must be initialized at most once by its unique owning CPU.
/// All descriptor references must live for the entire execution lifetime.
unsafe fn install<T>(
    storage: &'static UnsafeCell<MaybeUninit<T>>,
    value: T,
) -> &'static T {
    // SAFETY: caller has unique ownership for the lifetime of boot.
    unsafe {
        (*storage.get()).write(value);
        &*(*storage.get()).as_ptr()
    }
}

/// Called only by the AP at its Limine handoff. The AP has a private stack.
/// Returns once per-CPU GDT/TSS/IDT are loaded and an INT3 has returned.
pub fn initialize_ap(index: usize) -> bool {
    x86_64::instructions::interrupts::disable();
    let Some(slot) = AP_STORAGE.get(index) else { return false; };

    let ist_base = slot.df_ist.get().cast::<u8>() as usize;
    let Some(ist_top) = ist_base.checked_add(DF_STACK_SIZE) else {
        return false;
    };
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DF_IST_INDEX as usize] = VirtAddr::new(ist_top as u64);

    // SAFETY: each AP exclusively initializes exactly its own static slot.
    let tss_ref = unsafe { install(&slot.tss, tss) };
    let mut gdt = GlobalDescriptorTable::new();
    let cs = gdt.append(Descriptor::kernel_code_segment());
    let ds = gdt.append(Descriptor::kernel_data_segment());
    let tr = gdt.append(Descriptor::tss_segment(tss_ref));
    // SAFETY: table persists; no other CPU accesses this slot.
    let gdt_ref = unsafe { install(&slot.gdt, gdt) };
    gdt_ref.load();

    // SAFETY: valid selectors from the currently loaded per-AP GDT.
    unsafe {
        CS::set_reg(cs);
        SS::set_reg(ds);
        DS::set_reg(ds);
        ES::set_reg(ds);
        load_tss(tr);
    }
    let loaded_tr: u16;
    // SAFETY: STR is unprivileged read-only introspection on this CPU.
    unsafe {
        asm!("str ax", out("ax") loaded_tr, options(nomem, nostack, preserves_flags));
    }
    if CS::get_reg() != cs || SS::get_reg() != ds || loaded_tr != tr.0 {
        return false;
    }

    let mut idt = InterruptDescriptorTable::new();
    idt.divide_error.set_handler_fn(ap_divide_error);
    idt.breakpoint.set_handler_fn(ap_breakpoint);
    idt.invalid_opcode.set_handler_fn(ap_invalid_opcode);
    idt.general_protection_fault.set_handler_fn(ap_general_protection);
    idt.page_fault.set_handler_fn(ap_page_fault);
    // SAFETY: slot-specific 20 KiB double-fault IST is permanently reserved.
    unsafe {
        idt.double_fault
            .set_handler_fn(ap_double_fault)
            .set_stack_index(DF_IST_INDEX);
    }
    // SAFETY: table remains allocated and immutable for the lifetime of AP.
    let idt_ref = unsafe { install(&slot.idt, idt) };
    idt_ref.load();

    // Deliver and return from #BP through this AP's own IDT. The handler
    // performs only a lock-free counter increment, never serial I/O.
    x86_64::instructions::interrupts::int3();
    true
}

pub fn breakpoint_count() -> usize {
    AP_BREAKPOINTS.load(Ordering::Acquire)
}

extern "x86-interrupt" fn ap_breakpoint(_frame: InterruptStackFrame) {
    AP_BREAKPOINTS.fetch_add(1, Ordering::Release);
}

extern "x86-interrupt" fn ap_divide_error(_frame: InterruptStackFrame) {
    crate::halt_forever();
}

extern "x86-interrupt" fn ap_invalid_opcode(_frame: InterruptStackFrame) {
    crate::halt_forever();
}

extern "x86-interrupt" fn ap_general_protection(_frame: InterruptStackFrame, _code: u64) {
    crate::halt_forever();
}

extern "x86-interrupt" fn ap_page_fault(
    _frame: InterruptStackFrame,
    _code: PageFaultErrorCode,
) {
    crate::halt_forever();
}

extern "x86-interrupt" fn ap_double_fault(_frame: InterruptStackFrame, _code: u64) -> ! {
    crate::halt_forever()
}
