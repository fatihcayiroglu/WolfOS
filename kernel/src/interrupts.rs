//! P1 x86-64 GDT, TSS/IST, IDT and CPU exception diagnostics.
//! Boot CPU and parked APs have independent GDT/TSS and double-fault IST stacks.
//! External IRQs remain masked; an SMP scheduler and IPIs are not initialized.
//! A dedicated double-fault IST stack protects against common stack failures.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
#[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
use core::arch::asm;
#[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
use core::sync::atomic::AtomicU64;
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

// P2 one-vCPU isolated QEMU preflight ONLY. No CPL3 switch is performed.
// The future TSS.RSP0 stack is not the double-fault IST stack.
#[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
const USER_RSP0_STACK_SIZE: usize = 16 * 1024;
#[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
const USER_RSP0_CANARY: u64 = 0x574f_4c46_5253_5030; // "WOLFRSP0"
#[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
#[repr(align(16))]
struct UserRsp0Stack([u8; USER_RSP0_STACK_SIZE]);
#[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
static mut BSP_USER_RSP0_STACK: UserRsp0Stack = UserRsp0Stack([0; USER_RSP0_STACK_SIZE]);
#[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
static USER_RSP0_EXPECTED: AtomicU64 = AtomicU64::new(0);
#[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
static USER_CS_EXPECTED: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
static USER_DS_EXPECTED: AtomicUsize = AtomicUsize::new(0);
#[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
static USER_TSS_SELECTOR_EXPECTED: AtomicUsize = AtomicUsize::new(0);


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
    // The isolated directed-IPI QEMU flavor installs two external vectors
    // only on secondary CPUs. Its handler EOIs the *receiving* local APIC.
    #[cfg(any(feature = "ap-ipi-smoke", feature = "ap-local-timer-smoke",
               feature = "ap-smp-preempt-smoke", feature = "ap-remote-work-smoke",
               feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
    {
        idt[crate::ap_ipi_smoke::VECTOR].set_handler_fn(crate::ap_ipi_smoke::irq);
        idt[crate::ap_ipi_smoke::SPURIOUS]
            .set_handler_fn(crate::ap_ipi_smoke::spurious);
    }
    #[cfg(feature = "ap-local-timer-smoke")]
    idt[crate::ap_local_timer_smoke::VECTOR]
        .set_handler_fn(crate::ap_local_timer_smoke::irq);
    // Only the QEMU per-AP preemption flavor uses a custom assembly
    // 15-GPR IRQ entry with a validated alternative per-AP task stack.
    #[cfg(feature = "ap-smp-preempt-smoke")]
    unsafe {
        idt[crate::ap_smp_preempt_smoke::VECTOR]
            .set_handler_addr(crate::ap_preempt_irq_entry::address());
    }
    // QEMU-only AP-local timer IRQ: interrupt *preempts* the shared task,
    // and the assembly dispatch can IRETQ to a separate local escape stack.
    #[cfg(feature = "ap-irq-migrate-smoke")]
    unsafe {
        idt[crate::ap_irq_migrate_smoke::TIMER_VECTOR]
            .set_handler_addr(crate::ap_irq_migrate_entry::irq_address());
    }
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
    #[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
    {
        let rsp0_bottom = (&raw mut BSP_USER_RSP0_STACK).cast::<u8>() as usize;
        let rsp0_top = rsp0_bottom + USER_RSP0_STACK_SIZE;
        // This static, 16-byte aligned stack remains mapped supervisor-only
        // by the live boot tables. Interrupts stay OFF in this QEMU mode.
        // It is a future CPL3->CPL0 trap landing stack, NOT the IST stack.
        // SAFETY: serialized BSP boot before any other code touches this
        // permanently owned static storage.
        unsafe {
            (rsp0_bottom as *mut u64).write(USER_RSP0_CANARY);
            (rsp0_bottom as *mut u64).add(1).write(!USER_RSP0_CANARY);
        }
        tss.privilege_stack_table[0] = VirtAddr::new(rsp0_top as u64);
        USER_RSP0_EXPECTED.store(rsp0_top as u64, Ordering::Release);
    }

    // SAFETY: boot path is single-threaded and never calls initialize twice.
    let tss_ref = unsafe { TSS_STORAGE.initialize(tss) };

    let mut gdt = GlobalDescriptorTable::new();
    let kernel_cs = gdt.append(Descriptor::kernel_code_segment());
    let kernel_ds = gdt.append(Descriptor::kernel_data_segment());
    let tss_sel = gdt.append(Descriptor::tss_segment(tss_ref));
    #[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
    {
        // The kernel stays at CPL0. These are descriptors for a future
        // isolated IRETQ transition, not a change in current CS/SS.
        let user_ds = gdt.append(Descriptor::user_data_segment());
        let user_cs = gdt.append(Descriptor::user_code_segment());
        USER_CS_EXPECTED.store(usize::from(user_cs.0 | 3), Ordering::Release);
        USER_DS_EXPECTED.store(usize::from(user_ds.0 | 3), Ordering::Release);
        USER_TSS_SELECTOR_EXPECTED.store(usize::from(tss_sel.0), Ordering::Release);
    }
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
    #[cfg(feature = "user-ring3-smoke")]
    {
        idt[0x80].set_handler_fn(crate::user_ring3_smoke::interrupt_80)
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
    }
    #[cfg(feature = "user-ring3-isolation-smoke")]
    {
        idt[0x80].set_handler_fn(crate::user_ring3_isolation_smoke::interrupt_80)
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
        // #PF remains DPL0. Only the CPU may deliver the protected fault;
        // user code cannot request this vector as an arbitrary INT.
        idt.page_fault.set_handler_fn(crate::user_ring3_isolation_smoke::user_page_fault);
    }
    #[cfg(any(feature = "p2-ring3-yield-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
    unsafe {
        // This custom gate saves ALL 15 GPRs so the kernel can dispatch
        // RAX/RDI/RSI arguments and change saved RAX before real IRETQ.
        // Only installed in the separate single-BSP QEMU acceptance flavor.
        idt[0x80].set_handler_addr(crate::user_syscall_entry::address())
            .set_privilege_level(x86_64::PrivilegeLevel::Ring3);
    }
    #[cfg(feature = "timer-smoke")]
    idt[crate::timer::TIMER_VECTOR].set_handler_fn(crate::timer::irq0);
    #[cfg(any(feature = "apic-timer-smoke", feature = "apic-calibration-smoke",
               feature = "apic-preempt-smoke"))]
    // SAFETY: custom x86-64 long-mode interrupt-gate entry saves all GPRs
    // before calling the BSP-only Rust dispatch, then IRETQs to same task.
    // This IDT entry is installed before enabling any APIC smoke interrupts.
    unsafe {
        idt[crate::apic_timer_smoke::TIMER_VECTOR]
            .set_handler_addr(crate::apic_irq_entry::address());
    }
    #[cfg(any(feature = "apic-timer-smoke", feature = "apic-calibration-smoke",
               feature = "apic-preempt-smoke"))]
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

#[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
pub fn verify_ring3_preconditions() -> bool {
    ring3_preflight_inner(false)
}

/// After a prior real CPL3->CPL0 INT80, x86-64 may leave the kernel's
/// SS selector NULL even though CPL remains zero and CS is still 0x8.
/// That is an architecturally valid long-mode interrupt-return state.
/// NEVER use this admission on the first kernel/user transition. The
/// caller must have already restored boot CR3 and reaped the previous PID.
#[cfg(feature = "user-process-smoke")]
pub fn verify_ring3_reentry_preconditions() -> bool {
    ring3_preflight_inner(true)
}

#[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke"))]
fn ring3_preflight_inner(after_user_trap: bool) -> bool {
    // Only after interrupts::initialize(), before SMP startup. Read actual
    // hardware task register and actual packed TSS privilege_stack_table.
    // Unlike a value cached in an atomic, TR and the TSS field attest that
    // the CPU has a loaded selector pointing to initialized RSP0 storage.
    let mut tr: u16;
    // SAFETY: non-mutating x86-64 STR reads the loaded task register.
    unsafe { asm!("str {0:x}", out(reg) tr, options(nomem, nostack, preserves_flags)); }

    let expected_rsp0 = USER_RSP0_EXPECTED.load(Ordering::Acquire);
    let user_cs = USER_CS_EXPECTED.load(Ordering::Acquire) as u16;
    let user_ds = USER_DS_EXPECTED.load(Ordering::Acquire) as u16;
    let expected_tr = USER_TSS_SELECTOR_EXPECTED.load(Ordering::Acquire) as u16;
    let base = (&raw const BSP_USER_RSP0_STACK).cast::<u8>() as usize;
    let top = base + USER_RSP0_STACK_SIZE;
    // SAFETY: initialized exactly once in initialize() on BSP. No other
    // thread mutates TSS after its task register is loaded; it is borrowed
    // read-only for this serialized smoke.
    let tss = unsafe { (*TSS_STORAGE.0.get()).assume_init_ref() };
    let actual_rsp0 = unsafe {
        core::ptr::addr_of!(tss.privilege_stack_table[0]).read_unaligned()
    }.as_u64();
    // SAFETY: static storage has never been used as the CPU entry stack
    // because this smoke does NOT switch to CPL3.
    let (low, next) = unsafe {
        ((base as *const u64).read(), (base as *const u64).add(1).read())
    };

    let contract = crate::user_ring_entry::validate(crate::user_ring_entry::Ring3Entry {
        rip: 0x401100,
        user_rsp: 0x405000,
        kernel_rsp0: actual_rsp0,
        user_cs, user_ss: user_ds,
        rflags: 0x2, // IF=0; no privilege transition is executed here.
    });
    let good = expected_rsp0 != 0 && expected_rsp0 == top as u64
        && expected_rsp0 == actual_rsp0
        && tr == expected_tr && tr != 0
        && CS::get_reg().0 == 0x8
        && (SS::get_reg().0 == 0x10 || (after_user_trap && SS::get_reg().0 == 0))
        && user_cs & 7 == 3 && user_ds & 7 == 3 && user_cs != user_ds
        && low == USER_RSP0_CANARY && next == !USER_RSP0_CANARY
        && contract.is_ok()
        && stack_top_check(base, top);
    if !good {
        serial::write_fmt(format_args!(
            "WOLFOS_RING_PREP_ERROR tr={:#x}/{:#x} rsp0={:#x}/{:#x} cs={:#x} ds={:#x} current_ss={:#x} reentry={} canary={} contract={:?}\n",
            tr, expected_tr, actual_rsp0, expected_rsp0, user_cs, user_ds,
            SS::get_reg().0, after_user_trap,
            low == USER_RSP0_CANARY && next == !USER_RSP0_CANARY, contract,
        ));
        return false;
    }
    serial::write_fmt(format_args!(
        "WOLFOS_RING_PREP_OK tr={:#x} user_cs={:#x} user_ds={:#x} rsp0_aligned=1 rsp0_stack_kib=16 ist_disjoint=1 guards=1 cpl=0 ring3=0\n",
        tr, user_cs, user_ds,
    ));
    true
}

/// BSP-only QEMU test gate: rewrite the ACTUAL loaded TSS.RSP0 field.
/// It is not used as an interrupt landing stack in this feature: CPL=0
/// throughout, IF=0, no AP user task and no Ring3 IRETQ may execute.
/// The upper-canonical guard-mapped destination must be independently
/// verified/pinned by the caller before changing this entry.
///
/// # Safety
/// Single BSP, IF=0, initialized TSS, no concurrent CPU/interrupt reader,
/// next RSP0 is a live 16-KiB supervisor stack top mapped in active CR3.
#[cfg(any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke"))]
pub unsafe fn test_handoff_rsp0(next: u64) -> bool {
    if next < 0xffff_8000_0000_0000 || next & 15 != 0
        || x86_64::instructions::interrupts::are_enabled() {
        return false
    }
    let ptr = unsafe { (*TSS_STORAGE.0.get()).as_mut_ptr() };
    let field = unsafe {
        core::ptr::addr_of_mut!((*ptr).privilege_stack_table[0])
    };
    unsafe {field.write_unaligned(VirtAddr::new(next));}
    unsafe {field.read_unaligned().as_u64()==next}
}

/// Read the actual loaded supervisor RSP0, not a cached metadata value.
#[cfg(any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke"))]
pub fn test_actual_rsp0() -> u64 {
    let ptr=unsafe{(*TSS_STORAGE.0.get()).as_ptr()};
    let field=unsafe{core::ptr::addr_of!((*ptr).privilege_stack_table[0])};
    unsafe{field.read_unaligned().as_u64()}
}

/// Read back selector + stack metadata after verify_ring3_preconditions().
#[cfg(any(any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke"), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
pub fn ring3_cpu_state() -> (u16, u16, u64) {
    (USER_CS_EXPECTED.load(Ordering::Acquire) as u16,
     USER_DS_EXPECTED.load(Ordering::Acquire) as u16,
     USER_RSP0_EXPECTED.load(Ordering::Acquire))
}

#[cfg(any(any(feature = "user-ring-prep-smoke", any(feature = "p2-handoff-preflight-smoke", feature = "p2-ring3-yield-smoke")), feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))]
fn stack_top_check(base: usize, top: usize) -> bool {
    base != 0 && base % 16 == 0 && top % 16 == 0
        && top > base && top - base == USER_RSP0_STACK_SIZE
        && {
            let ist = (&raw const DOUBLE_FAULT_STACK).cast::<u8>() as usize;
            let ist_end = ist + DOUBLE_FAULT_STACK_SIZE;
            top <= ist || base >= ist_end
        }
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
    #[cfg(any(feature = "kernel-stack-guard-fault-smoke",
              feature = "kernel-stack-guard-upper-fault-smoke"))]
    if matches!(address, Ok(address) if
        crate::kernel_stack_guard_smoke::expected_fault(
            address.as_u64(), code.bits(), frame.instruction_pointer.as_u64())
    ) {
        serial::write_fmt(format_args!(
            "WOLFOS_STACK_GUARD_HARDWARE_OK side={} nonpresent=1 supervisor=1 read=1\n",
            if cfg!(feature="kernel-stack-guard-upper-fault-smoke") { "upper" }
            else { "lower" }
        ));
        serial::qemu_exit_success();
    }
    #[cfg(any(feature = "high-half-stack-arena-lower-fault-smoke",
              feature = "high-half-stack-arena-upper-fault-smoke"))]
    if matches!(address, Ok(v) if
        crate::high_half_stack_arena_smoke::expected_fault(
            v.as_u64(), code.bits(), frame.instruction_pointer.as_u64())
    ) {
        serial::write_fmt(format_args!(
            "WOLFOS_HIGH_STACK_ARENA_HARDWARE_OK side={} nonpresent=1 supervisor=1 read=1\n",
            if cfg!(feature="high-half-stack-arena-upper-fault-smoke") {
                "pid2_upper"
            } else { "pid1_lower" }
        ));
        serial::qemu_exit_success();
    }
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
