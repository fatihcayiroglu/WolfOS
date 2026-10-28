//! Early secondary-CPU Rust execution on WolfOS-owned kernel stacks.
//!
//! BSP prepares independent 32 KiB stacks, Limine wakes APs, and the APs
//! switch stacks via a nonreturning x86-64 trampoline BEFORE setting up
//! their private GDT/TSS/IDT. All APs meet an Acquire/Release start barrier,
//! perform independent deterministic CPU work, and park. BSP checks results.
//!
//! Includes a fixed-batch dispatcher and two actual saved-context kernel
//! threads per CPU; NOT a preemptive scheduler. No IPIs, user mode or timers.
//! APs do not use serial, PMM, PCI, global page-table updates or disk access.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use limine::mp::{MpInfo, MpRespData};

use crate::{ap_stack, scheduler, serial, thread_scheduler, percpu_context, lapic_probe};

pub const MAX_BOOT_CPUS: usize = 256;
const ACK_MAGIC: u64 = 0x574F_4C46_4150_0000;
const WORK_ROUNDS: usize = 32_768;
const WAIT_ROUNDS: usize = 100_000_000;

static AP_READY: [AtomicU64; MAX_BOOT_CPUS] =
    [const { AtomicU64::new(0) }; MAX_BOOT_CPUS];
static AP_DONE: [AtomicU64; MAX_BOOT_CPUS] =
    [const { AtomicU64::new(0) }; MAX_BOOT_CPUS];
static AP_RESULT: [AtomicU64; MAX_BOOT_CPUS] =
    [const { AtomicU64::new(0) }; MAX_BOOT_CPUS];
static START_WORK: AtomicBool = AtomicBool::new(false);

fn expected_ack(info: &MpInfo) -> u64 {
    ACK_MAGIC ^ ((info.processor_id as u64) << 32) ^ info.lapic_id as u64
}

fn compute(index: usize, lapic_id: u32) -> u64 {
    let mut state = ACK_MAGIC ^ ((index as u64) << 32) ^ lapic_id as u64;
    for step in 0..WORK_ROUNDS {
        state ^= (step as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        state = state.rotate_left(7).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    }
    state
}

fn wait_for(cpus: &[&MpInfo], bsp_id: u32, values: &[AtomicU64; MAX_BOOT_CPUS]) -> bool {
    for _ in 0..WAIT_ROUNDS {
        if cpus.iter().enumerate().all(|(index, cpu)| {
            cpu.lapic_id == bsp_id ||
                values[index].load(Ordering::Acquire) == expected_ack(cpu)
        }) {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Bootloader's first AP entry: still uses the Limine-provided stack.
/// We switch to the CPU's reserved WolfOS stack before using general Rust
/// kernel services on that processor.
///
/// # Safety
/// MpInfo and its per-AP boot stack remain valid under Limine MP contract.
unsafe extern "C" fn secondary_entry(info: &MpInfo) -> ! {
    x86_64::instructions::interrupts::disable();
    let index = info.extra_argument() as usize;
    // Slot zero is not inherently reserved: BSP position is arbitrary.
    // BSP has already validated unique CPU IDs and assigned this index.
    let Some(top) = ap_stack::prepared_top(index) else {
        crate::halt_forever();
    };
    // SAFETY: BSP prepared this exact stack before releasing the AP, and
    // never mutates that stack after publishing the Limine entrypoint.
    unsafe { ap_stack::enter(info, index, top) }
}

/// Symbol called by the x86-64 trampoline after replacing RSP. Always !.
/// Both MpInfo pointer and index originate from the trusted Limine handoff.
#[unsafe(no_mangle)]
extern "C" fn wolfos_ap_stack_rust(info_ptr: *const MpInfo, index: usize) -> ! {
    x86_64::instructions::interrupts::disable();
    if info_ptr.is_null() || index >= MAX_BOOT_CPUS ||
        !ap_stack::verify_active(index)
    {
        crate::halt_forever();
    }
    // SAFETY: Limine MpInfo remains allocated throughout early boot;
    // immutable CPU directory was validated by BSP before AP release.
    let info = unsafe { &*info_ptr };
    if info.extra_argument() as usize != index {
        crate::halt_forever();
    }
    if !crate::interrupts::initialize_secondary(index) {
        crate::halt_forever();
    }

    // A failed read-only probe is published, then the BSP fails closed.
    let _ = lapic_probe::capture(index, info.lapic_id, false);
    AP_READY[index].store(expected_ack(info), Ordering::Release);
    // Every secondary waits until ALL workers reached this barrier.
    while !START_WORK.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    let result = compute(index, info.lapic_id);
    if !scheduler::BOOT_QUEUE.run_worker(index) {
        crate::halt_forever();
    }
    if !thread_scheduler::BOOT_TASKS.run_cpu(index) {
        crate::halt_forever();
    }
    // Run two real saved-RSP thread contexts on THIS AP only. Other CPU
    // context slots and per-CPU queues are never accessed by the AP.
    if !percpu_context::run(index) {
        crate::halt_forever();
    }
    if !ap_stack::verify_active(index) {
        crate::halt_forever();
    }
    AP_RESULT[index].store(result, Ordering::Release);
    AP_DONE[index].store(expected_ack(info), Ordering::Release);
    #[cfg(feature = "smp-address-space-retirement-smoke")]
    if !crate::smp_address_space_retirement_smoke::secondary(index) {
        crate::halt_forever();
    }
    // Dedicated QEMU IPI proof only: AP installs its own SVR, enables IF
    // briefly, accepts directed fixed IPIs, EOI-acks and reparks with IF=0.
    #[cfg(any(feature = "ap-ipi-smoke", feature = "tlb-shootdown-hardware-smoke", feature = "ap-local-timer-smoke",
               feature = "ap-smp-preempt-smoke", feature = "ap-remote-work-smoke",
               feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
    if !crate::ap_ipi_smoke::secondary_wait(index, info.lapic_id) {
        crate::halt_forever();
    }
    crate::halt_forever();
}

/// BSP starts APs and validates stack-switch, exception and work completion.
/// APs remain parked; BSP remains sole serial-logger and hardware manager.
pub fn boot_aps(mp: &MpRespData) -> bool {
    let cpus = mp.cpus();
    if cpus.is_empty() || cpus.len() > MAX_BOOT_CPUS {
        serial::write_fmt(format_args!(
            "WOLFOS_SMP_ERROR invalid_cpu_count={}\n", cpus.len()
        ));
        return false;
    }

    let mut bsp_count = 0usize;
    let mut ap_count = 0usize;

    for (i, cpu) in cpus.iter().enumerate() {
        if cpu.lapic_id == mp.bsp_lapic_id { bsp_count += 1; }
        for other in cpus[..i].iter() {
            if other.lapic_id == cpu.lapic_id {
                serial::write_line("WOLFOS_SMP_ERROR duplicate_lapic_id");
                return false;
            }
        }
    }
    if bsp_count != 1 {
        serial::write_line("WOLFOS_SMP_ERROR bsp_not_unique");
        return false;
    }
    let Some(bsp_index) = cpus.iter().position(|cpu| cpu.lapic_id == mp.bsp_lapic_id)
    else {
        return false;
    };
    if !lapic_probe::capture(bsp_index, mp.bsp_lapic_id, true) {
        serial::write_line("WOLFOS_LAPIC_ERROR bsp_msr_or_identity_invalid");
        return false;
    }
    // Configure before any AP can claim a queue item.
    if !scheduler::BOOT_QUEUE.configure(cpus.len()) {
        serial::write_line("WOLFOS_SCHED_ERROR invalid_initialization");
        return false;
    }
    if !thread_scheduler::BOOT_TASKS.configure(cpus.len()) {
        serial::write_line("WOLFOS_THREADS_ERROR invalid_initialization");
        return false;
    }

    // Prepare ALL stacks before releasing ANY secondary processor.
    for (index, cpu) in cpus.iter().enumerate() {
        if cpu.lapic_id == mp.bsp_lapic_id { continue; }
        if ap_stack::prepare(index).is_none() {
            serial::write_line("WOLFOS_SMP_ERROR cannot_prepare_stack");
            return false;
        }
    }
    for (index, cpu) in cpus.iter().enumerate() {
        if cpu.lapic_id == mp.bsp_lapic_id { continue; }
        cpu.bootstrap(secondary_entry, index as u64);
        ap_count += 1;
    }

    if !wait_for(cpus, mp.bsp_lapic_id, &AP_READY) {
        serial::write_fmt(format_args!(
            "WOLFOS_SMP_ERROR ap_ready_timeout expected={}\n", ap_count
        ));
        return false;
    }
    let Some(apic) = lapic_probe::verify(cpus, bsp_index) else {
        serial::write_line("WOLFOS_LAPIC_ERROR ap_msr_or_identity_invalid");
        return false;
    };
    serial::write_fmt(format_args!(
        "WOLFOS_LAPIC_ID_OK cpus={} verified={} base={:#x} x2apic={} readonly=1\n",
        apic.cpus, apic.cpus, apic.base, apic.x2apic
    ));
    // Acquire of AP_READY makes all per-AP GDT/TSS/IDT and #BP work visible.
    let bp = crate::interrupts::ap_breakpoint_count();
    if bp != ap_count {
        serial::write_fmt(format_args!(
            "WOLFOS_SMP_ERROR ap_breakpoints={} expected={}\n", bp, ap_count
        ));
        return false;
    }
    serial::write_fmt(format_args!(
        "WOLFOS_SMP_STACK_OK total={} switched={} stack_kib={}\n",
        cpus.len(), ap_count, ap_stack::KERNEL_STACK_SIZE / 1024
    ));
    serial::write_fmt(format_args!(
        "WOLFOS_SMP_AP_IDT_OK total={} ap_idts={} ap_bp_returns={}\n",
        cpus.len(), ap_count, bp
    ));

    // All APs have reached the barrier. Send one release event to begin
    // independent CPU work on each permanent stack.
    START_WORK.store(true, Ordering::Release);
    // BSP participates as a worker while APs run on private kernel stacks.
    if !scheduler::BOOT_QUEUE.run_worker(bsp_index) {
        serial::write_line("WOLFOS_SCHED_ERROR bsp_worker_failed");
        return false;
    }
    if !thread_scheduler::BOOT_TASKS.run_cpu(bsp_index) {
        serial::write_line("WOLFOS_THREADS_ERROR bsp_worker_failed");
        return false;
    }
    if !percpu_context::run(bsp_index) {
        serial::write_line("WOLFOS_SMP_CTX_ERROR bsp_context_failure");
        return false;
    }
    if !wait_for(cpus, mp.bsp_lapic_id, &AP_DONE) {
        serial::write_fmt(format_args!(
            "WOLFOS_SMP_ERROR ap_work_timeout expected={}\n", ap_count
        ));
        return false;
    }
    for (index, cpu) in cpus.iter().enumerate() {
        if cpu.lapic_id == mp.bsp_lapic_id { continue; }
        let observed = AP_RESULT[index].load(Ordering::Acquire);
        if observed != compute(index, cpu.lapic_id) {
            serial::write_fmt(format_args!(
                "WOLFOS_SMP_ERROR ap_work_mismatch index={}\n", index
            ));
            return false;
        }
    }
    // AP_DONE is published with Release only AFTER AP context work.
    // wait_for() read every AP_DONE with Acquire, so BSP may safely read
    // AP-specific non-atomic TCB records after all APs have parked.
    if !percpu_context::verify_all(cpus.len()) {
        serial::write_line("WOLFOS_SMP_CTX_ERROR per_cpu_context_verification");
        return false;
    }
    serial::write_fmt(format_args!(
        "WOLFOS_SMP_CTX_OK cpus={} active={} threads={} switches={} yields={} blocked={} woken={} finished={} stack_kib={} bank_kib={}\n",
        cpus.len(), cpus.len(),
        cpus.len() * percpu_context::THREADS_PER_PROCESSOR,
        cpus.len() * percpu_context::SWITCHES_PER_PROCESSOR,
        cpus.len() * percpu_context::YIELDS_PER_PROCESSOR,
        cpus.len(), cpus.len(),
        cpus.len() * percpu_context::THREADS_PER_PROCESSOR,
        percpu_context::STACK_KIB, percpu_context::MAX_BANK_KIB
    ));
    let Some(report) = scheduler::BOOT_QUEUE.verify(bsp_index) else {
        serial::write_line("WOLFOS_SCHED_ERROR job_verification_failed");
        return false;
    };
    serial::write_fmt(format_args!(
        "WOLFOS_SCHED_OK tasks={} cpus={} active={} bsp_jobs={} ap_jobs={}\n",
        report.jobs, report.workers, report.active_cpus,
        report.bsp_jobs, report.ap_jobs
    ));
    let Some(tasks) = thread_scheduler::BOOT_TASKS.verify() else {
        serial::write_line("WOLFOS_THREADS_ERROR state_verification_failed");
        return false;
    };
    serial::write_fmt(format_args!(
        "WOLFOS_THREADS_OK threads={} cpus={} active={} yielded={} blocked={} woken={} finished={}\n",
        tasks.threads, tasks.cpus, tasks.active, tasks.yielded,
        tasks.blocked, tasks.woken, tasks.finished
    ));
    serial::write_fmt(format_args!(
        "WOLFOS_SMP_WORK_OK total={} workers={} rounds={}\n",
        cpus.len(), ap_count, WORK_ROUNDS
    ));
    serial::write_fmt(format_args!(
        "WOLFOS_SMP_APS_OK total={} bsp_lapic={} ap_acks={}\n",
        cpus.len(), mp.bsp_lapic_id, ap_count
    ));
    serial::write_fmt(format_args!(
        "WOLFOS_SMP_PERCPU_OK total={} ap_tables={}\n",
        cpus.len(), ap_count
    ));
    true
}
