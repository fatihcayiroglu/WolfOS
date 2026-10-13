//! Early secondary-CPU Rust execution on WolfOS-owned kernel stacks.
//!
//! BSP prepares independent 32 KiB stacks, Limine wakes APs, and the APs
//! switch stacks via a nonreturning x86-64 trampoline BEFORE setting up
//! their private GDT/TSS/IDT. All APs meet an Acquire/Release start barrier,
//! perform independent deterministic CPU work, and park. BSP checks results.
//!
//! Includes a cooperative fixed-batch dispatcher but NOT a real preemptive
//! scheduler: no context switching, user mode, IPIs or timers.
//! APs do not use serial, PMM, PCI, global page-table updates or disk access.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use limine::mp::{MpInfo, MpRespData};

use crate::{ap_stack, scheduler, serial, thread_scheduler};

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
    if !ap_stack::verify_active(index) {
        crate::halt_forever();
    }
    AP_RESULT[index].store(result, Ordering::Release);
    AP_DONE[index].store(expected_ack(info), Ordering::Release);
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
