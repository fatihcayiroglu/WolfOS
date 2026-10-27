//! QEMU-only per-secondary-CPU xAPIC periodic timer proof.
//!
//! Each AP, on its own existing permanent stack and private IDT, masks the
//! legacy local timer, installs a validated periodic timer plan, enables IF,
//! completes non-yielding work under >=4 *locally generated* IRQs, sends
//! exactly one local APIC EOI for each IRQ, then disables IF, stops and masks
//! its timer, and returns to its own parked CPU loop.
//!
//! BSP is ONLY a read-only coordinator after smp::boot_aps() returned. The
//! BSP never writes an AP's LVT register, never EOIs on an AP's behalf,
//! never receives timer IRQs, and does not run an SMP preemptive scheduler.
//! The UC xAPIC alias was installed before AP startup by ap_ipi_smoke.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use limine::mp::MpInfo;
use x86_64::structures::idt::InterruptStackFrame;

use crate::{
    ap_ipi_smoke, lapic_irq_layout, lapic_timer_layout, lapic_timer_plan, pmm, serial,
    smp::MAX_BOOT_CPUS,
};

pub const VECTOR: u8 = 0xe2;
const INITIAL_COUNT: u32 = 262_144;
const DIVISOR: u32 = 16;
const MIN_TICKS: u64 = 4;
const PMM_IF1_ROUNDS: u64 = 64;
const MAX_SPINS: u64 = 200_000_000;
const BSP_WAIT_SPINS: usize = 200_000_000;

static ACTIVE: [AtomicBool; MAX_BOOT_CPUS] =
    [const { AtomicBool::new(false) }; MAX_BOOT_CPUS];
static READY: [AtomicBool; MAX_BOOT_CPUS] =
    [const { AtomicBool::new(false) }; MAX_BOOT_CPUS];
static DONE: [AtomicBool; MAX_BOOT_CPUS] =
    [const { AtomicBool::new(false) }; MAX_BOOT_CPUS];
static FAILED: [AtomicBool; MAX_BOOT_CPUS] =
    [const { AtomicBool::new(false) }; MAX_BOOT_CPUS];
static TICKS: [AtomicU64; MAX_BOOT_CPUS] =
    [const { AtomicU64::new(0) }; MAX_BOOT_CPUS];
static ACKS: [AtomicU64; MAX_BOOT_CPUS] =
    [const { AtomicU64::new(0) }; MAX_BOOT_CPUS];
static WORK: [AtomicU64; MAX_BOOT_CPUS] =
    [const { AtomicU64::new(0) }; MAX_BOOT_CPUS];
static FIRST_IRQ_WORK: [AtomicU64; MAX_BOOT_CPUS] =
    [const { AtomicU64::new(0) }; MAX_BOOT_CPUS];
static PROGRESS_IRQS: [AtomicU64; MAX_BOOT_CPUS] =
    [const { AtomicU64::new(0) }; MAX_BOOT_CPUS];
static LAST_IRQ_WORK: [AtomicU64; MAX_BOOT_CPUS] =
    [const { AtomicU64::new(0) }; MAX_BOOT_CPUS];
static BAD: AtomicU64 = AtomicU64::new(0);
static PMM_IF1_PROBES: [AtomicU64; MAX_BOOT_CPUS] =
    [const { AtomicU64::new(0) }; MAX_BOOT_CPUS];

/// Invoked ONLY on AP IDT timer vector 0xe2. The xAPIC ID MMIO register is
/// local to the receiving core even though all cores share the UC alias VA.
pub extern "x86-interrupt" fn irq(_frame: InterruptStackFrame) {
    let slot = ap_ipi_smoke::ap_slot(ap_ipi_smoke::local_id());
    if let Some(index) = slot {
        if !ACTIVE[index].load(Ordering::Relaxed) {
            BAD.fetch_add(1, Ordering::Relaxed);
        } else {
            let progress = WORK[index].load(Ordering::Relaxed);
            let old_ticks = TICKS[index].fetch_add(1, Ordering::Relaxed);
            if old_ticks == 0 {
                FIRST_IRQ_WORK[index].store(progress, Ordering::Relaxed);
            } else if progress > LAST_IRQ_WORK[index].load(Ordering::Relaxed) {
                PROGRESS_IRQS[index].fetch_add(1, Ordering::Relaxed);
            }
            LAST_IRQ_WORK[index].store(progress, Ordering::Relaxed);
        }
    } else {
        BAD.fetch_add(1, Ordering::Relaxed);
    }
    // Fixed local APIC periodic timer IRQ, not spurious. Ack the *current*
    // AP's in-service entry exactly once before the CPU IRETQ.
    unsafe { ap_ipi_smoke::write(lapic_irq_layout::EOI_OFFSET, 0); }
    if let Some(index) = slot {
        ACKS[index].fetch_add(1, Ordering::Release);
    }
}

fn stop_timer() {
    // On this AP only, in kernel CPL0 with IF=0: first mask LVT, then
    // write initial count zero so the timer is definitively stopped.
    let lvt = unsafe { ap_ipi_smoke::read(lapic_timer_layout::LVT_TIMER_OFFSET) };
    unsafe {
        ap_ipi_smoke::write(
            lapic_timer_layout::LVT_TIMER_OFFSET, lvt | lapic_timer_layout::LVT_MASKED
        );
        ap_ipi_smoke::write(lapic_timer_layout::INITIAL_COUNT_OFFSET, 0);
    }
}

/// Invoked after prior AP boot workload, on one AP's private kernel stack.
/// Caller has independently validated this CPU's xAPIC identity and has
/// already masked its timer and installed software-enabled SVR.
/// Enter/return IF=0, and never publish DONE until timer has been stopped.
pub fn secondary_run(index: usize) -> bool {
    if index >= MAX_BOOT_CPUS
        || x86_64::instructions::interrupts::are_enabled()
        || ap_ipi_smoke::ap_slot(ap_ipi_smoke::local_id()) != Some(index)
    {
        return false;
    }
    let Ok(plan) = lapic_timer_plan::periodic_timer_plan(
        VECTOR, DIVISOR, INITIAL_COUNT
    ) else {
        FAILED[index].store(true, Ordering::Release);
        return false;
    };
    let previous_divisor =
        unsafe { ap_ipi_smoke::read(lapic_timer_layout::DIVIDE_CONFIG_OFFSET) };
    for operation in plan.preparation {
        // SAFETY: this AP owns its own local APIC; its interrupts are still
        // disabled and the plan begins with a masked timer.
        unsafe { ap_ipi_smoke::write(operation.offset, operation.value); }
    }
    // Commit the unmask only after both division and count are prepared.
    unsafe { ap_ipi_smoke::write(plan.activation.offset, plan.activation.value); }
    ACTIVE[index].store(true, Ordering::Release);
    x86_64::instructions::interrupts::enable();
    READY[index].store(true, Ordering::Release);

    // The local xAPIC timer is armed and IF=1. Exercise the real PMM
    // lock from this AP, checking that every allocation and release
    // returns with IF=1. This is an IF-state integration proof, not a
    // forced interrupt *inside* the lock critical section.
    let mut pmm_if1_ok = true;
    for _ in 0..PMM_IF1_ROUNDS {
        if !x86_64::instructions::interrupts::are_enabled() {
            pmm_if1_ok = false;
            break;
        }
        let Some(frame) = pmm::allocate_frame() else {
            pmm_if1_ok = false;
            break;
        };
        if pmm::free_frame(frame).is_err()
            || !x86_64::instructions::interrupts::are_enabled()
        {
            pmm_if1_ok = false;
            break;
        }
        PMM_IF1_PROBES[index].fetch_add(1, Ordering::Relaxed);
    }

    let mut reached = false;
    for _ in 0..MAX_SPINS {
        WORK[index].fetch_add(1, Ordering::Relaxed);
        if ACKS[index].load(Ordering::Acquire) >= MIN_TICKS
            && PROGRESS_IRQS[index].load(Ordering::Acquire) >= MIN_TICKS - 1
            && WORK[index].load(Ordering::Relaxed)
                > FIRST_IRQ_WORK[index].load(Ordering::Relaxed)
        {
            reached = true;
            break;
        }
        core::hint::spin_loop();
    }
    x86_64::instructions::interrupts::disable();
    stop_timer();
    ACTIVE[index].store(false, Ordering::Release);
    // Leave the timer masked and stopped to prevent surprise AP IRQs if a
    // later feature re-enables IF. Restore divisor, not unmasked LVT state.
    unsafe {
        ap_ipi_smoke::write(
            lapic_timer_layout::DIVIDE_CONFIG_OFFSET, previous_divisor
        );
    }

    let delivered = TICKS[index].load(Ordering::Relaxed);
    let eois = ACKS[index].load(Ordering::Acquire);
    let progress = PROGRESS_IRQS[index].load(Ordering::Relaxed);
    let work = WORK[index].load(Ordering::Relaxed);
    let stopped = unsafe {
        ap_ipi_smoke::read(lapic_timer_layout::INITIAL_COUNT_OFFSET) == 0
            && ap_ipi_smoke::read(lapic_timer_layout::LVT_TIMER_OFFSET)
                & lapic_timer_layout::LVT_MASKED != 0
    };
    let ok = pmm_if1_ok && reached && stopped && delivered >= MIN_TICKS
        && delivered == eois && progress >= MIN_TICKS - 1
        && work > FIRST_IRQ_WORK[index].load(Ordering::Relaxed);
    FAILED[index].store(!ok, Ordering::Release);
    DONE[index].store(true, Ordering::Release);
    ok
}

fn wait_all(cpus: &[&MpInfo], bsp_id: u32) -> bool {
    for _ in 0..BSP_WAIT_SPINS {
        if cpus.iter().enumerate().all(|(index, cpu)| {
            cpu.lapic_id == bsp_id || (DONE[index].load(Ordering::Acquire)
                && ap_ipi_smoke::is_offline(index))
        }) { return true; }
        core::hint::spin_loop();
    }
    false
}

/// BSP IF=0, after all old SMP stack/context smoke tests have completed.
/// No AP-local MMIO register is ever touched by this verifier.
pub fn verify_bsp(bsp_id: u32, cpus: &[&MpInfo]) -> bool {
    if x86_64::instructions::interrupts::are_enabled()
        || cpus.len() != 4
        || cpus.iter().filter(|cpu| cpu.lapic_id == bsp_id).count() != 1
        || !wait_all(cpus, bsp_id)
    {
        serial::write_line("WOLFOS_AP_LOCAL_TIMER_ERROR ap_not_finished");
        return false;
    }
    let (mut ticks, mut eois, mut progress, mut work, mut ready, mut done) =
        (0u64, 0u64, 0u64, 0u64, 0usize, 0usize);
    let mut pmm_if1_probes = 0u64;
    let mut ok = true;
    for (index, cpu) in cpus.iter().enumerate() {
        if cpu.lapic_id == bsp_id { continue; }
        let irq = TICKS[index].load(Ordering::Acquire);
        let ack = ACKS[index].load(Ordering::Acquire);
        let advances = PROGRESS_IRQS[index].load(Ordering::Acquire);
        let steps = WORK[index].load(Ordering::Acquire);
        let armed = READY[index].load(Ordering::Acquire);
        let finished = DONE[index].load(Ordering::Acquire)
            && ap_ipi_smoke::is_offline(index);
        if !armed || !finished || FAILED[index].load(Ordering::Acquire)
            || ACTIVE[index].load(Ordering::Acquire)
            || irq < MIN_TICKS || ack != irq
            || advances < MIN_TICKS - 1
            || steps <= FIRST_IRQ_WORK[index].load(Ordering::Acquire)
        { ok = false; }
        ticks += irq;
        eois += ack;
        progress += advances;
        work += steps;
        pmm_if1_probes += PMM_IF1_PROBES[index].load(Ordering::Acquire);
        ready += usize::from(armed);
        done += usize::from(finished);
    }
    let bad = BAD.load(Ordering::Acquire);
    let spurious = ap_ipi_smoke::spurious_count();
    let unexpected_ipi = ap_ipi_smoke::ipi_count();
    if ok && ready == 3 && done == 3 && ticks >= 12
        && eois == ticks && progress >= 9 && work > 0
        && bad == 0 && spurious == 0 && unexpected_ipi == 0
        && pmm_if1_probes == 3 * PMM_IF1_ROUNDS
    {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_LOCAL_TIMER_OK cpus=4 aps=3 min_per_ap=4 ticks={} eois={} progress_irqs={} work={} ready={} offline={} invalid={} spurious={} unexpected_ipi={} vector={} bsp_if=0\n",
            ticks, eois, progress, work, ready, done, bad, spurious,
            unexpected_ipi, VECTOR
        ));
        serial::write_fmt(format_args!(
            "WOLFOS_PMM_IRQ_IF1_OK aps=3 probes={} timer_ticks={}\n",
            pmm_if1_probes, ticks,
        ));
        true
    } else {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_LOCAL_TIMER_ERROR ticks={} eois={} progress_irqs={} work={} ready={} offline={} invalid={} spurious={} unexpected_ipi={} pmm_if1_probes={} all_ok={}\n",
            ticks, eois, progress, work, ready, done, bad, spurious,
            unexpected_ipi, pmm_if1_probes, ok,
        ));
        false
    }
}
