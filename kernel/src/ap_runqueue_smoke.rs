//! QEMU-only 4-vCPU real IPI wake and BOUNDED per-AP work queue proof.
//!
//! BSP fills each destination's four-entry FIFO *before* sending one real
//! directed xAPIC IPI. AP-local IRQ increments only a wake epoch and EOIs;
//! actual work dequeuing and digest execution occurs after IRETQ on that
//! AP's own 32-KiB permanent MP kernel stack. Three independent AP workers
//! rendezvous inside each of two CPU-bound waves, proving overlapping
//! active work without sharing task stacks.
//!
//! Per-AP owner checks, six full-queue backpressure denials, six wrong-CPU
//! denials, 24 ordered completions, six hardware IPIs/EOIs and three FIFO
//! ring wraps are mandatory. This is a single-producer smoke facility, not
//! live context migration or a production SMP scheduler.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use limine::mp::MpInfo;
use crate::{
    ap_ipi_smoke, ap_work_placement::{choose_destination, PlacementError},
    percpu_work_queue::{CpuWorkQueue, QueueError, CAPACITY, digest}, serial,
};

const CPUS: usize = 4;
const WAVES: u64 = 2;
const PER_CPU: u64 = WAVES * CAPACITY as u64;
const WAIT_SPINS: usize = 200_000_000;

static Q: [CpuWorkQueue; CPUS] = [
    CpuWorkQueue::new(0),
    CpuWorkQueue::new(1),
    CpuWorkQueue::new(2),
    CpuWorkQueue::new(3),
];
static READY: [AtomicBool; CPUS] = [const { AtomicBool::new(false) }; CPUS];
static WAKE: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static ARMED: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static FINISHED: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static IN_IRQ: [AtomicBool; CPUS] = [const { AtomicBool::new(false) }; CPUS];
static RESULTS: [[AtomicU64; PER_CPU as usize]; CPUS] =
    [const { [const { AtomicU64::new(0) }; PER_CPU as usize] }; CPUS];
static ENTERED: [AtomicUsize; WAVES as usize] =
    [const { AtomicUsize::new(0) }; WAVES as usize];
static RELEASE: AtomicU64 = AtomicU64::new(0);
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static STOP: AtomicBool = AtomicBool::new(false);
static ERRORS: AtomicU64 = AtomicU64::new(0);

fn token(cpu: usize, seq: u64) -> u64 {
    (seq << 32) | ((cpu as u64) << 16) | 0x61a5
}

fn wait(mut predicate: impl FnMut() -> bool) -> bool {
    for _ in 0..WAIT_SPINS {
        if predicate() { return true; }
        core::hint::spin_loop();
    }
    predicate()
}

/// Called ONLY from receiving AP's private IDT, IF=0. No queue mutation,
/// locks, allocation, context switch, or work here. Parent handler issues
/// exactly one receiving local xAPIC EOI after this callback returns.
pub fn on_ipi(cpu: usize) {
    if cpu >= CPUS {
        ERRORS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if IN_IRQ[cpu].swap(true, Ordering::AcqRel) {
        ERRORS.fetch_add(1, Ordering::Relaxed);
    }
    WAKE[cpu].fetch_add(1, Ordering::Release);
    IN_IRQ[cpu].store(false, Ordering::Release);
}

/// Runs after IRETQ on this AP's existing MP stack, not inside its IRQ.
/// Each AP enters two separate waves, each with exactly four FIFO jobs.
pub fn secondary_run(cpu: usize) -> bool {
    if cpu == 0 || cpu >= CPUS
        || ap_ipi_smoke::ap_slot(ap_ipi_smoke::local_id()) != Some(cpu)
        || x86_64::instructions::interrupts::are_enabled()
    { return false; }

    x86_64::instructions::interrupts::enable();
    READY[cpu].store(true, Ordering::Release);
    let mut good = true;
    for wave in 1..=WAVES {
        if !wait(|| WAKE[cpu].load(Ordering::Acquire) >= wave
            || STOP.load(Ordering::Acquire))
            || STOP.load(Ordering::Acquire)
        { good = false; break; }
        // The BSP has already published the entire wave before the IPI.
        if IN_IRQ[cpu].load(Ordering::Acquire)
            || WAKE[cpu].load(Ordering::Acquire) != wave
            || Q[cpu].try_len() != Ok(CAPACITY)
        { good = false; break; }
        ARMED[cpu].store(wave, Ordering::Release);
        if !wait(|| RELEASE.load(Ordering::Acquire) >= wave
            || STOP.load(Ordering::Acquire))
            || STOP.load(Ordering::Acquire)
        { good = false; break; }
        let active = ACTIVE.fetch_add(1, Ordering::AcqRel) + 1;
        PEAK.fetch_max(active, Ordering::AcqRel);
        ENTERED[(wave - 1) as usize].fetch_add(1, Ordering::AcqRel);
        // All three APs must occupy their own worker loops before any AP
        // can complete the wave. This explicitly checks overlapping active
        // runnable work rather than mere serialized completion totals.
        if !wait(|| ENTERED[(wave - 1) as usize].load(Ordering::Acquire) == 3
            || STOP.load(Ordering::Acquire))
            || STOP.load(Ordering::Acquire)
        {
            ACTIVE.fetch_sub(1, Ordering::AcqRel);
            good = false;
            break;
        }
        for slot in 0..CAPACITY {
            let expected = (wave - 1) * CAPACITY as u64 + slot as u64 + 1;
            let Ok(Some(job)) = Q[cpu].dequeue(cpu) else {
                good = false;
                break;
            };
            if job.sequence != expected || job.token != token(cpu, expected)
                || IN_IRQ[cpu].load(Ordering::Acquire)
                || !x86_64::instructions::interrupts::are_enabled()
            {
                good = false;
                break;
            }
            let result = digest(cpu, job.sequence, job.token);
            RESULTS[cpu][(expected - 1) as usize].store(result, Ordering::Relaxed);
            // Completed result visible to BSP only after a Release store.
            FINISHED[cpu].store(expected, Ordering::Release);
        }
        ACTIVE.fetch_sub(1, Ordering::AcqRel);
        if !good || !Q[cpu].is_drained(wave * CAPACITY as u64) {
            good = false;
            break;
        }
    }
    // If one AP fails, BSP's finite wait will fail closed. STOP is
    // published only after all successful waves; no lost HLT wake-up.
    while good && !STOP.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
    x86_64::instructions::interrupts::disable();
    let final_ok = good
        && Q[cpu].is_drained(PER_CPU)
        && FINISHED[cpu].load(Ordering::Acquire) == PER_CPU
        && WAKE[cpu].load(Ordering::Acquire) == WAVES
        && ARMED[cpu].load(Ordering::Acquire) == WAVES
        && !IN_IRQ[cpu].load(Ordering::Acquire);
    if !final_ok { ERRORS.fetch_add(1, Ordering::Relaxed); }
    final_ok
}

/// BSP-only, IF=0. The BSP never executes the jobs or changes AP stack
/// ownership. MP indices and real xAPIC IDs are mapped by the MP table.
pub fn verify_bsp(bsp: u32, cpus: &[&MpInfo]) -> bool {
    if cpus.len() != CPUS || cpus[0].lapic_id != bsp
        || cpus.iter().filter(|c| c.lapic_id == bsp).count() != 1
        || x86_64::instructions::interrupts::are_enabled()
        || !wait(|| (1..CPUS).all(|i| READY[i].load(Ordering::Acquire)))
    {
        serial::write_line("WOLFOS_AP_RUNQUEUE_ERROR topology_or_ready");
        return false;
    }

    let (mut submitted, mut sent, mut full, mut wrong, mut checked,
         mut redirects, mut no_capacity) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut valid = true;
    'waves: for wave in 1..=WAVES {
        // ALL new jobs request AP1. The first 4 stay there. Once AP1
        // becomes full, 8 overflow jobs are routed to the least-loaded
        // ready AP2/AP3 before any AP is woken. This is placement of
        // NEW jobs only; no live task ownership or queued jobs move.
        let online = [false,
            READY[1].load(Ordering::Acquire),
            READY[2].load(Ordering::Acquire),
            READY[3].load(Ordering::Acquire)];
        for _ in 0..((CPUS - 1) * CAPACITY) {
            let (Ok(q1), Ok(q2), Ok(q3)) =
                (Q[1].try_len(), Q[2].try_len(), Q[3].try_len())
            else { valid = false; break 'waves; };
            let queued = [0, q1, q2, q3];
            let Ok(choice) = choose_destination(1, 0, &online, &queued, CAPACITY)
            else { valid = false; break 'waves; };
            let cpu = choice.destination;
            if choice.redirected { redirects += 1; }
            let seq = (wave - 1) * CAPACITY as u64 + queued[cpu] as u64 + 1;
            if Q[cpu].enqueue(cpu, seq, token(cpu, seq)).is_err() {
                valid = false; break 'waves;
            }
            submitted += 1;
        }
        // Every AP queue is now full. The placement policy must refuse
        // additional work instead of overwriting anyone's FIFO.
        let (Ok(q1), Ok(q2), Ok(q3)) =
            (Q[1].try_len(), Q[2].try_len(), Q[3].try_len())
        else { valid = false; break 'waves; };
        let all_full = [0, q1, q2, q3];
        if choose_destination(1, 0, &online, &all_full, CAPACITY)
            == Err(PlacementError::NoCapacity)
        { no_capacity += 1; } else { valid = false; break 'waves; }
        for cpu in 1..CPUS {
            let overflow_seq = wave * CAPACITY as u64 + 1;
            if Q[cpu].enqueue(cpu, overflow_seq, token(cpu, overflow_seq))
                == Err(QueueError::Full)
            { full += 1; } else { valid = false; break 'waves; }
            let other = if cpu == 3 { 1 } else { cpu + 1 };
            if Q[cpu].enqueue(other, overflow_seq, token(other, overflow_seq))
                == Err(QueueError::WrongCpu)
            { wrong += 1; } else { valid = false; break 'waves; }
            if Q[cpu].try_len() != Ok(CAPACITY) {
                valid = false; break 'waves;
            }
        }
        for cpu in 1..CPUS {
            if !ap_ipi_smoke::send(bsp, cpus[cpu].lapic_id) {
                valid = false;
                break 'waves;
            }
            sent += 1;
        }
        if !wait(|| (1..CPUS).all(|i| ARMED[i].load(Ordering::Acquire) == wave)) {
            valid = false;
            break 'waves;
        }
        RELEASE.store(wave, Ordering::Release);
        if !wait(|| (1..CPUS).all(|i| FINISHED[i].load(Ordering::Acquire)
            == wave * CAPACITY as u64))
        {
            valid = false;
            break 'waves;
        }
        for cpu in 1..CPUS {
            for slot in 0..CAPACITY {
                let seq = (wave - 1) * CAPACITY as u64 + slot as u64 + 1;
                let expected = digest(cpu, seq, token(cpu, seq));
                let received =
                    RESULTS[cpu][(seq - 1) as usize].load(Ordering::Acquire);
                if received != expected {
                    valid = false;
                    break 'waves;
                }
                checked += 1;
            }
            if !Q[cpu].is_drained(wave * CAPACITY as u64) {
                valid = false;
                break 'waves;
            }
        }
    }

    STOP.store(true, Ordering::Release);
    let parked = wait(|| (1..CPUS).all(|i| ap_ipi_smoke::is_offline(i)));
    let (mut ipis, mut eois, mut jobs, mut drained) =
        (0u64, 0u64, 0u64, 0usize);
    for cpu in 1..CPUS {
        ipis += ap_ipi_smoke::ipi_received(cpu);
        eois += ap_ipi_smoke::ipi_eois(cpu);
        jobs += FINISHED[cpu].load(Ordering::Acquire);
        drained += usize::from(Q[cpu].is_drained(PER_CPU));
        if ap_ipi_smoke::ipi_received(cpu) != WAVES
            || ap_ipi_smoke::ipi_eois(cpu) != WAVES
            || WAKE[cpu].load(Ordering::Acquire) != WAVES
            || ARMED[cpu].load(Ordering::Acquire) != WAVES
            || FINISHED[cpu].load(Ordering::Acquire) != PER_CPU
            || !ap_ipi_smoke::is_offline(cpu)
        { valid = false; }
    }
    let peak = PEAK.load(Ordering::Acquire);
    let remaining = ACTIVE.load(Ordering::Acquire);
    let bad = ERRORS.load(Ordering::Acquire) + ap_ipi_smoke::bad_count();
    let spurious = ap_ipi_smoke::spurious_count();
    if valid && parked && submitted == 24 && sent == 6
        && checked == submitted && ipis == sent && eois == sent
        && jobs == submitted && full == 6 && wrong == 6
        && redirects == 16 && no_capacity == 2
        && drained == 3 && peak == 3 && remaining == 0
        && ENTERED[0].load(Ordering::Acquire) == 3
        && ENTERED[1].load(Ordering::Acquire) == 3
        && bad == 0 && spurious == 0
    {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_RUNQUEUE_OK cpus=4 aps=3 capacity=4 waves=2 submitted={} executed={} full_rejected={} wrong_owner_rejected={} ipis={} eois={} fifo={} wraps=3 peak={} active={} idle={} offline=3 invalid={} spurious={} bsp_if=0 task_migrated=0 redirected={} no_capacity={}\n",
            submitted, jobs, full, wrong, ipis, eois,
            checked, peak, remaining, drained, bad, spurious,
            redirects, no_capacity
        ));
        true
    } else {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_RUNQUEUE_ERROR submitted={} sent={} executed={} checked={} full={} wrong={} ipis={} eois={} peak={} active={} idle={} parked={} valid={} invalid={} spurious={}\n",
            submitted, sent, jobs, checked, full, wrong, ipis, eois,
            peak, remaining, drained, parked, valid, bad, spurious
        ));
        false
    }
}
