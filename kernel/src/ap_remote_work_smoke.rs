//! QEMU-only directed IPI -> remote AP work execution proof.
//!
//! BSP publishes a NEW job into exactly one AP-owned, generation-tagged
//! mailbox and sends that AP a *real* fixed xAPIC IPI. The AP's own IRQ
//! claims only that exact mailbox, writes its local EOI and returns. Its
//! ordinary AP worker loop then computes the job outside IRQ context and
//! publishes a checked completion. BSP validates the digest and retires
//! that generation before reusing the slot.
//!
//! No context stack migrates between processors, no worker runs on BSP,
//! no production SMP scheduler is claimed. All AP work uses each AP's
//! existing permanent MP kernel stack; IPI delivery never schedules a
//! suspended task directly.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use limine::mp::MpInfo;

use crate::{
    ap_ipi_smoke, remote_runqueue::{compute_digest, RemoteMailbox}, serial,
};

const CPU_COUNT: usize = 4;
const JOB_ROUNDS: u64 = 4;
const WAIT_SPINS: usize = 200_000_000;
const INVALID_ID: u32 = u32::MAX;

static QUEUES: [RemoteMailbox; CPU_COUNT] = [
    RemoteMailbox::new(0),
    RemoteMailbox::new(1),
    RemoteMailbox::new(2),
    RemoteMailbox::new(3),
];

static READY: [AtomicBool; CPU_COUNT] = [
    const { AtomicBool::new(false) }; CPU_COUNT
];
static FINISHED: [AtomicU64; CPU_COUNT] = [
    const { AtomicU64::new(0) }; CPU_COUNT
];
static CLAIMS: [AtomicU64; CPU_COUNT] = [
    const { AtomicU64::new(0) }; CPU_COUNT
];
static BAD: AtomicU64 = AtomicU64::new(0);
static STOP: AtomicBool = AtomicBool::new(false);

fn token(cpu: usize, generation: u64) -> u64 {
    (generation << 32) | ((cpu as u64) << 16) | 0x51a5
}

/// Real IPI handler callback. Executes ONLY on the receiving AP with IF=0,
/// with no allocations, logging, spin locks, task switching or stack changes.
/// The shared xAPIC interrupt handler issues the single recipient-side EOI
/// after this callback returns.
pub fn on_ipi(cpu: usize) {
    if cpu >= CPU_COUNT {
        BAD.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if QUEUES[cpu].claim_from_irq(cpu).is_err() {
        BAD.fetch_add(1, Ordering::Relaxed);
    } else {
        CLAIMS[cpu].fetch_add(1, Ordering::Release);
    }
}

/// AP-only worker. Enter with IF=0, returns IF=0. The BSP does not enter
/// this function. One AP alone reads/modifies its slot and runs its jobs.
pub fn secondary_run(cpu: usize) -> bool {
    if cpu >= CPU_COUNT
        || ap_ipi_smoke::ap_slot(ap_ipi_smoke::local_id()) != Some(cpu)
        || x86_64::instructions::interrupts::are_enabled()
    {
        return false;
    }

    x86_64::instructions::interrupts::enable();
    READY[cpu].store(true, Ordering::Release);
    let mut last = 0u64;
    let mut success = true;
    // Never HLT without an extra wake IPI: STOP is published by BSP after
    // final retirement, and a spin avoids lost wake-up races.
    while !STOP.load(Ordering::Acquire) {
        match QUEUES[cpu].claimed_work(cpu) {
            Ok(Some(job)) => {
                if job.sequence != last + 1 || job.token != token(cpu, job.sequence) {
                    success = false;
                    break;
                }
                // This CPU owns the newly dispatched work. The IRQ already
                // returned and EOI has completed before work starts.
                let result = compute_digest(cpu, job.sequence, job.token);
                if QUEUES[cpu].finish(cpu, job.sequence, result).is_err() {
                    success = false;
                    break;
                }
                FINISHED[cpu].fetch_add(1, Ordering::Release);
                last = job.sequence;
            }
            Ok(None) => core::hint::spin_loop(),
            Err(_) => { success = false; break; }
        }
    }
    x86_64::instructions::interrupts::disable();
    let final_ok = success && last == JOB_ROUNDS
        && FINISHED[cpu].load(Ordering::Acquire) == JOB_ROUNDS
        && CLAIMS[cpu].load(Ordering::Acquire) == JOB_ROUNDS
        && QUEUES[cpu].is_idle_generation(JOB_ROUNDS);
    if !final_ok {
        BAD.fetch_add(1, Ordering::Relaxed);
    }
    final_ok
}

fn wait(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..WAIT_SPINS {
        if condition() { return true; }
        core::hint::spin_loop();
    }
    condition()
}

/// BSP ONLY; called after all prior 4-vCPU SMP boot workloads complete.
/// BSP IF stays disabled. Every IPI targets the actual APIC ID in the
/// Limine MP directory, not an assumed contiguous index.
pub fn verify_bsp(bsp: u32, cpus: &[&MpInfo]) -> bool {
    if cpus.len() != CPU_COUNT
        || cpus.iter().filter(|cpu| cpu.lapic_id == bsp).count() != 1
        || x86_64::instructions::interrupts::are_enabled()
        || !wait(|| cpus.iter().enumerate().all(|(i,c)|
            c.lapic_id == bsp || READY[i].load(Ordering::Acquire)
        ))
    {
        serial::write_line("WOLFOS_REMOTE_WORK_ERROR ap_not_ready");
        return false;
    }

    let mut sent = 0u64;
    let mut accepted = 0u64;
    let mut good = true;
    'rounds: for generation in 1..=JOB_ROUNDS {
        for (index, cpu) in cpus.iter().enumerate() {
            if cpu.lapic_id == bsp { continue; }
            if QUEUES[index].publish(index, generation, token(index, generation)).is_err()
                || !ap_ipi_smoke::send(bsp, cpu.lapic_id)
            {
                good = false;
                break 'rounds;
            }
            sent += 1;
        }
        // Await actual remote worker completion, not just delivery-pending
        // clear or the interrupt's EOI (which is not work completion).
        for (index, cpu) in cpus.iter().enumerate() {
            if cpu.lapic_id == bsp { continue; }
            if !wait(|| QUEUES[index].completed(index, generation)
                .ok().flatten().is_some()
            ) {
                good = false;
                break 'rounds;
            }
            let answer = QUEUES[index].completed(index, generation).ok().flatten();
            if answer != Some(compute_digest(
                index, generation, token(index, generation),
            )) || ap_ipi_smoke::ipi_received(index) != generation
                || ap_ipi_smoke::ipi_eois(index) != generation
                || CLAIMS[index].load(Ordering::Acquire) != generation
                || FINISHED[index].load(Ordering::Acquire) != generation
                || QUEUES[index].retire(index, generation).is_err()
            {
                good = false;
                break 'rounds;
            }
            accepted += 1;
        }
    }

    // All IPIs were delivered and EOI'd before marking STOP. AP worker
    // disables IF, restores its original local APIC timer/SVR and parks.
    STOP.store(true, Ordering::Release);
    let parked = wait(|| cpus.iter().enumerate().all(|(i, cpu)|
        cpu.lapic_id == bsp || ap_ipi_smoke::is_offline(i)
    ));

    let mut received = 0u64;
    let mut eois = 0u64;
    let mut claims = 0u64;
    let mut executed = 0u64;
    let mut idle = 0usize;
    for (i, cpu) in cpus.iter().enumerate() {
        if cpu.lapic_id == bsp { continue; }
        let r = ap_ipi_smoke::ipi_received(i);
        let e = ap_ipi_smoke::ipi_eois(i);
        let c = CLAIMS[i].load(Ordering::Acquire);
        let x = FINISHED[i].load(Ordering::Acquire);
        if r != JOB_ROUNDS || e != JOB_ROUNDS
            || c != JOB_ROUNDS || x != JOB_ROUNDS
            || !QUEUES[i].is_idle_generation(JOB_ROUNDS)
            || !ap_ipi_smoke::is_offline(i)
        {
            good = false;
        }
        received += r;
        eois += e;
        claims += c;
        executed += x;
        idle += usize::from(QUEUES[i].is_idle_generation(JOB_ROUNDS));
    }
    let bad = BAD.load(Ordering::Acquire) + ap_ipi_smoke::bad_count();
    let spurious = ap_ipi_smoke::spurious_count();
    let aps = cpus.len() - 1;

    if good && parked && aps == 3 && sent == 12 && accepted == 12
        && received == 12 && eois == 12 && claims == 12
        && executed == 12 && idle == 3
        && bad == 0 && spurious == 0
    {
        serial::write_fmt(format_args!(
            "WOLFOS_REMOTE_WORK_OK cpus=4 aps=3 per_ap={} published={} sent={} claims={} completed={} retired={} received={} eois={} idle={} offline=3 wrong_owner=0 duplicates=0 invalid={} spurious={} migrated=0 bsp_if=0\n",
            JOB_ROUNDS, sent, sent, claims, executed, accepted,
            received, eois, idle, bad, spurious
        ));
        true
    } else {
        serial::write_fmt(format_args!(
            "WOLFOS_REMOTE_WORK_ERROR published={} sent={} claims={} completed={} retired={} received={} eois={} idle={} parked={} good={} invalid={} spurious={}\n",
            sent, sent, claims, executed, accepted, received, eois,
            idle, parked, good, bad, spurious,
        ));
        false
    }
}
