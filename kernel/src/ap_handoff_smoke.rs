//! QEMU-only real xAPIC IPI proof: ONE paused logical continuation
//! is transferred AP1 -> AP2 -> AP3 -> AP1 across 12 short CPU quanta.
//!
//! The BSP ONLY dispatches and verifies; AP-private IRQ handlers claim
//! a one-slot mailbox with no computation, issue a local EOI and IRETQ.
//! Each owner AP then resumes the TaskLease OUTSIDE its IRQ, advances
//! the logical digest/step once on its own *existing* MP kernel stack,
//! pauses, and publishes a completion. BSP verifies that a quiesced state
//! exactly matches the independently computed expected continuation
//! BEFORE transferring owner+epoch to the next AP and issuing its IPI.
//!
//! No live saved RSP/trap frame, TLS/CR3, FX/XSAVE image or stack migrates.
//! This is an atomic *logical-state handoff* proof, not arbitrary live
//! kernel task migration, nor a production SMP run queue.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use limine::mp::MpInfo;

use crate::{
    ap_ipi_smoke,
    ap_handoff_validation::{validate, StepEvidence, StepFailure},
    remote_runqueue::RemoteMailbox,
    serial,
    task_handoff::{advance_digest, HandoffError, TaskLease, INITIAL_DIGEST},
};

const CPU_COUNT: usize = 4;
const TOTAL_STEPS: u64 = 12;
const PER_AP: u64 = 4;
const WAIT_SPINS: usize = 200_000_000;
const MAX_BAD: u64 = 0;

static TASK: TaskLease = TaskLease::new();
static QUEUES: [RemoteMailbox; CPU_COUNT] = [
    RemoteMailbox::new(0),
    RemoteMailbox::new(1),
    RemoteMailbox::new(2),
    RemoteMailbox::new(3),
];
static READY: [AtomicBool; CPU_COUNT] =
    [const { AtomicBool::new(false) }; CPU_COUNT];
static CLAIMS: [AtomicU64; CPU_COUNT] =
    [const { AtomicU64::new(0) }; CPU_COUNT];
static EXECUTED: [AtomicU64; CPU_COUNT] =
    [const { AtomicU64::new(0) }; CPU_COUNT];
static STOP: AtomicBool = AtomicBool::new(false);
static BAD: AtomicU64 = AtomicU64::new(0);

/// AP-private vector 0xE1 handler: only claim current generation.
pub fn on_ipi(cpu: usize) {
    if cpu >= CPU_COUNT || QUEUES[cpu].claim_from_irq(cpu).is_err() {
        BAD.fetch_add(1, Ordering::Relaxed);
        return;
    }
    CLAIMS[cpu].fetch_add(1, Ordering::Release);
}

/// AP only, on its own permanent MP kernel stack. No task runs in IRQ.
pub fn secondary_run(cpu: usize) -> bool {
    if cpu >= CPU_COUNT
        || ap_ipi_smoke::ap_slot(ap_ipi_smoke::local_id()) != Some(cpu)
        || x86_64::instructions::interrupts::are_enabled()
    { return false; }
    x86_64::instructions::interrupts::enable();
    READY[cpu].store(true, Ordering::Release);
    let mut local_generation = 0u64;
    let mut good = true;
    while !STOP.load(Ordering::Acquire) {
        match QUEUES[cpu].claimed_work(cpu) {
            Ok(Some(job)) => {
                // Sequence belongs to this AP's mailbox. Token is the
                // *global* logical epoch + 1 and was published by BSP
                // strictly AFTER successful Paused->InTransit transfer.
                if job.sequence != local_generation + 1 || job.token == 0 {
                    good = false;
                    break;
                }
                let epoch = job.token - 1;
                if TASK.resume(cpu, epoch).is_err() {
                    good = false;
                    break;
                }
                let Ok(snapshot) = TASK.execute_quantum(cpu, epoch) else {
                    good = false;
                    break;
                };
                // Paused snapshot Release publication occurs BEFORE this
                // per-CPU mailbox publishes Completed. BSP can now
                // Acquire-check both CPU ownership and task continuation.
                if QUEUES[cpu].finish(cpu, job.sequence, snapshot.digest).is_err() {
                    good = false;
                    break;
                }
                local_generation = job.sequence;
                EXECUTED[cpu].fetch_add(1, Ordering::Release);
            }
            Ok(None) => core::hint::spin_loop(),
            Err(_) => { good = false; break; }
        }
    }
    x86_64::instructions::interrupts::disable();
    let accepted = good && local_generation == PER_AP
        && EXECUTED[cpu].load(Ordering::Acquire) == PER_AP
        && CLAIMS[cpu].load(Ordering::Acquire) == PER_AP
        && QUEUES[cpu].is_idle_generation(PER_AP);
    if !accepted { BAD.fetch_add(1, Ordering::Relaxed); }
    accepted
}

fn wait(mut predicate: impl FnMut() -> bool) -> bool {
    for _ in 0..WAIT_SPINS {
        if predicate() { return true; }
        core::hint::spin_loop();
    }
    predicate()
}

/// BSP only, IF=0; validate the MP directory, then send real directed
/// hardware IPIs. BSP never accesses or resumes AP CPU saved stacks.
pub fn verify_bsp(bsp_id: u32, cpus: &[&MpInfo]) -> bool {
    if cpus.len() != CPU_COUNT
        || x86_64::instructions::interrupts::are_enabled()
        || cpus.iter().filter(|c| c.lapic_id == bsp_id).count() != 1
    {
        serial::write_line("WOLFOS_AP_HANDOFF_ERROR invalid_topology");
        return false;
    }
    let mut aps = [usize::MAX; 3];
    let mut pos = 0usize;
    for (i, info) in cpus.iter().enumerate() {
        if info.lapic_id == bsp_id { continue; }
        if i == 0 || pos >= 3 {
            // The isolated migration lease deliberately reserves owner0
            // for the BSP, so require QEMU's BSP-first MP index layout.
            serial::write_line("WOLFOS_AP_HANDOFF_ERROR unsupported_cpu_directory");
            return false;
        }
        aps[pos] = i;
        pos += 1;
    }
    if pos != 3 || !wait(|| aps.iter().all(|&i| READY[i].load(Ordering::Acquire))) {
        serial::write_line("WOLFOS_AP_HANDOFF_ERROR ap_not_ready");
        return false;
    }
    if TASK.initialize(aps[0]).is_err() {
        serial::write_line("WOLFOS_AP_HANDOFF_ERROR initialization");
        return false;
    }

    let mut expected_digest = INITIAL_DIGEST;
    let mut epoch = 0u64;
    let mut last = aps[0];
    let mut migrations = 0u64;
    let mut sent = 0u64;
    let mut paused = 0u64;
    let mut denied = 0u64;
    let mut valid = true;
    // Diagnoses the FIRST refused BSP transition only; never relax a gate.
    let mut failure_phase = "none";
    let mut failure_step = 0u64;
    let mut failure_cpu = 0usize;
    let mut failure_evidence: Option<(StepFailure, StepEvidence)> = None;
    let mut local_generations = [0u64; CPU_COUNT];

    'steps: for step in 1..=TOTAL_STEPS {
        let cpu = aps[((step - 1) % 3) as usize];
        failure_step = step;
        failure_cpu = cpu;
        if step > 1 {
            let old_epoch = epoch;
            let Ok(next_epoch) = TASK.transfer(last, cpu, old_epoch) else {
                failure_phase = "transfer";
                valid = false;
                break 'steps;
            };
            epoch = next_epoch;
            migrations += 1;
            // Immediately repeat the stale transfer after the owner
            // changed. Must fail: previous CPU cannot reclaim a fresh
            // generation or authorize overlapping execution.
            if TASK.transfer(last, cpu, old_epoch)
                == Err(HandoffError::WrongOwner) {
                denied += 1;
            } else {
                failure_phase = "stale_owner_rejection";
                valid = false;
                break 'steps;
            }
        }
        local_generations[cpu] += 1;
        let generation = local_generations[cpu];
        if QUEUES[cpu].publish(cpu, generation, epoch + 1).is_err() {
            failure_phase = "mailbox_publish";
            valid = false;
            break 'steps;
        }
        if !ap_ipi_smoke::send(bsp_id, cpus[cpu].lapic_id) {
            failure_phase = "ipi_send";
            valid = false;
            break 'steps;
        }
        sent += 1;
        // Do not trust an ICR delivery bit or EOI as work completion.
        // Require a returned, generation-matched AP-owned result.
        if !wait(|| QUEUES[cpu].completed(cpu, generation)
            .ok().flatten().is_some())
        {
            failure_phase = "completion_wait";
            valid = false;
            break 'steps;
        }
        expected_digest = advance_digest(expected_digest, step);
        let evidence = StepEvidence {
            snapshot: TASK.snapshot().ok()
                .map(|s| (s.epoch, s.owner, s.steps, s.digest)),
            completion: QUEUES[cpu].completed(cpu, generation).ok().flatten(),
            received: ap_ipi_smoke::ipi_received(cpu),
            eois: ap_ipi_smoke::ipi_eois(cpu),
            claimed: CLAIMS[cpu].load(Ordering::Acquire),
            executed: EXECUTED[cpu].load(Ordering::Acquire),
        };
        if let Err(why) = validate(
            evidence, epoch, cpu, step, expected_digest, generation
        ) {
            failure_phase = "proof_validation";
            failure_evidence = Some((why, evidence));
            valid = false;
            break 'steps;
        }
        if QUEUES[cpu].retire(cpu, generation).is_err() {
            failure_phase = "mailbox_retire";
            valid = false;
            break 'steps;
        }
        paused += 1;
        last = cpu;
    }
    if valid && TASK.retire(last, epoch).is_err() {
        failure_phase = "final_retire";
        valid = false;
    }
    // STOP only after last completion and owner retirement, never while
    // any AP is still writing a quiesced snapshot or handling its IRQ.
    STOP.store(true, Ordering::Release);
    let all_offline = wait(|| aps.iter().all(|&cpu| ap_ipi_smoke::is_offline(cpu)));

    let (mut irqs, mut eois, mut claimed, mut executed, mut idle) =
        (0u64, 0u64, 0u64, 0u64, 0usize);
    for &cpu in &aps {
        let seen = ap_ipi_smoke::ipi_received(cpu);
        let acked = ap_ipi_smoke::ipi_eois(cpu);
        irqs += seen;
        eois += acked;
        claimed += CLAIMS[cpu].load(Ordering::Acquire);
        executed += EXECUTED[cpu].load(Ordering::Acquire);
        idle += usize::from(QUEUES[cpu].is_idle_generation(PER_AP));
        if seen != PER_AP || acked != PER_AP
            || CLAIMS[cpu].load(Ordering::Acquire) != PER_AP
            || EXECUTED[cpu].load(Ordering::Acquire) != PER_AP
            || !ap_ipi_smoke::is_offline(cpu)
        { valid = false; }
    }
    // Only error-path instrumentation; no timing-sensitive serial writes
    // between IPI delivery and worker completion, no retry and no skip.
    if !valid || !all_offline {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_HANDOFF_DIAG first_step={} cpu={} phase={} epoch={} source_owner={} expected_digest={:#x} proof={:?} offline={}\n",
            failure_step, failure_cpu, failure_phase, epoch, last,
            expected_digest, failure_evidence, all_offline
        ));
    }
    let bad = BAD.load(Ordering::Acquire) + ap_ipi_smoke::bad_count();
    let spurious = ap_ipi_smoke::spurious_count();
    if valid && all_offline && migrations == 11
        && paused == TOTAL_STEPS && sent == TOTAL_STEPS
        && irqs == TOTAL_STEPS && eois == TOTAL_STEPS
        && claimed == TOTAL_STEPS && executed == TOTAL_STEPS
        && idle == 3 && denied == migrations
        && TASK.is_retired(last, epoch) && epoch == 11
        && bad == MAX_BAD && spurious == 0
    {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_HANDOFF_OK cpus=4 aps=3 logical_tasks=1 epochs={} migrations={} quiesced={} sent={} received={} eois={} claimed={} executed={} retired=1 stale_denied={} idle={} offline=3 invalid={} spurious={} stack_migrated=0 bsp_if=0\n",
            TOTAL_STEPS, migrations, paused, sent, irqs, eois,
            claimed, executed, denied, idle, bad, spurious
        ));
        true
    } else {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_HANDOFF_ERROR epochs={} migrations={} quiesced={} sent={} received={} eois={} claimed={} executed={} stale_denied={} idle={} parked={} valid={} invalid={} spurious={}\n",
            TOTAL_STEPS, migrations, paused, sent, irqs, eois,
            claimed, executed, denied, idle, all_offline, valid, bad, spurious
        ));
        false
    }
}
