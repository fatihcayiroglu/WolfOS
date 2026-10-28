//! Quiesced logical-task ownership handoff between fixed CPU owners.
//!
//! A transferable task's *logical progress* (step + accumulator) lives in
//! atomics; the running worker executes on its destination CPU's OWN stack.
//! No suspended RSP, trap frame, CR3, TLS or FX/XSAVE state migrates here.
//! An owner must publish an immutable Paused snapshot before a coordinator
//! can transfer the lease to a new CPU. New owner may resume only after an
//! Acquire transition from InTransit. Every handoff increases its epoch.
//!
//! This is a checked migration *protocol preflight*, NOT migration of a live
//! kernel context or a production multi-core scheduler. The coordinator
//! and AP owners must respect exclusive-role entrypoints described below.

use core::sync::atomic::{AtomicU64, Ordering};

const PHASE_MASK: u64 = 7;
const OWNER_MASK: u64 = 255;
const OWNER_SHIFT: u64 = 3;
const EPOCH_SHIFT: u64 = 11;
pub const MAX_EPOCH: u64 = u64::MAX >> EPOCH_SHIFT;

const PAUSED: u64 = 1;
const IN_TRANSIT: u64 = 2;
const RUNNING: u64 = 3;
const RETIRED: u64 = 4;
const UNINITIALIZED: u64 = u64::MAX;
pub const INITIAL_DIGEST: u64 = 0x4f53_574f_4c46_2026;

fn pack(epoch: u64, owner: usize, phase: u64) -> u64 {
    (epoch << EPOCH_SHIFT) | ((owner as u64) << OWNER_SHIFT) | phase
}
fn epoch(word: u64) -> u64 { word >> EPOCH_SHIFT }
fn owner(word: u64) -> usize { ((word >> OWNER_SHIFT) & OWNER_MASK) as usize }
fn phase(word: u64) -> u64 { word & PHASE_MASK }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffError {
    InvalidOwner,
    InvalidEpoch,
    Busy,
    WrongOwner,
    WrongPhase,
    EpochExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    pub epoch: u64,
    pub owner: usize,
    pub steps: u64,
    pub digest: u64,
}

pub struct TaskLease {
    state: AtomicU64,
    steps: AtomicU64,
    digest: AtomicU64,
}

impl TaskLease {
    pub const fn new() -> Self {
        Self {
            state: AtomicU64::new(UNINITIALIZED),
            steps: AtomicU64::new(0),
            digest: AtomicU64::new(INITIAL_DIGEST),
        }
    }

    /// Coordinator: choose the first CPU owner only once, before any work
    /// or IPI has been dispatched. CPU IDs here are Limine MP indices.
    pub fn initialize(&self, cpu: usize) -> Result<(), HandoffError> {
        if cpu == 0 || cpu > OWNER_MASK as usize {
            return Err(HandoffError::InvalidOwner);
        }
        self.state.compare_exchange(
            UNINITIALIZED, pack(0, cpu, PAUSED),
            Ordering::AcqRel, Ordering::Acquire,
        ).map(|_| ()).map_err(|_| HandoffError::Busy)
    }

    /// Coordinator: inspect only a quiesced snapshot. No worker can write
    /// steps/digest once the Paused Release transition is visible.
    pub fn snapshot(&self) -> Result<Snapshot, HandoffError> {
        let state = self.state.load(Ordering::Acquire);
        if phase(state) != PAUSED { return Err(HandoffError::WrongPhase); }
        let snap = Snapshot {
            epoch: epoch(state),
            owner: owner(state),
            steps: self.steps.load(Ordering::Relaxed),
            digest: self.digest.load(Ordering::Relaxed),
        };
        // A concurrent coordinator transfer must not allow a stale
        // snapshot to be treated as belonging to a new generation.
        if self.state.load(Ordering::Acquire) != state {
            return Err(HandoffError::Busy);
        }
        Ok(snap)
    }

    /// Coordinator: transfer a *paused* logical task from its old owner
    /// to a distinct new owner. Both cores must be actual secondary CPUs.
    /// Old CPU no longer has any authority as soon as this CAS succeeds.
    pub fn transfer(&self, from: usize, to: usize, expected_epoch: u64)
        -> Result<u64, HandoffError>
    {
        if from == 0 || to == 0 || from > OWNER_MASK as usize
            || to > OWNER_MASK as usize || from == to
        {
            return Err(HandoffError::InvalidOwner);
        }
        if expected_epoch >= MAX_EPOCH {
            return Err(HandoffError::EpochExhausted);
        }
        let expected = pack(expected_epoch, from, PAUSED);
        let state = self.state.load(Ordering::Acquire);
        if state != expected {
            return Err(if owner(state) != from {
                HandoffError::WrongOwner
            } else if epoch(state) != expected_epoch {
                HandoffError::InvalidEpoch
            } else {
                HandoffError::WrongPhase
            });
        }
        self.state.compare_exchange(
            expected, pack(expected_epoch + 1, to, IN_TRANSIT),
            Ordering::AcqRel, Ordering::Acquire,
        ).map(|_| expected_epoch + 1).map_err(|_| HandoffError::Busy)
    }

    /// On actual CPU after directed IPI claim, OUTSIDE the IRQ handler.
    /// Initial epoch 0 is Paused; later epochs require a real transfer.
    pub fn resume(&self, cpu: usize, expected_epoch: u64)
        -> Result<(), HandoffError>
    {
        if cpu == 0 || cpu > OWNER_MASK as usize {
            return Err(HandoffError::InvalidOwner);
        }
        let state = self.state.load(Ordering::Acquire);
        if owner(state) != cpu { return Err(HandoffError::WrongOwner); }
        if epoch(state) != expected_epoch { return Err(HandoffError::InvalidEpoch); }
        let desired_phase = if expected_epoch == 0 { PAUSED } else { IN_TRANSIT };
        if phase(state) != desired_phase { return Err(HandoffError::WrongPhase); }
        self.state.compare_exchange(
            state, pack(expected_epoch, cpu, RUNNING),
            Ordering::AcqRel, Ordering::Acquire,
        ).map(|_| ()).map_err(|_| HandoffError::Busy)
    }

    /// AP owner: progress a fixed one-quantum logical continuation on the
    /// CURRENT CPU stack. Commit digest and step BEFORE publishing Paused.
    /// Exactly one owner can enter RUNNING for any epoch.
    pub fn execute_quantum(&self, cpu: usize, expected_epoch: u64)
        -> Result<Snapshot, HandoffError>
    {
        let state = self.state.load(Ordering::Acquire);
        if owner(state) != cpu { return Err(HandoffError::WrongOwner); }
        if epoch(state) != expected_epoch { return Err(HandoffError::InvalidEpoch); }
        if phase(state) != RUNNING { return Err(HandoffError::WrongPhase); }
        let before = self.digest.load(Ordering::Relaxed);
        let steps = self.steps.load(Ordering::Relaxed);
        let new_digest = advance_digest(before, steps + 1);
        self.digest.store(new_digest, Ordering::Relaxed);
        self.steps.store(steps + 1, Ordering::Relaxed);
        self.state.compare_exchange(
            state, pack(expected_epoch, cpu, PAUSED),
            Ordering::Release, Ordering::Acquire,
        ).map_err(|_| HandoffError::Busy)?;
        Ok(Snapshot {
            epoch: expected_epoch, owner: cpu,
            steps: steps + 1, digest: new_digest,
        })
    }

    /// Coordinator: only a paused final generation can be retired.
    pub fn retire(&self, cpu: usize, expected_epoch: u64)
        -> Result<(), HandoffError>
    {
        self.state.compare_exchange(
            pack(expected_epoch, cpu, PAUSED),
            pack(expected_epoch, cpu, RETIRED),
            Ordering::AcqRel, Ordering::Acquire,
        ).map(|_| ()).map_err(|_| HandoffError::WrongPhase)
    }

    pub fn is_retired(&self, cpu: usize, expected_epoch: u64) -> bool {
        self.state.load(Ordering::Acquire)
            == pack(expected_epoch, cpu, RETIRED)
    }
}

/// Deterministic, non-trivial increment independent of physical CPU.
/// BSP can verify progress without executing the AP's task on its behalf.
pub fn advance_digest(previous: u64, new_step: u64) -> u64 {
    let mut digest = previous ^ new_step.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for i in 0..2048u64 {
        digest = digest.rotate_left(11)
            ^ i.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        digest = digest.wrapping_mul(0x94d0_49bb_1331_11eb);
    }
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_moves_one_logical_continuation_across_three_ap_owners() {
        let lease = TaskLease::new();
        assert_eq!(lease.initialize(1), Ok(()));
        assert_eq!(lease.initialize(1), Err(HandoffError::Busy));
        let mut previous = INITIAL_DIGEST;
        let mut current = 1usize;
        let mut epoch = 0;
        for step in 1..=12u64 {
            if step == 1 {
                assert_eq!(lease.snapshot().unwrap().steps, 0);
            } else {
                // An owner-transfer has already moved the lease into
                // InTransit: a not-yet-resumed task is NOT quiesced and
                // must refuse a stale Paused snapshot.
                assert_eq!(lease.snapshot(), Err(HandoffError::WrongPhase));
            }
            assert_eq!(lease.resume(current, epoch), Ok(()));
            assert_eq!(lease.snapshot(), Err(HandoffError::WrongPhase));
            let snap = lease.execute_quantum(current, epoch).unwrap();
            previous = advance_digest(previous, step);
            assert_eq!(snap.digest, previous);
            assert_eq!(snap.steps, step);
            assert_eq!(lease.snapshot(), Ok(snap));
            if step < 12 {
                let next = (current % 3) + 1;
                assert_eq!(lease.transfer(current, next, epoch), Ok(epoch + 1));
                assert_eq!(lease.resume(current, epoch), Err(HandoffError::WrongOwner));
                assert_eq!(lease.execute_quantum(current, epoch),
                    Err(HandoffError::WrongOwner));
                current = next;
                epoch += 1;
            }
        }
        assert_eq!(lease.retire(current, epoch), Ok(()));
        assert!(lease.is_retired(current, epoch));
        assert_eq!(lease.resume(current, epoch), Err(HandoffError::WrongPhase));
        assert_eq!(lease.snapshot(), Err(HandoffError::WrongPhase));
    }

    #[test]
    fn rejects_cross_cpu_double_run_and_unquiesced_transfer() {
        let lease = TaskLease::new();
        assert_eq!(lease.initialize(0), Err(HandoffError::InvalidOwner));
        assert_eq!(lease.initialize(1), Ok(()));
        assert_eq!(lease.resume(2, 0), Err(HandoffError::WrongOwner));
        assert_eq!(lease.resume(1, 3), Err(HandoffError::InvalidEpoch));
        assert_eq!(lease.transfer(1, 1, 0), Err(HandoffError::InvalidOwner));
        assert_eq!(lease.resume(1, 0), Ok(()));
        assert_eq!(lease.resume(1, 0), Err(HandoffError::WrongPhase));
        assert_eq!(lease.transfer(1, 2, 0), Err(HandoffError::WrongPhase));
        assert_eq!(lease.execute_quantum(2, 0), Err(HandoffError::WrongOwner));
        assert!(lease.execute_quantum(1, 0).is_ok());
        assert_eq!(lease.execute_quantum(1, 0), Err(HandoffError::WrongPhase));
        assert_eq!(lease.transfer(1, 2, 0), Ok(1));
        assert_eq!(lease.transfer(1, 3, 0), Err(HandoffError::WrongOwner));
        assert_eq!(lease.resume(3, 1), Err(HandoffError::WrongOwner));
        assert_eq!(lease.resume(2, 0), Err(HandoffError::InvalidEpoch));
        assert_eq!(lease.resume(2, 1), Ok(()));
    }

    #[test]
    fn invalid_owner_and_stale_epochs_cannot_acquire_or_resurrect() {
        let lease = TaskLease::new();
        assert_eq!(lease.initialize(usize::MAX), Err(HandoffError::InvalidOwner));
        assert_eq!(lease.resume(0, 0), Err(HandoffError::InvalidOwner));
        assert_eq!(lease.initialize(3), Ok(()));
        assert_eq!(lease.retire(3, 0), Ok(()));
        assert!(lease.is_retired(3, 0));
        assert_eq!(lease.transfer(3, 2, 0), Err(HandoffError::WrongPhase));
        assert_eq!(lease.resume(3, 0), Err(HandoffError::WrongPhase));
        assert_eq!(lease.retire(3, 0), Err(HandoffError::WrongPhase));
    }

    #[test]
    fn real_threads_handoff_has_single_running_owner() {
        // Real OS threads are intentionally used: the coordinator sends
        // an exact owner+epoch command, the selected worker performs a
        // single running->paused quantum, and the coordinator verifies the
        // Acquire-visible snapshot BEFORE transferring the owner.
        //
        // Previous implementation polled all epochs on all workers for a
        // fixed number of busy-loop iterations; CI scheduler starvation
        // caused occasional false "AP did not quiesce" despite correct
        // lease code. Channels remove timing-dependent readiness races
        // without weakening any ownership, digest or count assertions.
        use std::sync::{mpsc, Arc};
        use std::thread;
        use std::time::Duration;
        let lease = Arc::new(TaskLease::new());
        assert_eq!(lease.initialize(1), Ok(()));

        let (completed_tx, completed_rx) = mpsc::channel();
        let mut senders = Vec::new();
        let mut workers = Vec::new();
        for cpu in 1..=3usize {
            let shared = Arc::clone(&lease);
            let (sender, receiver) = mpsc::channel::<u64>();
            let done = completed_tx.clone();
            senders.push(sender);
            workers.push(thread::spawn(move || {
                let mut count = 0u64;
                while let Ok(epoch) = receiver.recv() {
                    assert_eq!(shared.resume(cpu, epoch), Ok(()));
                    assert_eq!(shared.resume(cpu, epoch), Err(HandoffError::WrongPhase));
                    let snapshot = shared.execute_quantum(cpu, epoch).unwrap();
                    assert_eq!(snapshot.owner, cpu);
                    assert_eq!(snapshot.epoch, epoch);
                    done.send((cpu, epoch, snapshot)).unwrap();
                    count += 1;
                }
                count
            }));
        }
        drop(completed_tx);
        let mut previous = INITIAL_DIGEST;
        let mut owner = 1usize;
        let mut epoch = 0;
        for step in 1..=12u64 {
            senders[owner - 1].send(epoch).unwrap();
            let (actual_owner, actual_epoch, completed) =
                completed_rx.recv_timeout(Duration::from_secs(15))
                    .expect("AP worker did not publish completion");
            assert_eq!(actual_owner, owner);
            assert_eq!(actual_epoch, epoch);
            assert_eq!(completed.steps, step);
            previous = advance_digest(previous, step);
            assert_eq!(completed.digest, previous);
            let paused = lease.snapshot().unwrap();
            assert_eq!(paused, completed);
            if step != 12 {
                let next = (owner % 3) + 1;
                epoch = lease.transfer(owner, next, epoch).unwrap();
                assert_eq!(lease.resume(owner, epoch - 1), Err(HandoffError::WrongOwner));
                owner = next;
            }
        }
        lease.retire(owner, epoch).unwrap();
        assert!(lease.is_retired(owner, epoch));
        assert_eq!(lease.snapshot(), Err(HandoffError::WrongPhase));
        drop(senders);
        let total: u64 = workers.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total, 12);
    }
}
