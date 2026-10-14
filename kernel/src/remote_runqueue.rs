//! Single-producer, single-owner remote execution mailbox.
//!
//! This is a small, fixed-capacity foundation for sending NEW CPU-bound work
//! to another CPU, not migrating a suspended task or exposing a production
//! scheduler API. One coordinator publishes; exactly one destination CPU
//! may claim and complete. IRQ merely CLAIMS the job: execution happens
//! outside the interrupt handler on that AP's existing kernel stack.
//!
//! The state word carries a monotonically increasing generation so stale,
//! duplicate, cross-core and overlapping operations fail closed. A 2-phase
//! publish (Idle -> Writing -> Pending) prevents the IRQ from observing
//! partially initialized payload. Release/Acquire ownership handoff binds
//! the payload, completion result and retirement to the state transition.

use core::sync::atomic::{AtomicU64, Ordering};

const PHASE_BITS: u32 = 3;
const PHASE_MASK: u64 = (1 << PHASE_BITS) - 1;
const IDLE: u64 = 0;
const WRITING: u64 = 1;
const PENDING: u64 = 2;
const CLAIMED: u64 = 3;
const COMPLETED: u64 = 4;
pub const MAX_SEQUENCE: u64 = u64::MAX >> PHASE_BITS;

const fn encode(sequence: u64, phase: u64) -> u64 {
    (sequence << PHASE_BITS) | phase
}
const fn sequence(word: u64) -> u64 { word >> PHASE_BITS }
const fn phase(word: u64) -> u64 { word & PHASE_MASK }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxError {
    WrongCpu,
    InvalidGeneration,
    InvalidPayload,
    Busy,
    NotPending,
    NotClaimed,
    NotCompleted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Job {
    pub sequence: u64,
    pub token: u64,
}

/// One mailbox belongs to precisely ONE logical CPU index, even when the
/// hardware xAPIC IDs are noncontiguous. No AP ever touches another slot.
pub struct RemoteMailbox {
    owner: usize,
    state: AtomicU64,
    payload: AtomicU64,
    result: AtomicU64,
}

impl RemoteMailbox {
    pub const fn new(owner: usize) -> Self {
        Self {
            owner,
            state: AtomicU64::new(encode(0, IDLE)),
            payload: AtomicU64::new(0),
            result: AtomicU64::new(0),
        }
    }

    /// BSP ONLY, single producer. Publish exact next generation to the
    /// addressed CPU. Does not send the IPI; caller must send it only
    /// *after* this returns Ok, using a real directed hardware interrupt.
    pub fn publish(&self, destination: usize, next: u64, token: u64)
        -> Result<(), MailboxError>
    {
        if destination != self.owner { return Err(MailboxError::WrongCpu); }
        if token == 0 { return Err(MailboxError::InvalidPayload); }
        let before = self.state.load(Ordering::Acquire);
        if phase(before) != IDLE { return Err(MailboxError::Busy); }
        if next == 0 || next > MAX_SEQUENCE
            || next != sequence(before).saturating_add(1)
        {
            return Err(MailboxError::InvalidGeneration);
        }
        self.state.compare_exchange(
            before, encode(next, WRITING), Ordering::AcqRel, Ordering::Acquire
        ).map_err(|_| MailboxError::Busy)?;
        self.payload.store(token, Ordering::Relaxed);
        self.result.store(0, Ordering::Relaxed);
        self.state.store(encode(next, PENDING), Ordering::Release);
        Ok(())
    }

    /// IRQ ONLY, on the receiving local AP. No work is executed inside IRQ.
    /// A duplicate IRQ or a wrong CPU MUST NOT consume another job.
    pub fn claim_from_irq(&self, receiver: usize) -> Result<u64, MailboxError> {
        if receiver != self.owner { return Err(MailboxError::WrongCpu); }
        let state = self.state.load(Ordering::Acquire);
        if phase(state) != PENDING { return Err(MailboxError::NotPending); }
        let generation = sequence(state);
        self.state.compare_exchange(
            state, encode(generation, CLAIMED),
            Ordering::AcqRel, Ordering::Acquire
        ).map_err(|_| MailboxError::NotPending)?;
        Ok(generation)
    }

    /// AP worker ONLY, outside IRQ. A Claimed state is only visible after
    /// the interrupt's Acquire read of the published payload.
    pub fn claimed_work(&self, receiver: usize) -> Result<Option<Job>, MailboxError> {
        if receiver != self.owner { return Err(MailboxError::WrongCpu); }
        let state = self.state.load(Ordering::Acquire);
        if phase(state) == CLAIMED {
            Ok(Some(Job {
                sequence: sequence(state),
                token: self.payload.load(Ordering::Relaxed),
            }))
        } else {
            Ok(None)
        }
    }

    /// AP worker ONLY. Exactly one completion per generation, with the
    /// computed digest published BEFORE the COMPLETED Release transition.
    pub fn finish(&self, receiver: usize, generation: u64, digest: u64)
        -> Result<(), MailboxError>
    {
        if receiver != self.owner { return Err(MailboxError::WrongCpu); }
        let expected = encode(generation, CLAIMED);
        if self.state.load(Ordering::Acquire) != expected {
            return Err(MailboxError::NotClaimed);
        }
        self.result.store(digest, Ordering::Relaxed);
        self.state.compare_exchange(
            expected, encode(generation, COMPLETED),
            Ordering::Release, Ordering::Acquire
        ).map_err(|_| MailboxError::NotClaimed)?;
        Ok(())
    }

    /// BSP ONLY. Acquire synchronization proves the remote worker finished.
    pub fn completed(&self, destination: usize, generation: u64)
        -> Result<Option<u64>, MailboxError>
    {
        if destination != self.owner { return Err(MailboxError::WrongCpu); }
        let state = self.state.load(Ordering::Acquire);
        if state == encode(generation, COMPLETED) {
            Ok(Some(self.result.load(Ordering::Relaxed)))
        } else {
            Ok(None)
        }
    }

    /// BSP ONLY. A fully verified completion must be explicitly retired
    /// before the same slot may publish next-generation work.
    pub fn retire(&self, destination: usize, generation: u64)
        -> Result<(), MailboxError>
    {
        if destination != self.owner { return Err(MailboxError::WrongCpu); }
        self.state.compare_exchange(
            encode(generation, COMPLETED), encode(generation, IDLE),
            Ordering::AcqRel, Ordering::Acquire
        ).map(|_| ()).map_err(|_| MailboxError::NotCompleted)
    }

    pub fn is_idle_generation(&self, generation: u64) -> bool {
        self.state.load(Ordering::Acquire) == encode(generation, IDLE)
    }
}

/// A deterministic, nontrivial *new* job that can be independently
/// verified by BSP without running any AP code or reading AP stacks.
pub fn compute_digest(cpu: usize, generation: u64, token: u64) -> u64 {
    let mut value = token
        ^ (cpu as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ generation.rotate_left(23);
    for step in 0..2048u64 {
        value ^= step.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = value.rotate_left(9).wrapping_mul(0x94d0_49bb_1331_11eb);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_lifecycle_and_generations() {
        let q = RemoteMailbox::new(3);
        assert!(q.is_idle_generation(0));
        for generation in 1..=20 {
            let token = (generation << 32) | 0x55aa;
            assert_eq!(q.publish(3, generation, token), Ok(()));
            assert_eq!(q.claimed_work(3), Ok(None));
            assert_eq!(q.claim_from_irq(3), Ok(generation));
            assert_eq!(q.claimed_work(3), Ok(Some(Job { sequence: generation, token })));
            let digest = compute_digest(3, generation, token);
            assert_eq!(q.finish(3, generation, digest), Ok(()));
            assert_eq!(q.completed(3, generation), Ok(Some(digest)));
            assert_eq!(q.retire(3, generation), Ok(()));
            assert!(q.is_idle_generation(generation));
        }
    }

    #[test]
    fn wrong_cpu_cannot_publish_claim_execute_finish_or_retire() {
        let q = RemoteMailbox::new(2);
        assert_eq!(q.publish(1, 1, 42), Err(MailboxError::WrongCpu));
        assert_eq!(q.publish(2, 1, 42), Ok(()));
        assert_eq!(q.claim_from_irq(3), Err(MailboxError::WrongCpu));
        assert_eq!(q.claimed_work(3), Err(MailboxError::WrongCpu));
        assert_eq!(q.claim_from_irq(2), Ok(1));
        assert_eq!(q.finish(1, 1, 17), Err(MailboxError::WrongCpu));
        assert_eq!(q.completed(1, 1), Err(MailboxError::WrongCpu));
        assert_eq!(q.finish(2, 1, 17), Ok(()));
        assert_eq!(q.retire(1, 1), Err(MailboxError::WrongCpu));
        assert_eq!(q.retire(2, 1), Ok(()));
    }

    #[test]
    fn duplicate_irq_busy_and_stale_completion_are_refused() {
        let q = RemoteMailbox::new(1);
        assert_eq!(q.publish(1, 1, 1), Ok(()));
        assert_eq!(q.publish(1, 2, 2), Err(MailboxError::Busy));
        assert_eq!(q.claim_from_irq(1), Ok(1));
        assert_eq!(q.claim_from_irq(1), Err(MailboxError::NotPending));
        assert_eq!(q.finish(1, 2, 3), Err(MailboxError::NotClaimed));
        assert_eq!(q.finish(1, 1, 5), Ok(()));
        assert_eq!(q.finish(1, 1, 7), Err(MailboxError::NotClaimed));
        assert_eq!(q.completed(1, 2), Ok(None));
        assert_eq!(q.retire(1, 2), Err(MailboxError::NotCompleted));
        assert_eq!(q.retire(1, 1), Ok(()));
        assert_eq!(q.claim_from_irq(1), Err(MailboxError::NotPending));
        assert_eq!(q.publish(1, 1, 99), Err(MailboxError::InvalidGeneration));
        assert_eq!(q.publish(1, 3, 99), Err(MailboxError::InvalidGeneration));
        assert_eq!(q.publish(1, 2, 99), Ok(()));
    }

    #[test]
    fn empty_payload_invalid_generation_and_no_premature_completion() {
        let q = RemoteMailbox::new(0);
        assert_eq!(q.publish(0, 0, 1), Err(MailboxError::InvalidGeneration));
        assert_eq!(q.publish(0, 1, 0), Err(MailboxError::InvalidPayload));
        assert_eq!(q.publish(0, 1, 1), Ok(()));
        assert_eq!(q.completed(0, 1), Ok(None));
        assert_eq!(q.retire(0, 1), Err(MailboxError::NotCompleted));
        assert_eq!(q.finish(0, 1, 12), Err(MailboxError::NotClaimed));
    }

    #[test]
    fn real_threads_handoff_without_exposing_partial_payload() {
        use std::sync::Arc;
        use std::thread;
        let slot = Arc::new(RemoteMailbox::new(1));
        let ap = Arc::clone(&slot);
        let handle = thread::spawn(move || {
            for generation in 1..=40u64 {
                let mut claimed = false;
                for _ in 0..3_000_000 {
                    if ap.claim_from_irq(1) == Ok(generation) {
                        claimed = true;
                        break;
                    }
                    thread::yield_now();
                }
                assert!(claimed, "no published job for generation {generation}");
                let job = ap.claimed_work(1).unwrap().unwrap();
                assert_eq!(job.sequence, generation);
                assert_eq!(job.token, (generation << 32) | 1);
                let digest = compute_digest(1, job.sequence, job.token);
                ap.finish(1, generation, digest).unwrap();
            }
        });
        for generation in 1..=40u64 {
            slot.publish(1, generation, (generation << 32) | 1).unwrap();
            let mut result = None;
            for _ in 0..3_000_000 {
                result = slot.completed(1, generation).unwrap();
                if result.is_some() { break; }
                thread::yield_now();
            }
            assert_eq!(result, Some(compute_digest(
                1, generation, (generation << 32) | 1,
            )));
            slot.retire(1, generation).unwrap();
        }
        handle.join().unwrap();
    }
}
