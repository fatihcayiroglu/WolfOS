//! Fixed-capacity SPSC per-CPU work queue, independent of the IRQ path.
//!
//! BSP is the *only* producer; the destination AP is the *only* consumer.
//! An AP's fixed xAPIC IPI only wakes that AP (and is locally EOI-acked):
//! NO queue mutation, allocation or computation occurs inside IRQ context.
//! A queue contains NEW work, not suspended RSPs or transferable threads.
//!
//! Publish sequence: write token/sequence slots (Relaxed), then tail Release.
//! Consumer observes tail Acquire before reading slots. The AP copies both
//! fields before head Release permits BSP to reuse a ring position.
//! Producer observes head Acquire before overwriting reused positions.
//! Capacity/fullness, overflow, FIFO and wrong owner fail closed.
//! Exactly one producer and one consumer are required by construction.

use core::sync::atomic::{AtomicU64, Ordering};

pub const CAPACITY: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    WrongCpu,
    Full,
    BadSequence,
    BadToken,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueuedJob {
    pub sequence: u64,
    pub token: u64,
}

pub struct CpuWorkQueue {
    owner: usize,
    head: AtomicU64,
    tail: AtomicU64,
    sequences: [AtomicU64; CAPACITY],
    tokens: [AtomicU64; CAPACITY],
}

impl CpuWorkQueue {
    pub const fn new(owner: usize) -> Self {
        Self {
            owner,
            head: AtomicU64::new(0),
            tail: AtomicU64::new(0),
            sequences: [const { AtomicU64::new(0) }; CAPACITY],
            tokens: [const { AtomicU64::new(0) }; CAPACITY],
        }
    }

    /// BSP-only, never called from an interrupt. A full queue rejects work
    /// without changing tail, data, or the next expected sequence.
    pub fn enqueue(&self, destination: usize, sequence: u64, token: u64)
        -> Result<(), QueueError>
    {
        if destination != self.owner { return Err(QueueError::WrongCpu); }
        if token == 0 { return Err(QueueError::BadToken); }
        let tail = self.tail.load(Ordering::Relaxed);
        if tail == u64::MAX { return Err(QueueError::Exhausted); }
        let head = self.head.load(Ordering::Acquire);
        if tail < head || tail - head > CAPACITY as u64 {
            return Err(QueueError::Exhausted);
        }
        if sequence != tail + 1 { return Err(QueueError::BadSequence); }
        if tail - head == CAPACITY as u64 { return Err(QueueError::Full); }
        let slot = tail as usize % CAPACITY;
        self.tokens[slot].store(token, Ordering::Relaxed);
        self.sequences[slot].store(sequence, Ordering::Relaxed);
        self.tail.store(tail + 1, Ordering::Release);
        Ok(())
    }

    /// AP-only, AFTER IRETQ from the wake IPI, on the AP's permanent stack.
    /// A wrong CPU cannot remove another AP's queued work.
    pub fn dequeue(&self, receiver: usize)
        -> Result<Option<QueuedJob>, QueueError>
    {
        if receiver != self.owner { return Err(QueueError::WrongCpu); }
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if tail < head || tail - head > CAPACITY as u64 {
            return Err(QueueError::Exhausted);
        }
        if tail == head { return Ok(None); }
        if head == u64::MAX { return Err(QueueError::Exhausted); }
        let slot = head as usize % CAPACITY;
        let result = QueuedJob {
            sequence: self.sequences[slot].load(Ordering::Relaxed),
            token: self.tokens[slot].load(Ordering::Relaxed),
        };
        if result.sequence != head + 1 || result.token == 0 {
            return Err(QueueError::BadSequence);
        }
        self.head.store(head + 1, Ordering::Release);
        Ok(Some(result))
    }

    pub fn len(&self) -> usize {
        let tail = self.tail.load(Ordering::Acquire);
        let head = self.head.load(Ordering::Acquire);
        if tail < head { return 0; }
        (tail - head).min(CAPACITY as u64) as usize
    }

    pub fn is_drained(&self, count: u64) -> bool {
        self.head.load(Ordering::Acquire) == count
            && self.tail.load(Ordering::Acquire) == count
    }
}

/// Same deterministic AP-owned work function as the previous 1-slot
/// mailbox. BSP independently verifies every digest.
pub fn digest(cpu: usize, sequence: u64, token: u64) -> u64 {
    let mut value = token
        ^ (cpu as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ sequence.rotate_left(23);
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
    fn fifo_full_backpressure_and_ring_wrap() {
        let queue = CpuWorkQueue::new(2);
        for wave in 0..5u64 {
            for i in 1..=CAPACITY as u64 {
                let seq = wave * CAPACITY as u64 + i;
                assert_eq!(queue.enqueue(2, seq, seq | 0x100), Ok(()));
            }
            assert_eq!(queue.len(), CAPACITY);
            let seq = (wave + 1) * CAPACITY as u64 + 1;
            assert_eq!(queue.enqueue(2, seq, seq | 0x100), Err(QueueError::Full));
            assert_eq!(queue.len(), CAPACITY);
            for i in 1..=CAPACITY as u64 {
                let seq = wave * CAPACITY as u64 + i;
                assert_eq!(queue.dequeue(2), Ok(Some(QueuedJob {
                    sequence: seq, token: seq | 0x100,
                })));
            }
            assert_eq!(queue.dequeue(2), Ok(None));
            assert!(queue.is_drained((wave + 1) * CAPACITY as u64));
        }
    }

    #[test]
    fn wrong_cpu_stale_generation_and_zero_payload_are_rejected() {
        let queue = CpuWorkQueue::new(3);
        assert_eq!(queue.dequeue(2), Err(QueueError::WrongCpu));
        assert_eq!(queue.enqueue(2, 1, 1), Err(QueueError::WrongCpu));
        assert_eq!(queue.enqueue(3, 1, 0), Err(QueueError::BadToken));
        assert_eq!(queue.enqueue(3, 2, 88), Err(QueueError::BadSequence));
        assert_eq!(queue.enqueue(3, 1, 88), Ok(()));
        assert_eq!(queue.enqueue(3, 1, 77), Err(QueueError::BadSequence));
        assert_eq!(queue.dequeue(3), Ok(Some(QueuedJob { sequence: 1, token: 88 })));
        assert_eq!(queue.dequeue(3), Ok(None));
        assert_eq!(queue.enqueue(3, 1, 90), Err(QueueError::BadSequence));
        assert!(queue.is_drained(1));
    }

    #[test]
    fn real_threaded_owner_runs_two_full_waves_with_synchronous_handoff() {
        use std::sync::{mpsc, Arc};
        use std::thread;
        use std::time::Duration;

        let q = Arc::new(CpuWorkQueue::new(1));
        let consumer = Arc::clone(&q);
        let (wake_tx, wake_rx) = mpsc::channel::<u64>();
        let (result_tx, result_rx) = mpsc::channel::<Vec<u64>>();
        let handle = thread::spawn(move || {
            for wave in 0..2u64 {
                assert_eq!(wake_rx.recv_timeout(Duration::from_secs(15)).unwrap(), wave + 1);
                let mut digest_results = Vec::new();
                for i in 1..=CAPACITY as u64 {
                    let seq = wave * CAPACITY as u64 + i;
                    let job = consumer.dequeue(1).unwrap().unwrap();
                    assert_eq!(job.sequence, seq);
                    digest_results.push(digest(1, seq, job.token));
                }
                assert_eq!(consumer.dequeue(1), Ok(None));
                result_tx.send(digest_results).unwrap();
            }
        });
        for wave in 0..2u64 {
            for i in 1..=CAPACITY as u64 {
                let seq = wave * CAPACITY as u64 + i;
                q.enqueue(1, seq, seq + 0x500).unwrap();
            }
            assert_eq!(q.enqueue(1, (wave+1)*CAPACITY as u64+1, 0x77),
                Err(QueueError::Full));
            wake_tx.send(wave + 1).unwrap();
            let results = result_rx.recv_timeout(Duration::from_secs(15)).unwrap();
            for (slot, received) in results.into_iter().enumerate() {
                let seq = wave * CAPACITY as u64 + slot as u64 + 1;
                assert_eq!(received, digest(1, seq, seq + 0x500));
            }
            assert!(q.is_drained((wave+1)*CAPACITY as u64));
        }
        handle.join().unwrap();
    }
}
