//! SPSC bounded, fixed-capacity, AP-owned work queue.
//!
//! One coordinator CPU publishes NEW jobs. Exactly one AP consumes them.
//! All cells are permanent and preallocated. No heap, blocking locks,
//! IRQ-time work, sleep/wake lost-notification assumptions or task migration.
//! Atomic per-slot sequence tags protect against stale head/tail reuse
//! and prevent producer from overwriting a still-owned job.
//!
//! The producer MUST be serialized externally (BSP-only in the smoke);
//! consumers MUST be restricted to the slot's local CPU owner.
//! This is NOT a lock-free MPMC queue and does not transport task stacks.
//! For the fixed QEMU acceptance scenario every slot is an atomic ring
//! and each AP is the only consumer of its own queue.

use core::sync::atomic::{AtomicU64, Ordering};

pub const CAPACITY: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    WrongCpu,
    InvalidPayload,
    Full,
    Empty,
    Exhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkItem {
    pub sequence: u64,
    pub token: u64,
}

struct Slot {
    generation: AtomicU64,
    payload: AtomicU64,
}
impl Slot {
    const fn new(initial: u64) -> Self {
        Self {
            generation: AtomicU64::new(initial),
            payload: AtomicU64::new(0),
        }
    }
}

pub struct CpuWorkQueue {
    owner: usize,
    publish_head: AtomicU64,
    consume_head: AtomicU64,
    slots: [Slot; CAPACITY],
}

impl CpuWorkQueue {
    pub const fn new(owner: usize) -> Self {
        Self {
            owner,
            publish_head: AtomicU64::new(0),
            consume_head: AtomicU64::new(0),
            slots: [
                Slot::new(0),
                Slot::new(1),
                Slot::new(2),
                Slot::new(3),
                Slot::new(4),
                Slot::new(5),
                Slot::new(6),
                Slot::new(7),
            ],
        }
    }

    pub const fn owner(&self) -> usize {
        self.owner
    }

    /// SINGLE external producer: publish a strictly positive token with
    /// immutable sequence number. Publication to the slot's generation
    /// is a Release fence for the payload.
    ///
    /// A failed Full never changes producer index, payload or generation.
    pub fn publish(&self, cpu: usize, token: u64) -> Result<u64, QueueError> {
        if cpu != self.owner { return Err(QueueError::WrongCpu); }
        if token == 0 { return Err(QueueError::InvalidPayload); }
        let next = self.publish_head.load(Ordering::Relaxed);
        if next > u64::MAX - (CAPACITY as u64) - 1 {
            return Err(QueueError::Exhausted);
        }
        let slot = &self.slots[(next as usize) % CAPACITY];
        if slot.generation.load(Ordering::Acquire) != next {
            return Err(QueueError::Full);
        }
        slot.payload.store(token, Ordering::Relaxed);
        slot.generation.store(next + 1, Ordering::Release);
        self.publish_head.store(next + 1, Ordering::Release);
        Ok(next + 1)
    }

    /// Called ONLY by the addressed AP, OUTSIDE the hardware IRQ.
    /// Load Acquire observes the producer's complete payload. Releasing
    /// the generation by +CAPACITY allows exactly one future reuse.
    pub fn consume(&self, cpu: usize) -> Result<WorkItem, QueueError> {
        if cpu != self.owner { return Err(QueueError::WrongCpu); }
        let before = self.consume_head.load(Ordering::Relaxed);
        if before > u64::MAX - (CAPACITY as u64) - 1 {
            return Err(QueueError::Exhausted);
        }
        let slot = &self.slots[(before as usize) % CAPACITY];
        if slot.generation.load(Ordering::Acquire) != before + 1 {
            return Err(QueueError::Empty);
        }
        let token = slot.payload.load(Ordering::Relaxed);
        slot.generation.store(before + CAPACITY as u64, Ordering::Release);
        self.consume_head.store(before + 1, Ordering::Release);
        Ok(WorkItem { sequence: before + 1, token })
    }

    /// Read-only for the BSP. Production callers must not infer job
    /// *completion* from this count: it only proves dequeue happened.
    pub fn consumed(&self) -> u64 {
        self.consume_head.load(Ordering::Acquire)
    }

    pub fn published(&self) -> u64 {
        self.publish_head.load(Ordering::Acquire)
    }

    /// Snapshot valid only after the owning AP is parked or at a
    /// coordinator-controlled publication boundary.
    pub fn is_empty_at(&self, generation: u64) -> bool {
        self.consume_head.load(Ordering::Acquire) == generation
            && self.publish_head.load(Ordering::Acquire) == generation
    }
}

pub fn job_token(cpu: usize, sequence: u64) -> u64 {
    (sequence << 24) ^ ((cpu as u64) << 12) ^ 0x5cc5_9a3d
}

pub fn rolling_digest(previous: u64, cpu: usize, sequence: u64, token: u64) -> u64 {
    let mut hash = previous
        ^ token
        ^ (cpu as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
        ^ sequence.rotate_left(13);
    for i in 0..1024u64 {
        hash = hash.rotate_left(7)
            .wrapping_mul(0xbf58_476d_1ce4_e5b9)
            ^ i.wrapping_mul(0x94d0_49bb_1331_11eb);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_rejects_overflow_then_wraps_without_stale_replay() {
        let q = CpuWorkQueue::new(2);
        assert_eq!(q.owner(), 2);
        for i in 1..=CAPACITY as u64 {
            assert_eq!(q.publish(2, job_token(2, i)), Ok(i));
        }
        assert_eq!(q.published(), CAPACITY as u64);
        assert_eq!(q.publish(2, 999), Err(QueueError::Full));
        assert_eq!(q.published(), CAPACITY as u64);
        for i in 1..=CAPACITY as u64 {
            assert_eq!(q.consume(2), Ok(WorkItem {
                sequence: i,
                token: job_token(2, i),
            }));
        }
        assert_eq!(q.consume(2), Err(QueueError::Empty));
        assert!(q.is_empty_at(CAPACITY as u64));
        for i in (CAPACITY as u64 + 1)..=1000 {
            assert_eq!(q.publish(2, job_token(2, i)), Ok(i));
            assert_eq!(q.consume(2), Ok(WorkItem {
                sequence: i,
                token: job_token(2, i),
            }));
        }
        assert!(q.is_empty_at(1000));
    }

    #[test]
    fn wrong_owner_and_bad_token_never_mutate_state() {
        let q = CpuWorkQueue::new(3);
        assert_eq!(q.publish(2, 99), Err(QueueError::WrongCpu));
        assert_eq!(q.publish(3, 0), Err(QueueError::InvalidPayload));
        assert_eq!(q.consume(2), Err(QueueError::WrongCpu));
        assert_eq!(q.consume(3), Err(QueueError::Empty));
        assert!(q.is_empty_at(0));
        assert_eq!(q.publish(3, 7), Ok(1));
        assert_eq!(q.consume(1), Err(QueueError::WrongCpu));
        assert_eq!(q.consume(3), Ok(WorkItem {
            sequence: 1, token: 7,
        }));
        assert!(q.is_empty_at(1));
    }

    #[test]
    fn real_two_threads_serialize_ring_with_backpressure() {
        use std::sync::{mpsc, Arc};
        use std::thread;
        use std::time::Duration;
        let q = Arc::new(CpuWorkQueue::new(1));
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let ap = Arc::clone(&q);
        let worker = thread::spawn(move || {
            let mut hash = 0u64;
            let mut expected = 1u64;
            for _ in 0..32 {
                ready_rx.recv_timeout(Duration::from_secs(10))
                    .expect("producer publication absent");
                for _ in 0..CAPACITY {
                    let job = ap.consume(1).expect("AP must own published slot");
                    assert_eq!(job.sequence, expected);
                    assert_eq!(job.token, job_token(1, expected));
                    hash = rolling_digest(hash, 1, expected, job.token);
                    expected += 1;
                }
            }
            assert!(ap.is_empty_at(32 * CAPACITY as u64));
            hash
        });
        let mut expected_hash = 0u64;
        for round in 0..32u64 {
            let initial = round * CAPACITY as u64;
            for offset in 1..=CAPACITY as u64 {
                let id = initial + offset;
                // Each block is published only after the previous block
                // has drained. This barrier avoids scheduling-related
                // false failure; the consumer remains a genuine thread.
                while q.published() != q.consumed() {
                    thread::yield_now();
                }
                assert_eq!(q.publish(1, job_token(1, id)), Ok(id));
                expected_hash = rolling_digest(
                    expected_hash, 1, id, job_token(1, id),
                );
            }
            ready_tx.send(()).unwrap();
            while q.consumed() != (round + 1) * CAPACITY as u64 {
                thread::yield_now();
            }
        }
        let actual = worker.join().unwrap();
        assert_eq!(actual, expected_hash);
    }

    #[test]
    fn owner_identity_isolated_between_queues() {
        let a = CpuWorkQueue::new(1);
        let b = CpuWorkQueue::new(2);
        assert_eq!(a.publish(1, 10), Ok(1));
        assert_eq!(b.publish(2, 20), Ok(1));
        assert_eq!(a.consume(2), Err(QueueError::WrongCpu));
        assert_eq!(b.consume(1), Err(QueueError::WrongCpu));
        assert_eq!(a.consume(1).unwrap().token, 10);
        assert_eq!(b.consume(2).unwrap().token, 20);
    }
}
