//! Original bounded SPSC raw-scancode queue for an isolated PS/2 IRQ proof.
//! Only the IRQ producer calls push; only BSP foreground calls pop. Neither
//! allocation, locks, parsing nor framebuffer access are permitted in IRQ.
//! Full queue poisons input: the consumer must fail closed, never silently
//! process a keyboard line whose make/break events were dropped.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

pub struct ScancodeQueue<const CAP: usize> {
    slots: [AtomicU8; CAP],
    head: AtomicUsize,
    tail: AtomicUsize,
    poisoned: AtomicBool,
    dropped: AtomicUsize,
}

impl<const CAP: usize> ScancodeQueue<CAP> {
    pub const fn new() -> Self {
        Self {
            slots: [const { AtomicU8::new(0) }; CAP],
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            poisoned: AtomicBool::new(false),
            dropped: AtomicUsize::new(0),
        }
    }

    /// IRQ producer; false permanently poisons this isolated input session.
    pub fn push(&self, scan: u8) -> bool {
        if self.poisoned.load(Ordering::Acquire) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        if CAP == 0 || tail.wrapping_sub(head) >= CAP {
            self.poisoned.store(true, Ordering::Release);
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.slots[tail % CAP].store(scan, Ordering::Relaxed);
        self.tail.store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    /// Foreground consumer; Err means loss was observed and input must stop.
    pub fn pop(&self) -> Result<Option<u8>, ()> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(());
        }
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        if head == tail {
            return if self.poisoned.load(Ordering::Acquire) { Err(()) } else { Ok(None) };
        }
        let scan = self.slots[head % CAP].load(Ordering::Relaxed);
        self.head.store(head.wrapping_add(1), Ordering::Release);
        if self.poisoned.load(Ordering::Acquire) {
            Err(())
        } else {
            Ok(Some(scan))
        }
    }

    pub fn dropped(&self) -> usize {
        self.dropped.load(Ordering::Acquire)
    }

    pub fn poisoned(&self) -> bool {
        self.poisoned.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn wrap_and_fifo_preserve_raw_make_break_bytes() {
        let q = ScancodeQueue::<3>::new();
        for b in [0x1e, 0x9e, 0x30] { assert!(q.push(b)); }
        assert_eq!(q.pop(), Ok(Some(0x1e)));
        assert!(q.push(0xb0));
        assert_eq!(q.pop(), Ok(Some(0x9e)));
        assert_eq!(q.pop(), Ok(Some(0x30)));
        assert_eq!(q.pop(), Ok(Some(0xb0)));
        assert_eq!(q.pop(), Ok(None));
        assert_eq!(q.dropped(), 0);
    }

    #[test]
    fn full_queue_poison_is_permanent_fail_closed() {
        let q = ScancodeQueue::<2>::new();
        assert!(q.push(1));
        assert!(q.push(2));
        assert!(!q.push(3));
        assert!(q.poisoned());
        assert_eq!(q.dropped(), 1);
        assert_eq!(q.pop(), Err(()));
        assert!(!q.push(4));
        assert_eq!(q.dropped(), 2);
    }

    #[test]
    fn lost_modifier_break_poison_blocks_all_later_input() {
        let queue = ScancodeQueue::<2>::new();
        // A lost Shift release would leave the decoder falsely shifted.
        assert!(queue.push(0x2a)); // Shift make
        assert!(queue.push(0x1e)); // A make
        assert!(!queue.push(0xaa)); // Shift release cannot fit
        assert!(queue.poisoned());
        assert_eq!(queue.pop(), Err(())); // do not replay incomplete input
        assert!(!queue.push(0x1c)); // Enter is not dispatched either
        assert_eq!(queue.dropped(), 2);
        assert_eq!(queue.pop(), Err(()));
    }

    #[test]
    fn zero_capacity_fails_without_modulo_by_zero() {
        let q = ScancodeQueue::<0>::new();
        assert_eq!(q.pop(), Ok(None));
        assert!(!q.push(0x1e));
        assert_eq!(q.pop(), Err(()));
    }

    #[test]
    fn concurrent_one_producer_one_consumer_preserves_order() {
        let q = Arc::new(ScancodeQueue::<128>::new());
        let producer = q.clone();
        let join = thread::spawn(move || {
            for n in 0..20_000usize {
                // Consumer can only advance head, so once there is space
                // it cannot disappear before this single producer pushes.
                while producer.tail.load(Ordering::Acquire)
                    .wrapping_sub(producer.head.load(Ordering::Acquire)) >= 128
                {
                    thread::yield_now();
                }
                assert!(producer.push(n as u8));
            }
        });
        for n in 0..20_000usize {
            loop {
                match q.pop() {
                    Ok(Some(b)) => {
                        assert_eq!(b, n as u8);
                        break;
                    }
                    Ok(None) => thread::yield_now(),
                    Err(()) => panic!("unexpected queue overflow"),
                }
            }
        }
        join.join().unwrap();
        assert_eq!(q.pop(), Ok(None));
        assert_eq!(q.dropped(), 0);
    }
}
