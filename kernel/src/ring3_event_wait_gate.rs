//! Fixed-capacity BSP event registration/notification gate for native Ring3.
//!
//! This module closes the *policy* lost-notification window between registering
//! an event and actually parking a running user task. A signal after ARM but
//! before COMMIT is latched, causing COMMIT to return without BLOCK. A signal
//! after COMMIT wakes only its exact generation/sequence-bound wait ticket.
//!
//! Every call here and the corresponding process-table state transition MUST
//! run within the SAME caller-provided, IRQ-masked/preemption-disabled BSP
//! critical section. This struct has no internal lock and is NOT SMP-safe.
//! The caller MUST independently authenticate interrupt/event provenance and
//! captured CPL3 GPR/IRET/FX/CR3/RSP0. This code performs NO hardware work,
//! IRQ EOI, CR3/TSS/FX/IRET switch, PMM release or physical disk I/O.
#[cfg(test)]
#[path = "ring3_runqueue.rs"]
mod standalone_queue;
#[cfg(test)]
use standalone_queue::{Error as QueueError, Handle, Ring3RunQueue, WaitTicket};
#[cfg(not(test))]
use crate::ring3_runqueue::{Error as QueueError, Handle, Ring3RunQueue, WaitTicket};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventToken {
    handle: Handle,
    event: u64,
    sequence: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidEvent, InvalidHandle, Duplicate, Full, Stale, WrongEvent,
    WrongState, AlreadyDelivered, Overflow, Queue(QueueError),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit {
    /// Signal was registered before park: user remains Running.
    DeliveredBeforePark,
    /// Real source may be IRET-switched to this optional new running task.
    Parked(Option<Handle>),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Delivery {
    Latched,
    Woken(Handle),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { Empty, Armed, Pending, Parked }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Record {
    phase: Phase,
    token: EventToken,
    queue_ticket: Option<WaitTicket>,
}
impl Record {
    const EMPTY: Self = Self {
        phase: Phase::Empty,
        token: EventToken {
            handle: Handle { pid: 0, generation: 0 },
            event: 0, sequence: 0,
        },
        queue_ticket: None,
    };
}

/// Every error leaves BOTH the registry and the supplied scheduler unchanged.
/// The user event *producer* must hold an authorized EventToken for this exact
/// registration and supply a separately authenticated delivered event ID.
/// A token is a correlation key, NOT proof that real hardware signalled it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventWaitGate<const N: usize> {
    records: [Record; N],
    next_sequence: u64,
}
impl<const N: usize> EventWaitGate<N> {
    pub const fn new() -> Self {
        Self { records: [Record::EMPTY; N], next_sequence: 0 }
    }

    /// Number of not-yet-consumed registrations; zero is required before
    /// the owner can retire all physical process/FX/stack resources.
    pub fn in_flight(&self) -> usize {
        self.records.iter().filter(|r| r.phase != Phase::Empty).count()
    }

    fn locate(&self, token: EventToken) -> Result<usize, Error> {
        self.records.iter().position(|r|
            r.phase != Phase::Empty && r.token == token
        ).ok_or(Error::Stale)
    }

    /// Register BEFORE the WAIT syscall makes the task Blocked. Registration
    /// and the later commit must be serialized against authenticated signals
    /// by the external BSP critical section. Sequence never wraps or reuses.
    pub fn arm(
        &mut self, queue: &Ring3RunQueue<N>, handle: Handle, event: u64,
    ) -> Result<EventToken, Error> {
        if event == 0 { return Err(Error::InvalidEvent) }
        if handle.pid == 0 || handle.generation == 0 ||
            queue.running() != Some(handle) {
            return Err(Error::InvalidHandle)
        }
        if self.records.iter().any(|r|
            r.phase != Phase::Empty && r.token.handle == handle
        ) { return Err(Error::Duplicate) }
        let i = self.records.iter().position(|r| r.phase == Phase::Empty)
            .ok_or(Error::Full)?;
        let sequence = self.next_sequence.checked_add(1).ok_or(Error::Overflow)?;
        let token = EventToken { handle, event, sequence };
        self.records[i] = Record {
            phase: Phase::Armed, token, queue_ticket: None,
        };
        self.next_sequence = sequence;
        Ok(token)
    }

    /// Atomically with the caller's scheduler/IRQ exclusion, either consume
    /// an earlier notification WITHOUT parking, or establish the one-use
    /// blocked ticket in Ring3RunQueue. A failed queue block never changes
    /// the registration. If Parked(None), the BSP needs a safe idle path.
    pub fn commit(
        &mut self, queue: &mut Ring3RunQueue<N>, token: EventToken,
    ) -> Result<Commit, Error> {
        let i = self.locate(token)?;
        match self.records[i].phase {
            Phase::Pending => {
                if queue.running() != Some(token.handle) {
                    return Err(Error::InvalidHandle)
                }
                self.records[i] = Record::EMPTY;
                Ok(Commit::DeliveredBeforePark)
            }
            Phase::Armed => {
                let (next, ticket) =
                    queue.block_current_for_event(token.handle, token.event)
                        .map_err(Error::Queue)?;
                self.records[i].phase = Phase::Parked;
                self.records[i].queue_ticket = Some(ticket);
                Ok(Commit::Parked(next))
            }
            _ => Err(Error::WrongState),
        }
    }

    /// Genuine authenticated signal arrives either before or after COMMIT.
    /// Its correlation token and delivered event must both match. A second
    /// signal and a stale registration never produce a second wake/IRQ tick.
    pub fn signal(
        &mut self, queue: &mut Ring3RunQueue<N>,
        token: EventToken, delivered_event: u64,
    ) -> Result<Delivery, Error> {
        if delivered_event == 0 { return Err(Error::InvalidEvent) }
        let i = self.locate(token)?;
        if token.event != delivered_event { return Err(Error::WrongEvent) }
        match self.records[i].phase {
            Phase::Armed => {
                self.records[i].phase = Phase::Pending;
                Ok(Delivery::Latched)
            }
            Phase::Pending => Err(Error::AlreadyDelivered),
            Phase::Parked => {
                let ticket = self.records[i].queue_ticket
                    .ok_or(Error::WrongState)?;
                queue.wake_for_event(ticket, delivered_event)
                    .map_err(Error::Queue)?;
                self.records[i] = Record::EMPTY;
                Ok(Delivery::Woken(token.handle))
            }
            Phase::Empty => Err(Error::Stale),
        }
    }

    /// Abort only a not-yet-parked registration. A parked user needs
    /// coordinated ProcessTable, saved-stack and PMM teardown instead.
    pub fn disarm_unparked(&mut self, token: EventToken) -> Result<(), Error> {
        let i = self.locate(token)?;
        if !matches!(self.records[i].phase, Phase::Armed | Phase::Pending) {
            return Err(Error::WrongState)
        }
        self.records[i] = Record::EMPTY;
        Ok(())
    }

    /// Cancel a parked queue task without resurrecting an old notification.
    /// Caller remains responsible for separately coordinated ProcessTable
    /// cancellation and quiesced physical resource retirement.
    pub fn retire_parked(
        &mut self, queue: &mut Ring3RunQueue<N>, token: EventToken,
    ) -> Result<(), Error> {
        let i = self.locate(token)?;
        if self.records[i].phase != Phase::Parked {
            return Err(Error::WrongState)
        }
        queue.cancel(token.handle).map_err(Error::Queue)?;
        self.records[i] = Record::EMPTY;
        Ok(())
    }
}


/// Opaque receipt for exactly one independently authenticated BSP device IRQ.
/// Its private identity prevents replaying an earlier callback's EOI marker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqEventReceipt { sequence: u64, vector: u8 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqEventError {
    WrongVector, InvalidEvent, Busy, Stale, WrongPhase, Overflow,
    NotDrained, Event(Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqEventTotals {
    pub entered: u64,
    pub acknowledged: u64,
    pub delivered: u64,
    pub discarded: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IrqPhase { Entered, EoiAcknowledged }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InFlightIrq {
    receipt: IrqEventReceipt,
    token: EventToken,
    delivered_event: u64,
    phase: IrqPhase,
}

/// One BSP interrupt callback can be in flight at a time. The trusted
/// interrupt handler must independently validate its vector, CPU/APIC source,
/// interrupt frame and supervisor CR3, physically send the exact EOI, and
/// serialize the mailbox + EventWaitGate + Ring3RunQueue under one protected
/// critical section. Merely calling acknowledge_physical_eoi here does NOT
/// perform an MMIO EOI or prove that hardware delivered an interrupt.
///
/// An IRQ must be EOI-acknowledged before its notification can be forwarded to
/// EventWaitGate. Replayed, mismatched and nested IRQ receipts fail closed.
/// This is BSP policy/evidence plumbing ONLY, not general IF=1 device wake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BspIrqEventBridge {
    active: Option<InFlightIrq>,
    next_sequence: u64,
    entered: u64,
    acknowledged: u64,
    delivered: u64,
    discarded: u64,
}
impl BspIrqEventBridge {
    pub const fn new() -> Self {
        Self {
            active: None, next_sequence: 0, entered: 0,
            acknowledged: 0, delivered: 0, discarded: 0,
        }
    }

    /// The caller guarantees that the observed vector and pending token were
    /// independently authenticated; this rejects mismatches but cannot
    /// authenticate physical APIC ISR or its MMIO mapping by itself.
    pub fn capture<const N: usize>(
        &mut self, gate: &EventWaitGate<N>, token: EventToken,
        observed_vector: u8, expected_vector: u8, delivered_event: u64,
    ) -> Result<IrqEventReceipt, IrqEventError> {
        if observed_vector < 32 || observed_vector != expected_vector {
            return Err(IrqEventError::WrongVector)
        }
        if delivered_event == 0 { return Err(IrqEventError::InvalidEvent) }
        if self.active.is_some() { return Err(IrqEventError::Busy) }
        // Do not admit another IRQ when idle counters are already corrupt.
        self.verify_drained()?;
        gate.locate(token).map_err(IrqEventError::Event)?;
        let sequence = self.next_sequence.checked_add(1)
            .ok_or(IrqEventError::Overflow)?;
        let entered = self.entered.checked_add(1)
            .ok_or(IrqEventError::Overflow)?;
        let receipt = IrqEventReceipt { sequence, vector: observed_vector };
        self.active = Some(InFlightIrq {
            receipt, token, delivered_event, phase: IrqPhase::Entered,
        });
        self.next_sequence = sequence;
        self.entered = entered;
        Ok(receipt)
    }

    /// Must be called ONLY AFTER the trusted handler writes real xAPIC EOI.
    /// This is evidence bookkeeping, never hardware access.
    pub fn acknowledge_physical_eoi(
        &mut self, receipt: IrqEventReceipt,
    ) -> Result<(), IrqEventError> {
        let pending = self.active.ok_or(IrqEventError::Stale)?;
        if pending.receipt != receipt { return Err(IrqEventError::Stale) }
        if pending.phase != IrqPhase::Entered {
            return Err(IrqEventError::WrongPhase)
        }
        let acknowledged = self.acknowledged.checked_add(1)
            .ok_or(IrqEventError::Overflow)?;
        if acknowledged != self.entered { return Err(IrqEventError::WrongPhase) }
        self.acknowledged = acknowledged;
        self.active.as_mut().unwrap().phase = IrqPhase::EoiAcknowledged;
        Ok(())
    }

    /// Deliver only an acknowledged IRQ. An invalid event/ticket leaves the
    /// IRQ envelope and both scheduler structures unchanged; its owner may
    /// explicitly discard the acknowledged envelope before processing more.
    pub fn deliver_after_eoi<const N: usize>(
        &mut self, gate: &mut EventWaitGate<N>,
        queue: &mut Ring3RunQueue<N>, receipt: IrqEventReceipt,
    ) -> Result<Delivery, IrqEventError> {
        let pending = self.active.ok_or(IrqEventError::Stale)?;
        if pending.receipt != receipt { return Err(IrqEventError::Stale) }
        if pending.phase != IrqPhase::EoiAcknowledged {
            return Err(IrqEventError::WrongPhase)
        }
        let delivered = self.delivered.checked_add(1)
            .ok_or(IrqEventError::Overflow)?;
        let outcome = gate.signal(queue, pending.token, pending.delivered_event)
            .map_err(IrqEventError::Event)?;
        self.active = None;
        self.delivered = delivered;
        Ok(outcome)
    }

    /// An already acknowledged IRQ can be explicitly discarded if its wait
    /// was canceled or its event was rejected. The caller retains responsibility
    /// for safely handling the originating physical device interrupt.
    pub fn discard_after_eoi(
        &mut self, receipt: IrqEventReceipt,
    ) -> Result<(), IrqEventError> {
        let pending = self.active.ok_or(IrqEventError::Stale)?;
        if pending.receipt != receipt { return Err(IrqEventError::Stale) }
        if pending.phase != IrqPhase::EoiAcknowledged {
            return Err(IrqEventError::WrongPhase)
        }
        let discarded = self.discarded.checked_add(1)
            .ok_or(IrqEventError::Overflow)?;
        self.discarded = discarded;
        self.active = None;
        Ok(())
    }

    /// Source/EOI/finalization accounting. This cannot prove the trusted
    /// caller actually wrote EOI; QEMU hardware must separately test that.
    pub fn verify_drained(&self) -> Result<IrqEventTotals, IrqEventError> {
        if self.active.is_some() || self.entered != self.acknowledged {
            return Err(IrqEventError::NotDrained)
        }
        if self.delivered.checked_add(self.discarded)
            .ok_or(IrqEventError::Overflow)? != self.entered {
            return Err(IrqEventError::NotDrained)
        }
        Ok(IrqEventTotals {
            entered: self.entered, acknowledged: self.acknowledged,
            delivered: self.delivered, discarded: self.discarded,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use standalone_queue::State;

    #[test]
    fn idle_irq_bridge_corruption_rejects_capture_without_mutation() {
        let mut q = Ring3RunQueue::<1>::new();
        let h = q.admit(1).unwrap();
        q.start_next().unwrap();
        let mut gate = EventWaitGate::<1>::new();
        let token = gate.arm(&q, h, 7).unwrap();
        let mut bridge = BspIrqEventBridge::new();
        bridge.entered = 1;
        let before = bridge;
        assert_eq!(bridge.capture(&gate, token, 48, 48, 7), Err(IrqEventError::NotDrained));
        assert_eq!(bridge, before);
        bridge.acknowledged = 1;
        bridge.delivered = 1;
        assert!(bridge.capture(&gate, token, 48, 48, 7).is_ok());
    }

    #[test]
    fn idle_irq_bridge_counter_overflow_rejects_capture_without_mutation() {
        let mut q = Ring3RunQueue::<1>::new();
        let h = q.admit(1).unwrap();
        q.start_next().unwrap();
        let mut gate = EventWaitGate::<1>::new();
        let token = gate.arm(&q, h, 7).unwrap();
        let mut bridge = BspIrqEventBridge::new();
        bridge.entered = u64::MAX;
        bridge.acknowledged = u64::MAX;
        bridge.delivered = u64::MAX;
        let before = bridge;
        assert_eq!(bridge.capture(&gate, token, 48, 48, 7), Err(IrqEventError::Overflow));
        assert_eq!(bridge, before);
    }

    #[test]
    fn signal_between_registration_and_park_is_latched_without_lost_wake() {
        let mut q = Ring3RunQueue::<2>::new();
        let a = q.admit(1).unwrap();
        let b = q.admit(2).unwrap();
        assert_eq!(q.start_next(), Ok(a));
        let mut gate = EventWaitGate::<2>::new();
        let first = gate.arm(&q, a, 77).unwrap();
        assert_eq!(gate.signal(&mut q, first, 77), Ok(Delivery::Latched));
        let frozen = (gate, q);
        assert_eq!(gate.signal(&mut q, first, 77), Err(Error::AlreadyDelivered));
        assert_eq!((gate, q), frozen);
        assert_eq!(gate.commit(&mut q, first), Ok(Commit::DeliveredBeforePark));
        assert_eq!(q.running(), Some(a));
        assert_eq!(q.timer_switches(), 0);
        assert_eq!(gate.signal(&mut q, first, 77), Err(Error::Stale));

        let second = gate.arm(&q, a, 77).unwrap();
        assert_ne!(second, first);
        assert_eq!(gate.commit(&mut q, second), Ok(Commit::Parked(Some(b))));
        assert_eq!(q.slots()[0].state, State::Blocked);
        let blocked = (gate, q);
        assert_eq!(gate.signal(&mut q, first, 77), Err(Error::Stale));
        assert_eq!((gate, q), blocked);
        assert_eq!(gate.signal(&mut q, second, 77), Ok(Delivery::Woken(a)));
        assert_eq!(gate.signal(&mut q, second, 77), Err(Error::Stale));
        assert_eq!(q.timer_tick(b), Ok(a));
        assert_eq!(q.timer_switches(), 1);
    }

    #[test]
    fn wrong_event_and_cross_generation_signals_never_mutate_wait() {
        let mut q = Ring3RunQueue::<2>::new();
        let a = q.admit(11).unwrap();
        let b = q.admit(22).unwrap();
        q.start_next().unwrap();
        let mut gate = EventWaitGate::<2>::new();
        let token = gate.arm(&q, a, 99).unwrap();
        assert_eq!(gate.commit(&mut q, token), Ok(Commit::Parked(Some(b))));
        let frozen = (gate, q);
        assert_eq!(gate.signal(&mut q, token, 100), Err(Error::WrongEvent));
        let counterfeit = EventToken { sequence: token.sequence+1, ..token };
        assert_eq!(gate.signal(&mut q, counterfeit, 99), Err(Error::Stale));
        assert_eq!((gate, q), frozen);
        assert_eq!(gate.signal(&mut q, token, 99), Ok(Delivery::Woken(a)));
        assert_eq!(q.slots()[0].state, State::Ready);
        assert_eq!(gate.signal(&mut q, token, 99), Err(Error::Stale));
        assert_eq!(q.timer_switches(), 0);
    }

    #[test]
    fn all_blocked_then_event_wakeup_preserves_idle_semantics() {
        let mut q = Ring3RunQueue::<1>::new();
        let a = q.admit(7).unwrap();
        assert_eq!(q.start_next(), Ok(a));
        let mut gate = EventWaitGate::<1>::new();
        let token = gate.arm(&q, a, 5).unwrap();
        assert_eq!(gate.commit(&mut q, token), Ok(Commit::Parked(None)));
        assert_eq!(q.running(), None);
        assert_eq!(q.start_next(), Err(QueueError::NoRunnable));
        assert_eq!(gate.signal(&mut q, token, 5), Ok(Delivery::Woken(a)));
        assert_eq!(q.start_next(), Ok(a));
        assert_eq!(q.timer_switches(), 0);
    }

    #[test]
    fn cancel_and_slot_reuse_invalidate_old_wait_sequence() {
        let mut q = Ring3RunQueue::<2>::new();
        let a = q.admit(41).unwrap();
        let b = q.admit(42).unwrap();
        q.start_next().unwrap();
        let mut gate = EventWaitGate::<2>::new();
        let token = gate.arm(&q, a, 6).unwrap();
        assert_eq!(gate.commit(&mut q, token), Ok(Commit::Parked(Some(b))));
        assert_eq!(gate.disarm_unparked(token), Err(Error::WrongState));
        assert_eq!(gate.retire_parked(&mut q, token), Ok(()));
        assert_eq!(q.slots()[0].state, State::Exited);
        assert_eq!(q.reap(a), Ok(()));
        let replacement = q.admit(41).unwrap();
        assert_ne!(a, replacement);
        assert_eq!(gate.signal(&mut q, token, 6), Err(Error::Stale));
        let previous = (gate, q);
        assert_eq!(gate.arm(&q, a, 6), Err(Error::InvalidHandle));
        assert_eq!((gate, q), previous);
        assert_eq!(q.timer_switches(), 0);
    }

    #[test]
    fn failed_registration_and_overflow_leave_everything_unchanged() {
        let mut q = Ring3RunQueue::<1>::new();
        let a = q.admit(55).unwrap();
        q.start_next().unwrap();
        let mut gate = EventWaitGate::<1>::new();
        let state = (gate, q);
        assert_eq!(gate.arm(&q, a, 0), Err(Error::InvalidEvent));
        assert_eq!(gate.arm(&q, Handle { pid: 44, generation: 1 }, 7),
            Err(Error::InvalidHandle));
        assert_eq!((gate, q), state);

        let token = gate.arm(&q, a, 7).unwrap();
        assert_eq!(gate.arm(&q, a, 8), Err(Error::Duplicate));
        let state = (gate, q);
        assert_eq!(gate.signal(&mut q, token, 0), Err(Error::InvalidEvent));
        assert_eq!((gate, q), state);
        assert_eq!(gate.disarm_unparked(token), Ok(()));
        gate.next_sequence = u64::MAX;
        let state = (gate, q);
        assert_eq!(gate.arm(&q, a, 7), Err(Error::Overflow));
        assert_eq!((gate, q), state);
        assert_eq!(q.running(), Some(a));
    }

    #[test]
    fn authenticated_irq_before_park_is_latched_only_after_eoi() {
        let mut q = Ring3RunQueue::<2>::new();
        let a = q.admit(1).unwrap();
        q.admit(2).unwrap();
        assert_eq!(q.start_next(), Ok(a));
        let mut gate = EventWaitGate::<2>::new();
        let mut irq = BspIrqEventBridge::new();
        let t = gate.arm(&q, a, 77).unwrap();
        let proof = irq.capture(&gate, t, 0x51, 0x51, 77).unwrap();
        assert_eq!(irq.verify_drained(), Err(IrqEventError::NotDrained));
        let unchanged = (irq, gate, q);
        assert_eq!(irq.deliver_after_eoi(&mut gate, &mut q, proof),
            Err(IrqEventError::WrongPhase));
        assert_eq!((irq, gate, q), unchanged);
        irq.acknowledge_physical_eoi(proof).unwrap();
        assert_eq!(irq.deliver_after_eoi(&mut gate, &mut q, proof),
            Ok(Delivery::Latched));
        assert_eq!(gate.commit(&mut q, t), Ok(Commit::DeliveredBeforePark));
        assert_eq!(q.running(), Some(a));
        assert_eq!(q.timer_switches(), 0);
        assert_eq!(irq.verify_drained(), Ok(IrqEventTotals {
            entered: 1, acknowledged: 1, delivered: 1, discarded: 0,
        }));
        assert_eq!(irq.deliver_after_eoi(&mut gate, &mut q, proof),
            Err(IrqEventError::Stale));
    }

    #[test]
    fn after_park_irq_delivery_wakes_exact_ticket_without_forged_timer() {
        let mut q = Ring3RunQueue::<2>::new();
        let a = q.admit(11).unwrap();
        let b = q.admit(22).unwrap();
        q.start_next().unwrap();
        let mut gate = EventWaitGate::<2>::new();
        let mut irq = BspIrqEventBridge::new();
        let t = gate.arm(&q, a, 13).unwrap();
        assert_eq!(gate.commit(&mut q, t), Ok(Commit::Parked(Some(b))));
        let proof = irq.capture(&gate, t, 0x52, 0x52, 13).unwrap();
        irq.acknowledge_physical_eoi(proof).unwrap();
        assert_eq!(irq.deliver_after_eoi(&mut gate, &mut q, proof),
            Ok(Delivery::Woken(a)));
        assert_eq!(q.timer_switches(), 0);
        assert_eq!(q.timer_tick(b), Ok(a));
        assert_eq!(q.timer_switches(), 1);
        assert_eq!(irq.verify_drained().unwrap().delivered, 1);
    }

    #[test]
    fn wrong_event_nesting_and_replayed_ack_preserve_all_owners() {
        let mut q = Ring3RunQueue::<2>::new();
        let a = q.admit(1).unwrap();
        let b = q.admit(2).unwrap();
        q.start_next().unwrap();
        let mut gate = EventWaitGate::<2>::new();
        let mut irq = BspIrqEventBridge::new();
        let t = gate.arm(&q, a, 91).unwrap();
        assert_eq!(gate.commit(&mut q, t), Ok(Commit::Parked(Some(b))));
        let before = (irq, gate, q);
        assert_eq!(irq.capture(&gate, t, 0x50, 0x51, 91),
            Err(IrqEventError::WrongVector));
        assert_eq!(irq.capture(&gate, t, 0x51, 0x51, 0),
            Err(IrqEventError::InvalidEvent));
        assert_eq!((irq, gate, q), before);
        let bad = irq.capture(&gate, t, 0x51, 0x51, 92).unwrap();
        let entered = (irq, gate, q);
        assert_eq!(irq.capture(&gate, t, 0x51, 0x51, 91),
            Err(IrqEventError::Busy));
        assert_eq!(irq.discard_after_eoi(bad), Err(IrqEventError::WrongPhase));
        assert_eq!((irq, gate, q), entered);
        let fake = IrqEventReceipt { sequence: bad.sequence + 1, ..bad };
        assert_eq!(irq.acknowledge_physical_eoi(fake),
            Err(IrqEventError::Stale));
        irq.acknowledge_physical_eoi(bad).unwrap();
        let acknowledged = (irq, gate, q);
        assert_eq!(irq.acknowledge_physical_eoi(bad),
            Err(IrqEventError::WrongPhase));
        assert_eq!(irq.deliver_after_eoi(&mut gate, &mut q, bad),
            Err(IrqEventError::Event(Error::WrongEvent)));
        assert_eq!((irq, gate, q), acknowledged);
        irq.discard_after_eoi(bad).unwrap();
        assert_eq!(irq.discard_after_eoi(bad), Err(IrqEventError::Stale));
        assert_eq!(q.slots()[0].state, State::Blocked);
        let good = irq.capture(&gate, t, 0x51, 0x51, 91).unwrap();
        assert_ne!(bad, good);
        irq.acknowledge_physical_eoi(good).unwrap();
        assert_eq!(irq.deliver_after_eoi(&mut gate, &mut q, good),
            Ok(Delivery::Woken(a)));
        assert_eq!(q.timer_switches(), 0);
        assert_eq!(irq.verify_drained(), Ok(IrqEventTotals {
            entered: 2, acknowledged: 2, delivered: 1, discarded: 1,
        }));
    }

    #[test]
    fn canceled_wait_and_overflow_never_resurrect_or_fake_eoi() {
        let mut q = Ring3RunQueue::<1>::new();
        let a = q.admit(1).unwrap();
        q.start_next().unwrap();
        let mut gate = EventWaitGate::<1>::new();
        let mut irq = BspIrqEventBridge::new();
        let t = gate.arm(&q, a, 3).unwrap();
        assert_eq!(gate.commit(&mut q, t), Ok(Commit::Parked(None)));
        let proof = irq.capture(&gate, t, 0x60, 0x60, 3).unwrap();
        gate.retire_parked(&mut q, t).unwrap();
        irq.acknowledge_physical_eoi(proof).unwrap();
        let before = (irq, gate, q);
        assert_eq!(irq.deliver_after_eoi(&mut gate, &mut q, proof),
            Err(IrqEventError::Event(Error::Stale)));
        assert_eq!((irq, gate, q), before);
        irq.discard_after_eoi(proof).unwrap();
        assert_eq!(irq.verify_drained().unwrap().discarded, 1);
        q.reap(a).unwrap();
        let replacement = q.admit(1).unwrap();
        assert_ne!(replacement, a);
        assert_eq!(irq.capture(&gate, t, 0x60, 0x60, 3),
            Err(IrqEventError::Event(Error::Stale)));

        let mut q = Ring3RunQueue::<1>::new();
        let a = q.admit(9).unwrap();
        q.start_next().unwrap();
        let mut gate = EventWaitGate::<1>::new();
        let t = gate.arm(&q, a, 8).unwrap();
        let mut irq = BspIrqEventBridge::new();
        irq.next_sequence = u64::MAX;
        let frozen = (irq, gate, q);
        assert_eq!(irq.capture(&gate, t, 0x50, 0x50, 8),
            Err(IrqEventError::Overflow));
        assert_eq!((irq, gate, q), frozen);
    }

    #[test]
    fn registry_capacity_is_bounded_and_no_lease_changes_on_refusal() {
        let mut q = Ring3RunQueue::<2>::new();
        let a = q.admit(1).unwrap();
        let b = q.admit(2).unwrap();
        q.start_next().unwrap();
        let mut gate = EventWaitGate::<1>::new();
        let a_token = gate.arm(&Ring3RunQueue::<1>::new(), a, 7);
        assert_eq!(a_token, Err(Error::InvalidHandle));

        // The registry is allowed to be smaller than the runqueue, but
        // this particular gate shares the same N by design. Fill N=2
        // with one armed and one parked task, then fail closed on duplicate.
        let mut gate = EventWaitGate::<2>::new();
        let t = gate.arm(&q, a, 77).unwrap();
        assert_eq!(gate.commit(&mut q, t), Ok(Commit::Parked(Some(b))));
        let u = gate.arm(&q, b, 88).unwrap();
        assert_eq!(gate.arm(&q, b, 89), Err(Error::Duplicate));
        assert_eq!(gate.commit(&mut q, u), Ok(Commit::Parked(None)));
        assert_eq!(q.running(), None);
        assert_eq!(gate.signal(&mut q, t, 77), Ok(Delivery::Woken(a)));
        assert_eq!(gate.signal(&mut q, u, 88), Ok(Delivery::Woken(b)));
        assert_eq!(q.start_next(), Ok(a));
        assert_eq!(q.timer_switches(), 0);
    }
}
