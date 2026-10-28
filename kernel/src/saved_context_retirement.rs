//! Bounded, epoch-tagged saved user-context admission and revocation metadata.
//!
//! This does not own an actual interrupt frame, task queue, CR3, stack, TLB
//! translation or physical frame. A scheduler must register EVERY saved
//! resumable context and serialize admission, CPU reservation and retirement
//! using the same external lock. Losing this ledger is not reclamation proof.
//! Revocation is unsafe until real saved frame/queue users have been canceled.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase { Live, Closing, Closed }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidCapacity,
    InvalidGeneration,
    InvalidSlot,
    Busy,
    WrongPhase,
    StaleTicket,
    EpochExhausted,
    OutstandingContexts,
}

/// Opaque saved-context incarnation. An old token cannot authorize a reused
/// slot, even if that slot still describes the same address-space generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextTicket {
    generation: u64,
    slot: usize,
    epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub phase: Phase,
    pub pending: u64,
    pub epoch: u64,
}

pub struct SavedContextGate<const SLOTS: usize> {
    generation: u64,
    phase: Phase,
    epoch: u64,
    live: [u64; SLOTS],
}

impl<const SLOTS: usize> SavedContextGate<SLOTS> {
    pub fn new(generation: u64) -> Result<Self, Error> {
        if SLOTS == 0 || SLOTS > 64 { return Err(Error::InvalidCapacity); }
        if generation == 0 { return Err(Error::InvalidGeneration); }
        Ok(Self { generation, phase: Phase::Live, epoch: 0, live: [0; SLOTS] })
    }

    pub fn snapshot(&self) -> Snapshot {
        let mut pending = 0u64;
        for (slot, epoch) in self.live.iter().enumerate() {
            if *epoch != 0 { pending |= 1u64 << slot; }
        }
        Snapshot { phase: self.phase, pending, epoch: self.epoch }
    }

    /// Register an actual saved resumable frame/queue entry before exposing
    /// it to dispatch. A caller must not publish an unregistered resume path.
    pub fn admit(&mut self, slot: usize) -> Result<ContextTicket, Error> {
        if self.phase != Phase::Live { return Err(Error::WrongPhase); }
        if slot >= SLOTS { return Err(Error::InvalidSlot); }
        if self.live[slot] != 0 { return Err(Error::Busy); }
        let next = self.epoch.checked_add(1).ok_or(Error::EpochExhausted)?;
        self.epoch = next;
        self.live[slot] = next;
        Ok(ContextTicket { generation: self.generation, slot, epoch: next })
    }

    /// Admission check only. Dispatch must also obtain a fresh CPU reservation
    /// before any private CR3 load, under the SAME external coordinator lock.
    pub fn validate_resume(&self, ticket: ContextTicket) -> Result<(), Error> {
        if self.phase != Phase::Live { return Err(Error::WrongPhase); }
        self.check_ticket(ticket)
    }

    fn check_ticket(&self, ticket: ContextTicket) -> Result<(), Error> {
        if ticket.generation != self.generation || ticket.slot >= SLOTS
            || ticket.epoch == 0 || self.live[ticket.slot] != ticket.epoch
        {
            return Err(Error::StaleTicket);
        }
        Ok(())
    }

    /// Close saved-context admission permanently, including all queued
    /// tickets not yet resumed. Pending tokens remain pinned for revocation.
    pub fn close_admission(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Live { return Err(Error::WrongPhase); }
        self.phase = Phase::Closing;
        Ok(())
    }

    /// # Safety
    /// Caller must have canceled the corresponding actual saved frame, queue
    /// entry, event/timer wakeups and any in-flight CPU handoff. This metadata
    /// change does not perform those operations or prove hardware quiescence.
    pub unsafe fn revoke(&mut self, ticket: ContextTicket) -> Result<(), Error> {
        if self.phase == Phase::Closed { return Err(Error::WrongPhase); }
        self.check_ticket(ticket)?;
        self.live[ticket.slot] = 0;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Closing { return Err(Error::WrongPhase); }
        if self.live.iter().any(|epoch| *epoch != 0) {
            return Err(Error::OutstandingContexts);
        }
        self.phase = Phase::Closed;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_generation_and_bounded_capacity() {
        assert!(matches!(SavedContextGate::<0>::new(1), Err(Error::InvalidCapacity)));
        assert!(matches!(SavedContextGate::<65>::new(1), Err(Error::InvalidCapacity)));
        assert!(matches!(SavedContextGate::<1>::new(0), Err(Error::InvalidGeneration)));
        let mut gate = SavedContextGate::<1>::new(1).unwrap();
        assert_eq!(gate.admit(1), Err(Error::InvalidSlot));
        assert_eq!(gate.snapshot().pending, 0);
    }

    #[test]
    fn stale_ticket_cannot_reactivate_a_reused_saved_slot() {
        let mut gate = SavedContextGate::<2>::new(7).unwrap();
        let old = gate.admit(0).unwrap();
        assert_eq!(gate.admit(0), Err(Error::Busy));
        assert_eq!(gate.validate_resume(old), Ok(()));
        unsafe { gate.revoke(old) }.unwrap();
        let current = gate.admit(0).unwrap();
        assert_eq!(gate.validate_resume(old), Err(Error::StaleTicket));
        assert_eq!(unsafe { gate.revoke(old) }, Err(Error::StaleTicket));
        assert_eq!(gate.snapshot().pending, 1);
        assert_eq!(gate.validate_resume(current), Ok(()));
    }

    #[test]
    fn closing_blocks_dispatch_but_retains_pending_ownership() {
        let mut gate = SavedContextGate::<4>::new(9).unwrap();
        let a = gate.admit(0).unwrap();
        let b = gate.admit(3).unwrap();
        gate.close_admission().unwrap();
        assert_eq!(gate.validate_resume(a), Err(Error::WrongPhase));
        assert_eq!(gate.admit(1), Err(Error::WrongPhase));
        assert_eq!(gate.finish(), Err(Error::OutstandingContexts));
        assert_eq!(gate.snapshot().pending, 0b1001);
        unsafe { gate.revoke(a) }.unwrap();
        assert_eq!(gate.finish(), Err(Error::OutstandingContexts));
        unsafe { gate.revoke(b) }.unwrap();
        gate.finish().unwrap();
        assert_eq!(gate.snapshot().phase, Phase::Closed);
        assert_eq!(gate.admit(0), Err(Error::WrongPhase));
        assert_eq!(unsafe { gate.revoke(b) }, Err(Error::WrongPhase));
    }

    #[test]
    fn last_slot_and_epoch_overflow_fail_closed() {
        let mut gate = SavedContextGate::<64>::new(9).unwrap();
        let last = gate.admit(63).unwrap();
        assert_eq!(gate.snapshot().pending, 1u64 << 63);
        unsafe { gate.revoke(last) }.unwrap();
        gate.epoch = u64::MAX;
        let before = gate.snapshot();
        assert_eq!(gate.admit(63), Err(Error::EpochExhausted));
        assert_eq!(gate.snapshot(), before);
        gate.close_admission().unwrap();
        gate.finish().unwrap();
    }

    #[test]
    fn cross_generation_token_is_never_accepted() {
        let mut old = SavedContextGate::<2>::new(1).unwrap();
        let mut fresh = SavedContextGate::<2>::new(2).unwrap();
        let ticket = old.admit(1).unwrap();
        let current = fresh.admit(1).unwrap();
        assert_eq!(fresh.validate_resume(ticket), Err(Error::StaleTicket));
        assert_eq!(unsafe { fresh.revoke(ticket) }, Err(Error::StaleTicket));
        assert_eq!(fresh.validate_resume(current), Ok(()));
    }
}
