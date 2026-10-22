//! Fixed-capacity, allocation-free, **policy-only** BSP Ring3 ready queue.
//! No MMIO, IRET, CR3 changes, EOI, memory ownership or hardware scheduling.
//! The caller must authenticate saved frames and process generation before
//! any corresponding real trap/IRQ handoff. Issue #106 (host milestone).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle { pub pid: u64, pub generation: u64 }

/// Opaque proof of one specific event-bound wait, including a nonreusable
/// monotonically increasing sequence. Neither a PID nor an event ID alone
/// can authenticate a later wake. Caller still authenticates event origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitTicket { handle: Handle, event: u64, sequence: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State { Empty, Ready, Running, Blocked, Exited }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { InvalidPid, DuplicatePid, InvalidQuantum, InvalidEvent, WrongEvent, Full, Stale, WrongState, NoRunnable, Overflow }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub handle: Handle,
    pub state: State,
    pub ticks: u64,
}
impl Slot {
    const EMPTY: Self = Self {
        handle: Handle { pid: 0, generation: 0 },
        state: State::Empty,
        ticks: 0,
    };
}

/// Single-BSP scheduler ledger, **not** a concurrency-safe runtime.
/// Distinct handles are never reused until generation exhaustion (fail closed).
/// Every erroneous operation leaves *all* queue fields unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ring3RunQueue<const N: usize> {
    slots: [Slot; N],
    active: Option<usize>,
    switches: u64,
    generation: u64,
    // Consecutive authenticated, eligible timer IRQs in the current slice.
    // Policy-only: caller must establish genuine xAPIC IRQ provenance.
    slice_ticks: u64,
    // Last successful timer/yield rotation, only while the queue snapshot
    // has not changed since that decision (NOT hardware IRQ provenance).
    last_handoff: Option<(Handle, Handle)>,
    // Last BLOCK transition to a peer, invalidated by every subsequent
    // successful policy operation. This is NOT trusted trap provenance.
    last_block_handoff: Option<(Handle, Handle)>,
    // Optional trusted wait-event ID per slot; zero is legacy untagged BLOCK.
    // Bound waits may only be released via matching wake_for_event.
    wait_events: [u64; N],
    wait_sequences: [u64; N],
    next_wait_sequence: u64,
}

impl<const N: usize> Ring3RunQueue<N> {
    pub const fn new() -> Self {
        Self { slots: [Slot::EMPTY; N], active: None, switches: 0, generation: 0, slice_ticks: 0, last_handoff: None, last_block_handoff: None, wait_events: [0; N], wait_sequences: [0; N], next_wait_sequence: 0 }
    }

    pub fn slots(&self) -> [Slot; N] { self.slots }
    pub fn running(&self) -> Option<Handle> {
        self.active.map(|i| self.slots[i].handle)
    }
    /// Count only genuine policy-requested timer-origin cross-PID switches,
    /// never a syscall, EXIT, BLOCK or wakeup dispatch.
    pub fn timer_switches(&self) -> u64 { self.switches }
    pub fn current_slice_ticks(&self) -> u64 { self.slice_ticks }
    /// Identifies the most recent timer/yield cross-PID policy decision.
    /// Any subsequent successful admission, wake, cancel, reap, block, exit
    /// or dispatch invalidates it; a failed operation leaves it unchanged.
    /// This is metadata only: never a substitute for IRQ/syscall provenance
    /// or independently authenticated CPU/FX/CR3/TSS state.
    pub fn last_policy_handoff(&self) -> Option<(Handle, Handle)> { self.last_handoff }
    /// The last policy-only BLOCK dispatch, if it has not been superseded.
    /// A trusted caller must still prove a real trap and saved CPU state.
    pub fn last_block_handoff(&self) -> Option<(Handle, Handle)> { self.last_block_handoff }
    pub fn occupied(&self) -> usize {
        self.slots.iter().filter(|s| s.state != State::Empty).count()
    }

    fn locate(&self, handle: Handle) -> Result<usize, Error> {
        self.slots.iter().position(|s| {
            s.state != State::Empty && s.handle == handle
        }).ok_or(Error::Stale)
    }

    fn ready_after(&self, from: usize) -> Option<usize> {
        if N == 0 { return None; }
        (1..=N).map(|step| (from + step) % N)
            .find(|&j| self.slots[j].state == State::Ready)
    }

    pub fn admit(&mut self, pid: u64) -> Result<Handle, Error> {
        if pid == 0 { return Err(Error::InvalidPid); }
        if self.slots.iter().any(|s| {
            s.state != State::Empty && s.handle.pid == pid
        }) { return Err(Error::DuplicatePid); }
        let i = self.slots.iter().position(|s| s.state == State::Empty)
            .ok_or(Error::Full)?;
        let generation = self.generation.checked_add(1).ok_or(Error::Overflow)?;
        let handle = Handle { pid, generation };
        self.slots[i] = Slot { handle, state: State::Ready, ticks: 0 };
        self.wait_events[i] = 0;
        self.wait_sequences[i] = 0;
        self.generation = generation;
        self.last_handoff = None;
        self.last_block_handoff = None;
        Ok(handle)
    }

    /// Explicit dispatch after initial admission or when all tasks had
    /// blocked; this is NOT a hardware IRQ or a counted timer switch.
    pub fn start_next(&mut self) -> Result<Handle, Error> {
        if self.active.is_some() { return Err(Error::WrongState); }
        let i = self.slots.iter().position(|s| s.state == State::Ready)
            .ok_or(Error::NoRunnable)?;
        self.slots[i].state = State::Running;
        self.active = Some(i);
        self.slice_ticks = 0;
        self.last_handoff = None;
        self.last_block_handoff = None;
        Ok(self.slots[i].handle)
    }

    /// Called only AFTER the kernel has authenticated the hardware IRQ
    /// provenance, pinned source/destination IRET frames, CR3/TSS and FX.
    /// If no peer is READY the current task continues, with one timer tick
    /// accounted but no cross-PID switch.
    pub fn timer_tick(&mut self, interrupted: Handle) -> Result<Handle, Error> {
        self.timer_quantum_tick(interrupted, 1)
    }

    /// Count a *caller-authenticated real timer IRQ* and rotate only after
    /// `quantum_ticks` eligible interrupts. Every tick is charged to its
    /// source PID; only actual cross-PID rotation increments timer_switches.
    /// A voluntary YIELD/EXIT/BLOCK never counts as a timer-origin switch.
    ///
    /// With no READY peer, retain the current PID and cap the consumed slice
    /// at the deadline: the next eligible IRQ may rotate if a peer wakes.
    /// If the caller lowers quantum_ticks after a longer slice, the next
    /// authenticated tick treats the new deadline as already consumed.
    /// Every error leaves all fields unchanged, including overflow cases.
    /// This is a no_std, no-heap policy, not an IRQ provenance checker or
    /// hardware EOI, CR3, FX, TSS or IRET implementation.
    pub fn timer_quantum_tick(
        &mut self, interrupted: Handle, quantum_ticks: u64,
    ) -> Result<Handle, Error> {
        if quantum_ticks == 0 { return Err(Error::InvalidQuantum) }
        let i = self.active.ok_or(Error::NoRunnable)?;
        if self.slots[i].state != State::Running ||
            self.slots[i].handle != interrupted { return Err(Error::Stale); }
        let ticks = self.slots[i].ticks.checked_add(1).ok_or(Error::Overflow)?;
        // A slice already at its deadline stays capped when no peer was
        // READY. In particular, a valid u64::MAX quantum must not overflow
        // simply because the sole runnable task receives one more real IRQ.
        // Per-PID tick and switch counters remain checked independently.
        let elapsed = if self.slice_ticks >= quantum_ticks {
            // The caller may shorten a previously valid time slice.
            // Treat the new deadline as already reached rather than
            // overflowing the old saturated counter or postponing dispatch.
            quantum_ticks
        } else {
            self.slice_ticks.checked_add(1).ok_or(Error::Overflow)?
        };
        if elapsed < quantum_ticks {
            self.slots[i].ticks = ticks;
            self.slice_ticks = elapsed;
            self.last_handoff = None;
            self.last_block_handoff = None;
            return Ok(interrupted)
        }
        let next = self.ready_after(i);
        let switches = if next.is_some() {
            self.switches.checked_add(1).ok_or(Error::Overflow)?
        } else { self.switches };
        let handoff = next.map(|j| (interrupted, self.slots[j].handle));
        self.slots[i].ticks = ticks;
        if let Some(j) = next {
            self.slots[i].state = State::Ready;
            self.slots[j].state = State::Running;
            self.active = Some(j);
            self.slice_ticks = 0;
        } else {
            self.slice_ticks = quantum_ticks;
        }
        self.switches = switches;
        self.last_handoff = handoff;
        self.last_block_handoff = None;
        Ok(self.slots[self.active.unwrap()].handle)
    }

    /// Cooperative syscall-requested handoff to the next READY PID.
    /// No hardware timer IRQ is claimed and no timer tick/switch is counted.
    /// Callers must first validate the syscall owner and saved Ring3 frames;
    /// the policy never performs CR3, TSS, FX, or IRET operations.
    /// If no peer is READY or the handle is stale, every field is unchanged.
    pub fn voluntary_yield(&mut self, running: Handle) -> Result<Handle, Error> {
        let i = self.active.ok_or(Error::NoRunnable)?;
        if self.slots[i].state != State::Running || self.slots[i].handle != running {
            return Err(Error::Stale);
        }
        let j = self.ready_after(i).ok_or(Error::NoRunnable)?;
        self.slots[i].state = State::Ready;
        self.slots[j].state = State::Running;
        self.active = Some(j);
        self.slice_ticks = 0;
        self.last_handoff = Some((running, self.slots[j].handle));
        self.last_block_handoff = None;
        Ok(self.slots[j].handle)
    }

    pub fn block_current(&mut self, running: Handle) -> Result<Option<Handle>, Error> {
        let i = self.active.ok_or(Error::NoRunnable)?;
        if self.slots[i].handle != running || self.slots[i].state != State::Running {
            return Err(Error::Stale);
        }
        let next = self.ready_after(i);
        self.slots[i].state = State::Blocked;
        self.active = next;
        self.slice_ticks = 0;
        if let Some(j) = next { self.slots[j].state = State::Running; }
        self.last_handoff = None;
        self.last_block_handoff = next.map(|j| (running, self.slots[j].handle));
        Ok(self.running())
    }

    /// Bind a blocked Ring3 task to a nonzero trusted event ID and issue an
    /// opaque one-use wait ticket. Caller MUST first authenticate the CPL3
    /// trap, save GPR/IRET/FX and register the kernel wait event. This
    /// metadata operation cannot prove hardware event provenance.
    ///
    /// Checked sequence allocation happens BEFORE blocking, so exhaustion
    /// leaves all queue fields unchanged. Reusing an event ID for the same PID
    /// will not authorize delayed signals from a previous wait instance.
    pub fn block_current_for_event(
        &mut self, running: Handle, event: u64,
    ) -> Result<(Option<Handle>, WaitTicket), Error> {
        if event == 0 { return Err(Error::InvalidEvent) }
        let i = self.active.ok_or(Error::NoRunnable)?;
        if self.slots[i].handle != running || self.slots[i].state != State::Running {
            return Err(Error::Stale)
        }
        let sequence = self.next_wait_sequence.checked_add(1).ok_or(Error::Overflow)?;
        let selected = self.block_current(running)?;
        self.next_wait_sequence = sequence;
        self.wait_events[i] = event;
        self.wait_sequences[i] = sequence;
        Ok((selected, WaitTicket { handle: running, event, sequence }))
    }

    /// Legacy untagged wake. It cannot bypass event-bound waits.
    /// The caller still MUST independently authenticate wake provenance.
    pub fn wake(&mut self, handle: Handle) -> Result<(), Error> {
        let i = self.locate(handle)?;
        if self.slots[i].state != State::Blocked { return Err(Error::WrongState); }
        if self.wait_events[i] != 0 || self.wait_sequences[i] != 0 {
            return Err(Error::WrongEvent)
        }
        self.slots[i].state = State::Ready;
        self.last_handoff = None;
        self.last_block_handoff = None;
        Ok(())
    }

    /// A caller-authenticated event may wake ONLY the exact wait instance
    /// named in the kernel-issued ticket. Delayed signals from a previous
    /// wait with the same PID/event ID fail closed on sequence mismatch.
    /// The ticket alone is not evidence of real event provenance.
    pub fn wake_for_event(&mut self, ticket: WaitTicket, event: u64) -> Result<(), Error> {
        if event == 0 { return Err(Error::InvalidEvent) }
        let i = self.locate(ticket.handle)?;
        if self.slots[i].state != State::Blocked { return Err(Error::WrongState) }
        if self.wait_sequences[i] != ticket.sequence {
            return Err(Error::Stale)
        }
        if self.wait_events[i] != event || ticket.event != event {
            return Err(Error::WrongEvent)
        }
        self.slots[i].state = State::Ready;
        self.wait_events[i] = 0;
        self.wait_sequences[i] = 0;
        self.last_handoff = None;
        self.last_block_handoff = None;
        Ok(())
    }

    /// Involuntary cancellation is limited to non-running tasks.
    /// Active tasks must exit through their own trusted trap path.
    pub fn cancel(&mut self, handle: Handle) -> Result<(), Error> {
        let i = self.locate(handle)?;
        if !matches!(self.slots[i].state, State::Blocked | State::Ready) {
            return Err(Error::WrongState);
        }
        self.slots[i].state = State::Exited;
        self.wait_events[i] = 0;
        self.wait_sequences[i] = 0;
        self.last_handoff = None;
        self.last_block_handoff = None;
        Ok(())
    }

    pub fn exit_current(&mut self, running: Handle) -> Result<Option<Handle>, Error> {
        let i = self.active.ok_or(Error::NoRunnable)?;
        if self.slots[i].handle != running || self.slots[i].state != State::Running {
            return Err(Error::Stale);
        }
        let next = self.ready_after(i);
        self.slots[i].state = State::Exited;
        self.active = next;
        self.slice_ticks = 0;
        if let Some(j) = next { self.slots[j].state = State::Running; }
        self.last_handoff = None;
        self.last_block_handoff = None;
        Ok(self.running())
    }

    /// Must only be invoked after the hardware context and PMM frames have
    /// already been quiesced and fully reclaimed by the owning kernel code.
    pub fn reap(&mut self, handle: Handle) -> Result<(), Error> {
        let i = self.locate(handle)?;
        if self.slots[i].state != State::Exited { return Err(Error::WrongState); }
        self.slots[i] = Slot::EMPTY;
        self.wait_events[i] = 0;
        self.wait_sequences[i] = 0;
        self.last_handoff = None;
        self.last_block_handoff = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_owners_interleave_irq_block_event_wake_exit_and_stale_reuse() {
        let mut q = Ring3RunQueue::<4>::new();
        let h = [1, 2, 3, 4].map(|pid| q.admit(pid).unwrap());
        assert_eq!(q.start_next(), Ok(h[0]));
        // Two authenticated timer policy ticks, exactly one handoff.
        assert_eq!(q.timer_quantum_tick(h[0], 2), Ok(h[0]));
        assert_eq!(q.timer_quantum_tick(h[0], 2), Ok(h[1]));
        assert_eq!(q.timer_switches(), 1);
        assert_eq!(q.last_policy_handoff(), Some((h[0], h[1])));

        // PID2 blocks; PID3 installs a one-use event wait; PID4 and PID1
        // then block independently, leaving no fabricated RUNNING owner.
        assert_eq!(q.block_current(h[1]), Ok(Some(h[2])));
        let (next, ticket) = q.block_current_for_event(h[2], 77).unwrap();
        assert_eq!(next, Some(h[3]));
        assert_eq!(q.block_current(h[3]), Ok(Some(h[0])));
        assert_eq!(q.block_current(h[0]), Ok(None));
        assert_eq!(q.running(), None);
        assert_eq!(q.current_slice_ticks(), 0);
        assert_eq!(q.last_policy_handoff(), None);
        assert_eq!(q.timer_switches(), 1);

        let before = q;
        assert_eq!(q.wake(h[2]), Err(Error::WrongEvent));
        assert_eq!(q.wake_for_event(ticket, 78), Err(Error::WrongEvent));
        assert_eq!(q.timer_quantum_tick(h[0], 2), Err(Error::NoRunnable));
        assert_eq!(q, before, "all failures must preserve every ledger field");

        // The exact ticket wakes only PID3; it is the sole runnable PID.
        assert_eq!(q.wake_for_event(ticket, 77), Ok(()));
        assert_eq!(q.start_next(), Ok(h[2]));
        assert_eq!(q.timer_quantum_tick(h[2], 2), Ok(h[2]));
        assert_eq!(q.timer_quantum_tick(h[2], 2), Ok(h[2]));
        assert_eq!(q.current_slice_ticks(), 2);
        assert_eq!(q.timer_switches(), 1);
        let pre_wake = q;
        assert_eq!(q.wake_for_event(ticket, 77), Err(Error::WrongState));
        assert_eq!(q, pre_wake);

        // A ready peer can rotate on the next authentic timer tick despite
        // a capped solitary quantum. Exits and cancels never forge switches.
        assert_eq!(q.wake(h[1]), Ok(()));
        assert_eq!(q.timer_quantum_tick(h[2], 2), Ok(h[1]));
        assert_eq!(q.timer_switches(), 2);
        assert_eq!(q.exit_current(h[1]), Ok(Some(h[2])));
        assert_eq!(q.cancel(h[0]), Ok(()));
        assert_eq!(q.cancel(h[3]), Ok(()));
        assert_eq!(q.exit_current(h[2]), Ok(None));
        assert_eq!(q.running(), None);
        assert_eq!(q.timer_switches(), 2);
        assert!(q.slots().iter().all(|s| s.state == State::Exited));

        // Trusted hardware/PMM quiescence is a PRECONDITION of reap;
        // the host policy cannot claim the real resources were freed.
        for handle in h { assert_eq!(q.reap(handle), Ok(())); }
        assert_eq!(q.occupied(), 0);
        let fresh = q.admit(3).unwrap();
        assert!(fresh.generation > h[2].generation);
        assert_ne!(fresh, h[2]);
        assert_eq!(q.start_next(), Ok(fresh));
        let snapshot = q;
        assert_eq!(q.wake_for_event(ticket, 77), Err(Error::Stale));
        assert_eq!(q.timer_quantum_tick(h[2], 2), Err(Error::Stale));
        assert_eq!(q, snapshot);
        assert_eq!(q.timer_switches(), 2);
    }

    #[test]
    fn four_tasks_get_exact_two_irq_time_slices_without_fake_switches() {
        let mut q = Ring3RunQueue::<4>::new();
        let h = [1, 2, 3, 4].map(|pid| q.admit(pid).unwrap());
        assert_eq!(q.start_next(), Ok(h[0]));
        for turn in 0..32 {
            let from = h[turn % 4];
            let to = h[(turn + 1) % 4];
            assert_eq!(q.timer_quantum_tick(from, 2), Ok(from),
                       "the first authenticated timer IRQ must stay on its PID");
            assert_eq!(q.current_slice_ticks(), 1);
            assert_eq!(q.timer_switches(), turn as u64);
            assert_eq!(q.timer_quantum_tick(from, 2), Ok(to),
                       "the second timer IRQ must rotate to a ready peer");
            assert_eq!(q.current_slice_ticks(), 0);
            assert_eq!(q.timer_switches(), turn as u64 + 1);
        }
        for slot in q.slots() {
            assert_eq!(slot.ticks, 16, "charge ALL IRQs to the interrupted PID");
        }
        for (i, handle) in h.iter().enumerate() {
            assert_eq!(q.exit_current(*handle), Ok(h.get(i + 1).copied()));
        }
        assert_eq!(q.timer_switches(), 32, "EXIT never forges an IRQ switch");
        assert_eq!(q.current_slice_ticks(), 0);
    }

    #[test]
    fn pending_quantum_is_reset_on_yield_block_and_exit() {
        let mut q = Ring3RunQueue::<4>::new();
        let a = q.admit(1).unwrap();
        let b = q.admit(2).unwrap();
        q.start_next().unwrap();
        assert_eq!(q.timer_quantum_tick(a, 3), Ok(a));
        assert_eq!(q.current_slice_ticks(), 1);
        assert_eq!(q.voluntary_yield(a), Ok(b));
        assert_eq!(q.current_slice_ticks(), 0);
        assert_eq!(q.timer_quantum_tick(b, 3), Ok(b));
        assert_eq!(q.block_current(b), Ok(Some(a)));
        assert_eq!(q.current_slice_ticks(), 0);
        assert_eq!(q.timer_quantum_tick(a, 3), Ok(a));
        assert_eq!(q.exit_current(a), Ok(None));
        assert_eq!(q.current_slice_ticks(), 0);
        assert_eq!(q.timer_switches(), 0);
    }

    #[test]
    fn quantum_deadline_without_ready_peer_is_capped_and_wakeup_can_rotate() {
        let mut q = Ring3RunQueue::<4>::new();
        let a = q.admit(1).unwrap();
        q.start_next().unwrap();
        for _ in 0..10 {
            assert_eq!(q.timer_quantum_tick(a, 3), Ok(a));
        }
        assert_eq!(q.current_slice_ticks(), 3);
        assert_eq!(q.timer_switches(), 0);
        assert_eq!(q.slots()[0].ticks, 10);
        let b = q.admit(2).unwrap();
        assert_eq!(q.timer_quantum_tick(a, 3), Ok(b));
        assert_eq!(q.current_slice_ticks(), 0);
        assert_eq!(q.timer_switches(), 1);
        assert_eq!(q.slots()[0].ticks, 11);
    }

    #[test]
    fn max_quantum_deadline_does_not_deadlock_a_lone_runnable_pid() {
        let mut q = Ring3RunQueue::<2>::new();
        let a = q.admit(10).unwrap();
        assert_eq!(q.start_next(), Ok(a));
        // Model the fully consumed quantum without looping u64::MAX times.
        q.slice_ticks = u64::MAX;
        assert_eq!(q.timer_quantum_tick(a, u64::MAX), Ok(a));
        assert_eq!(q.current_slice_ticks(), u64::MAX);
        assert_eq!(q.timer_switches(), 0);
        assert_eq!(q.slots()[0].ticks, 1);
        let b = q.admit(20).unwrap();
        assert_eq!(q.timer_quantum_tick(a, u64::MAX), Ok(b));
        assert_eq!(q.running(), Some(b));
        assert_eq!(q.current_slice_ticks(), 0);
        assert_eq!(q.timer_switches(), 1);
        assert_eq!(q.slots()[0].ticks, 2);
    }


    #[test]
    fn reducing_quantum_rotates_at_the_next_authenticated_timer_tick() {
        let mut q = Ring3RunQueue::<2>::new();
        let a = q.admit(11).unwrap();
        let b = q.admit(12).unwrap();
        assert_eq!(q.start_next(), Ok(a));

        // Four real-policy ticks of a six-tick slice have elapsed.
        for elapsed in 1..=4 {
            assert_eq!(q.timer_quantum_tick(a, 6), Ok(a));
            assert_eq!(q.current_slice_ticks(), elapsed);
        }
        assert_eq!(q.timer_switches(), 0);

        // A policy change to quantum=2 must not allow two more ticks,
        // lose the fifth tick, or claim a fake voluntary switch.
        assert_eq!(q.timer_quantum_tick(a, 2), Ok(b));
        assert_eq!(q.current_slice_ticks(), 0);
        assert_eq!(q.slots()[0].ticks, 5);
        assert_eq!(q.timer_switches(), 1);
        assert_eq!(q.timer_quantum_tick(b, 2), Ok(b));
        assert_eq!(q.timer_quantum_tick(b, 2), Ok(a));
        assert_eq!(q.slots()[1].ticks, 2);
        assert_eq!(q.timer_switches(), 2);
    }

    #[test]
    fn saturated_max_quantum_can_be_reduced_without_overflow_or_starvation() {
        let mut q = Ring3RunQueue::<2>::new();
        let a = q.admit(1).unwrap();
        assert_eq!(q.start_next(), Ok(a));
        // Model a valid u64::MAX quantum at its full deadline without
        // iterating through all u64::MAX physical timer interrupts.
        q.slice_ticks = u64::MAX;
        assert_eq!(q.timer_quantum_tick(a, 1), Ok(a));
        assert_eq!(q.current_slice_ticks(), 1);
        assert_eq!(q.slots()[0].ticks, 1);
        assert_eq!(q.timer_switches(), 0);
        // Once a peer is admitted, the very next accounted timer IRQ
        // may select it instead of overflowing the old slice counter.
        let b = q.admit(2).unwrap();
        assert_eq!(q.timer_quantum_tick(a, 1), Ok(b));
        assert_eq!(q.running(), Some(b));
        assert_eq!(q.current_slice_ticks(), 0);
        assert_eq!(q.slots()[0].ticks, 2);
        assert_eq!(q.timer_switches(), 1);
    }

    #[test]
    fn quantum_errors_and_overflow_never_mutate_any_field() {
        let mut q = Ring3RunQueue::<4>::new();
        let a = q.admit(1).unwrap();
        let b = q.admit(2).unwrap();
        q.start_next().unwrap();
        let before = q;
        assert_eq!(q.timer_quantum_tick(a, 0), Err(Error::InvalidQuantum));
        assert_eq!(q.timer_quantum_tick(b, 2), Err(Error::Stale));
        assert_eq!(q, before);
        q.slots[0].ticks = u64::MAX;
        let before = q;
        assert_eq!(q.timer_quantum_tick(a, 2), Err(Error::Overflow));
        assert_eq!(q, before);
        q.slots[0].ticks = 0;
        q.slice_ticks = 1;
        q.switches = u64::MAX;
        let before = q;
        assert_eq!(q.timer_quantum_tick(a, 2), Err(Error::Overflow));
        assert_eq!(q, before);
    }

    #[test]
    fn four_task_cooperative_handoffs_do_not_forge_timer_switches() {
        let mut q = Ring3RunQueue::<4>::new();
        let h = [11, 22, 33, 44].map(|pid| q.admit(pid).unwrap());
        assert_eq!(q.start_next(), Ok(h[0]));
        for i in 0..4 {
            assert_eq!(q.voluntary_yield(h[i]), Ok(h[(i + 1) % 4]));
        }
        assert_eq!(q.timer_switches(), 0);
        assert!(q.slots().iter().all(|slot| slot.ticks == 0));
        assert_eq!(q.timer_tick(h[0]), Ok(h[1]));
        assert_eq!(q.voluntary_yield(h[1]), Ok(h[2]));
        assert_eq!(q.timer_tick(h[2]), Ok(h[3]));
        assert_eq!(q.timer_switches(), 2);
        assert_eq!(q.slots().map(|s| s.ticks), [1, 0, 1, 0]);
        for i in [3, 0, 1, 2] {
            let next = q.exit_current(h[i]).unwrap();
            assert_eq!(next, if i == 2 { None } else { Some(h[(i + 1) % 4]) });
        }
        assert_eq!(q.running(), None);
        assert_eq!(q.timer_switches(), 2);
    }

    #[test]
    fn yield_requires_live_running_handle_and_ready_peer_without_mutation() {
        let mut q = Ring3RunQueue::<4>::new();
        let a = q.admit(1).unwrap();
        assert_eq!(q.start_next(), Ok(a));
        let mut before = q;
        assert_eq!(q.voluntary_yield(a), Err(Error::NoRunnable));
        assert_eq!(q.voluntary_yield(Handle { pid: 2, generation: 7 }), Err(Error::Stale));
        assert_eq!(q, before);
        let b = q.admit(2).unwrap();
        assert_eq!(q.block_current(a), Ok(Some(b)));
        before = q;
        assert_eq!(q.voluntary_yield(a), Err(Error::Stale));
        assert_eq!(q.voluntary_yield(b), Err(Error::NoRunnable));
        assert_eq!(q, before);
        q.wake(a).unwrap();
        assert_eq!(q.voluntary_yield(b), Ok(a));
        assert_eq!(q.exit_current(a), Ok(Some(b)));
        q.reap(a).unwrap();
        let replacement = q.admit(1).unwrap();
        assert_ne!(a, replacement);
        before = q;
        assert_eq!(q.voluntary_yield(a), Err(Error::Stale));
        assert_eq!(q, before);
        assert_eq!(q.voluntary_yield(b), Ok(replacement));
        assert_eq!(q.timer_switches(), 0);
    }

    #[test]
    fn four_realistic_pids_get_equal_80_timer_quantums_without_yield() {
        let mut q = Ring3RunQueue::<4>::new();
        let handles = [11, 22, 33, 44].map(|pid| q.admit(pid).unwrap());
        assert_eq!(q.start_next(), Ok(handles[0]));
        for turn in 0..80 {
            let from = handles[turn % 4];
            let to = handles[(turn + 1) % 4];
            assert_eq!(q.timer_tick(from), Ok(to));
            assert_eq!(q.running(), Some(to));
        }
        assert_eq!(q.timer_switches(), 80);
        for slot in q.slots() {
            assert_eq!(slot.ticks, 20);
            assert_eq!(slot.state == State::Running, slot.handle == handles[0]);
        }
        for (i, h) in handles.iter().enumerate() {
            assert_eq!(q.exit_current(*h), Ok(handles.get(i + 1).copied()));
        }
        assert_eq!(q.running(), None);
        assert_eq!(q.timer_switches(), 80, "EXIT must not forge timer switches");
        for h in handles { q.reap(h).unwrap(); }
        assert_eq!(q.occupied(), 0);
    }

    #[test]
    fn blocked_peers_are_skipped_and_wake_after_all_sleep() {
        let mut q = Ring3RunQueue::<4>::new();
        let a = q.admit(1).unwrap();
        let b = q.admit(2).unwrap();
        let c = q.admit(3).unwrap();
        assert_eq!(q.start_next(), Ok(a));
        assert_eq!(q.block_current(a), Ok(Some(b)));
        assert_eq!(q.timer_tick(b), Ok(c));
        assert_eq!(q.block_current(c), Ok(Some(b)));
        assert_eq!(q.block_current(b), Ok(None));
        assert_eq!(q.timer_tick(b), Err(Error::NoRunnable));
        assert_eq!(q.start_next(), Err(Error::NoRunnable));
        q.wake(a).unwrap();
        assert_eq!(q.start_next(), Ok(a));
        assert_eq!(q.timer_tick(a), Ok(a));
        assert_eq!(q.timer_switches(), 1);
        q.wake(c).unwrap();
        assert_eq!(q.timer_tick(a), Ok(c));
        assert_eq!(q.timer_switches(), 2);
    }

    #[test]
    fn reaped_pid_reuse_never_accepts_old_generation() {
        let mut q = Ring3RunQueue::<4>::new();
        let old = q.admit(99).unwrap();
        q.start_next().unwrap();
        assert_eq!(q.exit_current(old), Ok(None));
        q.reap(old).unwrap();
        let newer = q.admit(99).unwrap();
        assert_ne!(old.generation, newer.generation);
        assert_eq!(q.wake(old), Err(Error::Stale));
        assert_eq!(q.reap(old), Err(Error::Stale));
        assert_eq!(q.start_next(), Ok(newer));
        let before = q;
        assert_eq!(q.timer_tick(old), Err(Error::Stale));
        assert_eq!(q.exit_current(old), Err(Error::Stale));
        assert_eq!(q, before);
    }

    #[test]
    fn capacity_duplicate_and_nonrunning_cancellation_are_fail_closed() {
        let mut q = Ring3RunQueue::<4>::new();
        let handles = [1, 2, 3, 4].map(|p| q.admit(p).unwrap());
        let before = q;
        assert_eq!(q.admit(0), Err(Error::InvalidPid));
        assert_eq!(q.admit(3), Err(Error::DuplicatePid));
        assert_eq!(q.admit(5), Err(Error::Full));
        assert_eq!(q, before);
        q.start_next().unwrap();
        assert_eq!(q.cancel(handles[0]), Err(Error::WrongState));
        assert_eq!(q.cancel(handles[2]), Ok(()));
        assert_eq!(q.timer_tick(handles[0]), Ok(handles[1]));
        assert_eq!(q.timer_tick(handles[1]), Ok(handles[3]));
        assert_eq!(q.reap(handles[2]), Ok(()));
        assert_eq!(q.cancel(handles[2]), Err(Error::Stale));
        assert_eq!(q.admit(5).unwrap().pid, 5);
    }

    #[test]
    fn out_of_order_exits_and_blocked_peer_preserve_single_running_owner() {
        let mut q = Ring3RunQueue::<4>::new();
        let h = [1, 2, 3, 4].map(|p| q.admit(p).unwrap());
        assert_eq!(q.start_next(), Ok(h[0]));
        assert_eq!(q.timer_tick(h[0]), Ok(h[1]));
        assert_eq!(q.exit_current(h[1]), Ok(Some(h[2])));
        assert_eq!(q.block_current(h[2]), Ok(Some(h[3])));
        assert_eq!(q.exit_current(h[3]), Ok(Some(h[0])));
        assert_eq!(q.exit_current(h[0]), Ok(None));
        assert_eq!(q.running(), None);
        assert_eq!(q.start_next(), Err(Error::NoRunnable));
        q.wake(h[2]).unwrap();
        assert_eq!(q.start_next(), Ok(h[2]));
        assert_eq!(q.exit_current(h[2]), Ok(None));
        for v in h { q.reap(v).unwrap(); }
        assert_eq!(q.occupied(), 0);
    }

    #[test]
    fn every_error_preserves_entire_state_even_on_u64_overflow() {
        let mut q = Ring3RunQueue::<4>::new();
        let a = q.admit(1).unwrap();
        let b = q.admit(2).unwrap();
        q.start_next().unwrap();
        let mut before = q;
        assert_eq!(q.timer_tick(b), Err(Error::Stale));
        assert_eq!(q.wake(b), Err(Error::WrongState));
        assert_eq!(q.reap(b), Err(Error::WrongState));
        assert_eq!(q, before);
        q.slots[0].ticks = u64::MAX;
        before = q;
        assert_eq!(q.timer_tick(a), Err(Error::Overflow));
        assert_eq!(q, before);
        q.slots[0].ticks = 0;
        q.switches = u64::MAX;
        before = q;
        assert_eq!(q.timer_tick(a), Err(Error::Overflow));
        assert_eq!(q, before);
        q.switches = 0;
        q.generation = u64::MAX;
        before = q;
        assert_eq!(q.admit(3), Err(Error::Overflow));
        assert_eq!(q, before);
    }

    #[test]
    fn wake_lifecycle_rejects_duplicates_cancelled_and_stale_handles_without_mutation() {
        let mut q = Ring3RunQueue::<3>::new();
        let a = q.admit(7).unwrap();
        let b = q.admit(8).unwrap();
        assert_eq!(q.start_next(), Ok(a));
        assert_eq!(q.timer_quantum_tick(a, 2), Ok(a));
        assert_eq!(q.block_current(a), Ok(Some(b)));
        let before = q;
        assert_eq!(q.wake(Handle { pid: a.pid, generation: a.generation + 1 }), Err(Error::Stale));
        assert_eq!(q.wake(b), Err(Error::WrongState));
        assert_eq!(q, before);

        assert_eq!(q.wake(a), Ok(()));
        let before = q;
        assert_eq!(q.wake(a), Err(Error::WrongState));
        assert_eq!(q, before);
        assert_eq!(q.block_current(b), Ok(Some(a)));
        assert_eq!(q.cancel(b), Ok(()));
        let before = q;
        assert_eq!(q.wake(b), Err(Error::WrongState));
        assert_eq!(q, before);
        assert_eq!(q.exit_current(a), Ok(None));
        assert_eq!(q.reap(a), Ok(()));
        let replacement = q.admit(7).unwrap();
        let before = q;
        assert_eq!(q.wake(a), Err(Error::Stale));
        assert_eq!(q, before);
        assert_eq!(q.start_next(), Ok(replacement));
        assert_eq!(q.timer_switches(), 0);
    }

    #[test]
    fn event_bound_block_requires_matching_wake_and_never_forges_timer_irq() {
        let mut q = Ring3RunQueue::<3>::new();
        let a = q.admit(11).unwrap();
        let b = q.admit(22).unwrap();
        assert_eq!(q.start_next(), Ok(a));

        let before = q;
        assert_eq!(q.block_current_for_event(a, 0), Err(Error::InvalidEvent));
        assert_eq!(q.block_current_for_event(b, 57), Err(Error::Stale));
        assert_eq!(q, before);

        let (next, ticket) = q.block_current_for_event(a, 57).unwrap();
        assert_eq!(next, Some(b));
        assert_eq!(q.wait_events[0], 57);
        assert_eq!(q.last_block_handoff(), Some((a, b)));
        assert_eq!(q.timer_switches(), 0);
        let blocked = q;
        assert_eq!(q.wake(a), Err(Error::WrongEvent),
            "untagged wake must not bypass event authentication");
        assert_eq!(q.wake_for_event(ticket, 58), Err(Error::WrongEvent));
        assert_eq!(q.wake_for_event(ticket, 0), Err(Error::InvalidEvent));
        assert_eq!(q.wake_for_event(WaitTicket { handle: b, ..ticket }, 57),
            Err(Error::WrongState));
        assert_eq!(q.wake_for_event(WaitTicket {
            handle: Handle { generation: a.generation + 1, ..a }, ..ticket
        }, 57), Err(Error::Stale));
        assert_eq!(q, blocked, "rejected wakes must preserve the entire policy");
        assert_eq!(q.wake_for_event(ticket, 57), Ok(()));
        assert_eq!(q.wait_events[0], 0);
        assert_eq!(q.last_block_handoff(), None);
        assert_eq!(q.timer_switches(), 0);
        assert_eq!(q.timer_tick(b), Ok(a));
        assert_eq!(q.last_policy_handoff(), Some((b, a)));
        assert_eq!(q.timer_switches(), 1);
        assert_eq!(q.wake_for_event(ticket, 57), Err(Error::WrongState));
    }

    #[test]
    fn all_blocked_event_wake_and_cancelled_stale_event_never_resurrect_pid() {
        let mut q = Ring3RunQueue::<1>::new();
        let old = q.admit(7).unwrap();
        assert_eq!(q.start_next(), Ok(old));
        let (next, first) = q.block_current_for_event(old, 99).unwrap();
        assert_eq!(next, None);
        assert_eq!(q.running(), None);
        assert_eq!(q.start_next(), Err(Error::NoRunnable));
        assert_eq!(q.wake(old), Err(Error::WrongEvent));
        assert_eq!(q.wake_for_event(first, 99), Ok(()));
        assert_eq!(q.start_next(), Ok(old));
        assert_eq!(q.timer_switches(), 0);

        let (next, second) = q.block_current_for_event(old, 101).unwrap();
        assert_eq!(next, None);
        assert_eq!(q.cancel(old), Ok(()));
        assert_eq!(q.wait_events[0], 0);
        assert_eq!(q.wake_for_event(second, 101), Err(Error::WrongState));
        assert_eq!(q.reap(old), Ok(()));
        let replacement = q.admit(7).unwrap();
        assert_ne!(replacement, old);
        let before = q;
        assert_eq!(q.wake_for_event(second, 101), Err(Error::Stale));
        assert_eq!(q, before);
        assert_eq!(q.start_next(), Ok(replacement));
        assert_eq!(q.timer_switches(), 0);
    }

    #[test]
    fn delayed_event_cannot_wake_a_second_wait_using_same_pid_and_event() {
        let mut q = Ring3RunQueue::<2>::new();
        let a = q.admit(10).unwrap();
        let b = q.admit(20).unwrap();
        assert_eq!(q.start_next(), Ok(a));
        let (next, first) = q.block_current_for_event(a, 77).unwrap();
        assert_eq!(next, Some(b));
        assert_eq!(q.wake_for_event(first, 77), Ok(()));
        assert_eq!(q.timer_tick(b), Ok(a));
        let (next, second) = q.block_current_for_event(a, 77).unwrap();
        assert_eq!(next, Some(b));
        assert_ne!(first, second, "the wait sequence cannot be reused");
        let before = q;
        assert_eq!(q.wake_for_event(first, 77), Err(Error::Stale));
        assert_eq!(q.wake_for_event(second, 78), Err(Error::WrongEvent));
        assert_eq!(q, before);
        assert_eq!(q.wake_for_event(second, 77), Ok(()));
        assert_eq!(q.timer_switches(), 1);
        assert_eq!(q.timer_tick(b), Ok(a));
        assert_eq!(q.timer_switches(), 2);
    }

    #[test]
    fn wait_ticket_exhaustion_is_transactional_and_never_blocks() {
        let mut q = Ring3RunQueue::<1>::new();
        let a = q.admit(1).unwrap();
        assert_eq!(q.start_next(), Ok(a));
        q.next_wait_sequence = u64::MAX;
        let before = q;
        assert_eq!(q.block_current_for_event(a, 123), Err(Error::Overflow));
        assert_eq!(q, before);
        assert_eq!(q.running(), Some(a));
        assert_eq!(q.wait_events[0], 0);
        assert_eq!(q.wait_sequences[0], 0);
        assert_eq!(q.timer_switches(), 0);
    }

    #[test]
    fn only_real_policy_rotation_records_its_exact_handoff_pair() {
        let mut q = Ring3RunQueue::<3>::new();
        let a = q.admit(1).unwrap();
        let b = q.admit(2).unwrap();
        let c = q.admit(3).unwrap();
        assert_eq!(q.last_policy_handoff(), None);
        assert_eq!(q.start_next(), Ok(a));
        assert_eq!(q.timer_quantum_tick(a, 2), Ok(a));
        assert_eq!(q.last_policy_handoff(), None);
        assert_eq!(q.block_current(a), Ok(Some(b)));
        assert_eq!(q.last_policy_handoff(), None);
        q.wake(a).unwrap();
        assert_eq!(q.last_policy_handoff(), None,
            "a wake cannot fabricate a transition from the woken PID");
        assert_eq!(q.timer_tick(b), Ok(c));
        assert_eq!(q.last_policy_handoff(), Some((b, c)));
        let before = q;
        assert_eq!(q.timer_tick(a), Err(Error::Stale));
        assert_eq!(q, before, "a rejected tick must preserve handoff evidence");
        assert_eq!(q.voluntary_yield(c), Ok(a));
        assert_eq!(q.last_policy_handoff(), Some((c, a)));
        assert_eq!(q.block_current(a), Ok(Some(b)));
        assert_eq!(q.last_policy_handoff(), None,
            "a blocking handoff is not a timer/yield rotation");
        assert_eq!(q.timer_switches(), 1);
    }

    #[test]
    fn successful_membership_mutations_revoke_stale_handoff_evidence() {
        let mut q = Ring3RunQueue::<4>::new();
        let a = q.admit(1).unwrap();
        let b = q.admit(2).unwrap();
        let c = q.admit(3).unwrap();
        assert_eq!(q.start_next(), Ok(a));
        assert_eq!(q.timer_tick(a), Ok(b));
        assert_eq!(q.last_policy_handoff(), Some((a, b)));
        let unchanged = q;
        assert_eq!(q.admit(1), Err(Error::DuplicatePid));
        assert_eq!(q.wake(a), Err(Error::WrongState));
        assert_eq!(q.cancel(b), Err(Error::WrongState));
        assert_eq!(q.reap(a), Err(Error::WrongState));
        assert_eq!(q, unchanged,
            "rejected membership operations may not consume valid evidence");

        let d = q.admit(4).unwrap();
        assert_eq!(q.last_policy_handoff(), None,
            "new admission must invalidate an earlier timer decision");
        assert_eq!(q.timer_tick(b), Ok(c));
        assert_eq!(q.last_policy_handoff(), Some((b, c)));
        assert_eq!(q.block_current(c), Ok(Some(d)));
        assert_eq!(q.last_policy_handoff(), None);
        assert_eq!(q.timer_tick(d), Ok(a));
        assert_eq!(q.last_policy_handoff(), Some((d, a)));
        q.wake(c).unwrap();
        assert_eq!(q.last_policy_handoff(), None,
            "waking a sleeping PID changes the runnable snapshot");

        assert_eq!(q.timer_tick(a), Ok(b));
        assert_eq!(q.last_policy_handoff(), Some((a, b)));
        q.cancel(c).unwrap();
        assert_eq!(q.last_policy_handoff(), None,
            "cancelling a READY PID changes the scheduler membership");
        assert_eq!(q.timer_tick(b), Ok(d));
        assert_eq!(q.last_policy_handoff(), Some((b, d)));
        q.reap(c).unwrap();
        assert_eq!(q.last_policy_handoff(), None,
            "reaping an EXITED slot invalidates earlier handoff evidence");

        assert_eq!(q.timer_tick(d), Ok(a));
        assert_eq!(q.last_policy_handoff(), Some((d, a)));
        assert_eq!(q.timer_switches(), 6,
            "admit/wake/cancel/reap must not forge timer switches");
    }

    #[test]
    fn block_handoff_proof_is_single_use_until_next_policy_mutation() {
        let mut q = Ring3RunQueue::<3>::new();
        let a = q.admit(10).unwrap();
        let b = q.admit(11).unwrap();
        let c = q.admit(12).unwrap();
        assert_eq!(q.last_block_handoff(), None);
        assert_eq!(q.start_next(), Ok(a));
        assert_eq!(q.block_current(a), Ok(Some(b)));
        assert_eq!(q.last_block_handoff(), Some((a, b)));
        assert_eq!(q.last_policy_handoff(), None);
        assert_eq!(q.timer_switches(), 0);
        let before = q;
        assert_eq!(q.block_current(a), Err(Error::Stale));
        assert_eq!(q.wake(b), Err(Error::WrongState));
        assert_eq!(q.cancel(b), Err(Error::WrongState));
        assert_eq!(q, before,
            "failed operations must not corrupt the pending BLOCK evidence");

        assert_eq!(q.timer_tick(b), Ok(c));
        assert_eq!(q.last_block_handoff(), None,
            "a real timer decision supersedes a BLOCK policy decision");
        assert_eq!(q.block_current(c), Ok(Some(b)));
        assert_eq!(q.last_block_handoff(), Some((c, b)));
        q.wake(a).unwrap();
        assert_eq!(q.last_block_handoff(), None);
        assert_eq!(q.block_current(b), Ok(Some(a)));
        assert_eq!(q.last_block_handoff(), Some((b, a)));
        q.cancel(c).unwrap();
        assert_eq!(q.last_block_handoff(), None);
        assert_eq!(q.exit_current(a), Ok(None));
        assert_eq!(q.last_block_handoff(), None);
        assert_eq!(q.reap(c), Ok(()));
        assert_eq!(q.last_block_handoff(), None);
        assert_eq!(q.timer_switches(), 1,
            "BLOCK, WAKE, CANCEL and REAP never forge timer switches");
    }

    #[test]
    fn blocking_the_last_ready_pid_produces_no_forged_handoff() {
        let mut q = Ring3RunQueue::<1>::new();
        let a = q.admit(7).unwrap();
        assert_eq!(q.start_next(), Ok(a));
        assert_eq!(q.block_current(a), Ok(None));
        assert_eq!(q.last_block_handoff(), None);
        assert_eq!(q.running(), None);
        assert_eq!(q.timer_switches(), 0);
        assert_eq!(q.wake(a), Ok(()));
        assert_eq!(q.start_next(), Ok(a));
        assert_eq!(q.last_block_handoff(), None);
    }

    #[test]
    fn zero_capacity_queue_remains_inert() {
        let mut q = Ring3RunQueue::<0>::new();
        assert_eq!(q.admit(1), Err(Error::Full));
        assert_eq!(q.start_next(), Err(Error::NoRunnable));
        assert_eq!(q.running(), None);
    }
}
