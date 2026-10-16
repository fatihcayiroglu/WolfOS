//! Fixed-capacity, allocation-free, **policy-only** BSP Ring3 ready queue.
//! No MMIO, IRET, CR3 changes, EOI, memory ownership or hardware scheduling.
//! The caller must authenticate saved frames and process generation before
//! any corresponding real trap/IRQ handoff. Issue #106 (host milestone).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle { pub pid: u64, pub generation: u64 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State { Empty, Ready, Running, Blocked, Exited }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { InvalidPid, DuplicatePid, Full, Stale, WrongState, NoRunnable, Overflow }

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
}

impl<const N: usize> Ring3RunQueue<N> {
    pub const fn new() -> Self {
        Self { slots: [Slot::EMPTY; N], active: None, switches: 0, generation: 0 }
    }

    pub fn slots(&self) -> [Slot; N] { self.slots }
    pub fn running(&self) -> Option<Handle> {
        self.active.map(|i| self.slots[i].handle)
    }
    /// Count only genuine policy-requested timer-origin cross-PID switches,
    /// never a syscall, EXIT, BLOCK or wakeup dispatch.
    pub fn timer_switches(&self) -> u64 { self.switches }
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
        self.generation = generation;
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
        Ok(self.slots[i].handle)
    }

    /// Called only AFTER the kernel has authenticated the hardware IRQ
    /// provenance, pinned source/destination IRET frames, CR3/TSS and FX.
    /// If no peer is READY the current task continues, with one timer tick
    /// accounted but no cross-PID switch.
    pub fn timer_tick(&mut self, interrupted: Handle) -> Result<Handle, Error> {
        let i = self.active.ok_or(Error::NoRunnable)?;
        if self.slots[i].state != State::Running ||
            self.slots[i].handle != interrupted { return Err(Error::Stale); }
        let ticks = self.slots[i].ticks.checked_add(1).ok_or(Error::Overflow)?;
        let next = self.ready_after(i);
        let switches = if next.is_some() {
            self.switches.checked_add(1).ok_or(Error::Overflow)?
        } else { self.switches };
        self.slots[i].ticks = ticks;
        if let Some(j) = next {
            self.slots[i].state = State::Ready;
            self.slots[j].state = State::Running;
            self.active = Some(j);
        }
        self.switches = switches;
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
        if let Some(j) = next { self.slots[j].state = State::Running; }
        Ok(self.running())
    }

    pub fn wake(&mut self, handle: Handle) -> Result<(), Error> {
        let i = self.locate(handle)?;
        if self.slots[i].state != State::Blocked { return Err(Error::WrongState); }
        self.slots[i].state = State::Ready;
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
        if let Some(j) = next { self.slots[j].state = State::Running; }
        Ok(self.running())
    }

    /// Must only be invoked after the hardware context and PMM frames have
    /// already been quiesced and fully reclaimed by the owning kernel code.
    pub fn reap(&mut self, handle: Handle) -> Result<(), Error> {
        let i = self.locate(handle)?;
        if self.slots[i].state != State::Exited { return Err(Error::WrongState); }
        self.slots[i] = Slot::EMPTY;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn zero_capacity_queue_remains_inert() {
        let mut q = Ring3RunQueue::<0>::new();
        assert_eq!(q.admit(1), Err(Error::Full));
        assert_eq!(q.start_next(), Err(Error::NoRunnable));
        assert_eq!(q.running(), None);
    }
}
