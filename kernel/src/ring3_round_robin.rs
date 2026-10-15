//! Bounded single-BSP Ring3 round-robin policy; not hardware integration.
//! No allocation, MMIO, locks, EOI, or CPU context switching.
//! Hardware callers must separately validate CR3/TSS/IRET/FPU ownership.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State { Empty, Ready, Running, Exited }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { InvalidPid, DuplicatePid, WrongState, NoRunnable, Overflow }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot { pub pid: u64, pub state: State, pub ticks: u64 }
impl Slot { const EMPTY: Self = Self { pid: 0, state: State::Empty, ticks: 0 }; }

/// All error paths preserve the ledger unchanged. At most one RUNNING slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundRobin { slots: [Slot; 2], active: Option<usize>, switches: u64 }
impl RoundRobin {
    pub const fn new() -> Self { Self { slots: [Slot::EMPTY; 2], active: None, switches: 0 } }
    pub fn slots(&self) -> [Slot; 2] { self.slots }
    pub fn running(&self) -> Option<u64> { self.active.map(|i| self.slots[i].pid) }
    pub fn switches(&self) -> u64 { self.switches }
    pub fn admit(&mut self, pid: u64) -> Result<(), Error> {
        if pid == 0 { return Err(Error::InvalidPid); }
        if self.slots.iter().any(|s| s.pid == pid) { return Err(Error::DuplicatePid); }
        let i = self.slots.iter().position(|s| s.state == State::Empty).ok_or(Error::WrongState)?;
        self.slots[i] = Slot { pid, state: State::Ready, ticks: 0 };
        Ok(())
    }
    pub fn start(&mut self, pid: u64) -> Result<(), Error> {
        if self.active.is_some() { return Err(Error::WrongState); }
        let i = self.slots.iter().position(|s| s.pid == pid && s.state == State::Ready).ok_or(Error::WrongState)?;
        self.slots[i].state = State::Running; self.active = Some(i); Ok(())
    }
    /// Choose peer on an already validated timer tick, never on a yield.
    pub fn timer_tick(&mut self, interrupted_pid: u64) -> Result<u64, Error> {
        let i = self.active.ok_or(Error::NoRunnable)?;
        if self.slots[i].pid != interrupted_pid || self.slots[i].state != State::Running { return Err(Error::WrongState); }
        let ticks = self.slots[i].ticks.checked_add(1).ok_or(Error::Overflow)?;
        let j = 1 - i;
        let rotate = self.slots[j].state == State::Ready;
        let switches = if rotate { self.switches.checked_add(1).ok_or(Error::Overflow)? } else { self.switches };
        self.slots[i].ticks = ticks;
        if rotate {
            self.slots[i].state = State::Ready;
            self.slots[j].state = State::Running;
            self.active = Some(j);
        }
        self.switches = switches;
        Ok(self.slots[self.active.unwrap()].pid)
    }
    pub fn exit(&mut self, pid: u64) -> Result<Option<u64>, Error> {
        let i = self.active.ok_or(Error::NoRunnable)?;
        if self.slots[i].pid != pid || self.slots[i].state != State::Running { return Err(Error::WrongState); }
        let j = 1 - i;
        let next = (self.slots[j].state == State::Ready).then_some(j);
        self.slots[i].state = State::Exited;
        self.active = next;
        if let Some(j) = next { self.slots[j].state = State::Running; }
        Ok(self.running())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eight_timer_policy_rotations_without_yield() {
        let mut q=RoundRobin::new(); q.admit(11).unwrap(); q.admit(22).unwrap(); q.start(11).unwrap();
        for n in 0..8 { let src=if n%2==0 {11} else {22}; assert_eq!(q.timer_tick(src),Ok(if src==11 {22} else {11})); }
        assert_eq!(q.switches(),8); assert_eq!(q.running(),Some(11));
        assert_eq!(q.slots()[0].ticks,4); assert_eq!(q.slots()[1].ticks,4);
        assert_eq!(q.exit(11),Ok(Some(22))); assert_eq!(q.exit(22),Ok(None));
    }
    #[test]
    fn reject_wrong_owner_and_duplicates_without_mutation() {
        let mut q=RoundRobin::new(); assert_eq!(q.admit(0),Err(Error::InvalidPid));
        q.admit(11).unwrap(); assert_eq!(q.admit(11),Err(Error::DuplicatePid)); q.admit(22).unwrap(); q.start(11).unwrap();
        let before=q; assert_eq!(q.timer_tick(22),Err(Error::WrongState)); assert_eq!(q,before);
        assert_eq!(q.start(22),Err(Error::WrongState)); assert_eq!(q,before);
        assert_eq!(q.exit(22),Err(Error::WrongState)); assert_eq!(q,before);
    }
    #[test]
    fn lone_runnable_then_peer_arrives() {
        let mut q=RoundRobin::new(); q.admit(1).unwrap(); q.start(1).unwrap();
        for _ in 0..3 { assert_eq!(q.timer_tick(1),Ok(1)); }
        assert_eq!(q.switches(),0); q.admit(2).unwrap(); assert_eq!(q.timer_tick(1),Ok(2));
        assert_eq!(q.exit(2),Ok(Some(1))); assert_eq!(q.exit(1),Ok(None));
    }
    #[test]
    fn exited_pid_is_stale() {
        let mut q=RoundRobin::new(); q.admit(1).unwrap(); q.admit(2).unwrap(); q.start(1).unwrap();
        q.exit(1).unwrap(); let before=q; assert_eq!(q.timer_tick(1),Err(Error::WrongState)); assert_eq!(q,before);
        assert_eq!(q.admit(1),Err(Error::DuplicatePid)); assert_eq!(q.start(1),Err(Error::WrongState));
    }
}
