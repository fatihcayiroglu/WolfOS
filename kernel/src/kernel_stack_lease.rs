//! PMM-backed kernel stack ownership metadata for distinct user PIDs.
//!
//! This is NOT a physical frame allocator or a page-table guard mapper.
//! Caller PMM-allocates four aligned *physically consecutive* 4-KiB frames;
//! they are already virtually contiguous through the bootloader HHDM.
//! We bind the exact lease to one PID, detect cross-PID aliases, and allow
//! release only after a caller-proven quiescent supervisor checkpoint.
//! A canary is an overrun DETECTOR, NOT an unmapped hardware guard page.
//! The actual CPU's RSP/TSS.RSP0 is never modified by this module.
pub const PAGE_BYTES: u64 = 4096;
pub const STACK_PAGES: usize = 4;
pub const STACK_BYTES: u64 = STACK_PAGES as u64 * PAGE_BYTES;
const HIGH_HALF_START: u64 = 0xffff_8000_0000_0000;
const PHYSICAL_LIMIT: u64 = 1 << 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackError {
    InvalidPid, InvalidFrame, NotContiguous, InvalidHhdm,
    InvalidRange, DuplicatePid, FrameAlias, VirtualOverlap,
    Full, InvalidSlot, StaleHandle, NotLive, NotQuiescent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackHandle {
    pub slot: usize,
    pub generation: u64,
    pub pid: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackLease {
    pub handle: StackHandle,
    pub frames: [u64; STACK_PAGES],
    pub bottom: u64,
    pub top: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetirementGate {
    pub interrupts_disabled: bool,
    pub scheduler_stopped: bool,
    pub on_independent_supervisor_stack: bool,
    pub no_borrowed_trap_frame: bool,
    pub owning_pid_no_longer_live: bool,
    pub owning_user_cr3_inactive: bool,
}

impl RetirementGate {
    pub fn safe(self) -> bool {
        self.interrupts_disabled && self.scheduler_stopped
            && self.on_independent_supervisor_stack
            && self.no_borrowed_trap_frame
            && self.owning_pid_no_longer_live
            && self.owning_user_cr3_inactive
    }
}

#[derive(Clone, Copy)]
struct Slot {
    generation: u64,
    lease: Option<StackLease>,
}
impl Slot {
    const fn empty() -> Self { Self { generation: 0, lease: None } }
}

pub struct StackLeaseTable<const N: usize> {
    slots: [Slot; N],
}
impl<const N: usize> StackLeaseTable<N> {
    pub const fn new() -> Self {
        Self { slots: [const { Slot::empty() }; N] }
    }

    pub fn occupied(&self) -> usize {
        self.slots.iter().filter(|e| e.lease.is_some()).count()
    }

    /// Completely preflight the externally-owned frame set before inserting.
    /// The caller keeps PMM ownership on every refusal and MUST release the
    /// tentative frames; no partial state or generation number is consumed.
    pub fn admit(
        &mut self, pid: u64, frames: [u64; STACK_PAGES], hhdm: u64,
    ) -> Result<StackLease, StackError> {
        if pid == 0 { return Err(StackError::InvalidPid) }
        if frames.iter().any(|f| *f == 0 || *f & (PAGE_BYTES - 1) != 0
            || *f >= PHYSICAL_LIMIT) {
            return Err(StackError::InvalidFrame)
        }
        for i in 1..STACK_PAGES {
            if frames[i-1].checked_add(PAGE_BYTES) != Some(frames[i]) {
                return Err(StackError::NotContiguous)
            }
        }
        if hhdm < HIGH_HALF_START || hhdm & (PAGE_BYTES - 1) != 0 {
            return Err(StackError::InvalidHhdm)
        }
        let bottom = hhdm.checked_add(frames[0]).ok_or(StackError::InvalidRange)?;
        let top = bottom.checked_add(STACK_BYTES).ok_or(StackError::InvalidRange)?;
        if bottom < HIGH_HALF_START || bottom & 15 != 0 || top & 15 != 0
            || top <= bottom {
            return Err(StackError::InvalidRange)
        }
        if self.slots.iter().filter_map(|slot| slot.lease)
            .any(|e| e.handle.pid == pid) {
            return Err(StackError::DuplicatePid)
        }
        if self.slots.iter().filter_map(|slot| slot.lease)
            .any(|e| frames.iter().any(|p| e.frames.contains(p))) {
            return Err(StackError::FrameAlias)
        }
        if self.slots.iter().filter_map(|slot| slot.lease)
            .any(|e| bottom < e.top && e.bottom < top) {
            return Err(StackError::VirtualOverlap)
        }
        let (index, slot) = self.slots.iter_mut().enumerate()
            .find(|(_, e)| e.lease.is_none()).ok_or(StackError::Full)?;
        let generation = slot.generation.checked_add(1)
            .ok_or(StackError::StaleHandle)?;
        let lease = StackLease {
            handle: StackHandle { slot: index, generation, pid },
            frames, bottom, top,
        };
        slot.generation = generation;
        slot.lease = Some(lease);
        Ok(lease)
    }

    pub fn inspect(&self, h: StackHandle) -> Result<StackLease, StackError> {
        let slot = self.slots.get(h.slot).ok_or(StackError::InvalidSlot)?;
        if slot.generation != h.generation || h.generation == 0 {
            return Err(StackError::StaleHandle)
        }
        let lease = slot.lease.ok_or(StackError::NotLive)?;
        if lease.handle != h { return Err(StackError::StaleHandle) }
        Ok(lease)
    }

    /// Metadata release ONLY. The caller verifies the real quiescence
    /// evidence before calling and then frees the returned EXACT frames via
    /// PMM. Never call on the currently executing kernel RSP0 stack.
    pub fn retire(
        &mut self, h: StackHandle, gate: RetirementGate,
    ) -> Result<[u64; STACK_PAGES], StackError> {
        let lease = self.inspect(h)?;
        if !gate.safe() { return Err(StackError::NotQuiescent) }
        self.slots[h.slot].lease = None;
        Ok(lease.frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HHDM: u64 = 0xffff_8000_0000_0000;
    fn pages(base: u64) -> [u64;STACK_PAGES] {
        [base,base+PAGE_BYTES,base+2*PAGE_BYTES,base+3*PAGE_BYTES]
    }
    fn gate() -> RetirementGate {
        RetirementGate {
            interrupts_disabled: true, scheduler_stopped: true,
            on_independent_supervisor_stack: true,
            no_borrowed_trap_frame: true, owning_pid_no_longer_live: true,
            owning_user_cr3_inactive: true,
        }
    }
    #[test]
    fn pids_own_separate_contiguous_high_half_stacks() {
        let mut t=StackLeaseTable::<2>::new();
        let a=t.admit(1,pages(0x1000),HHDM).unwrap();
        let b=t.admit(2,pages(0x10000),HHDM).unwrap();
        assert_eq!(t.occupied(),2);
        assert_eq!((a.bottom,a.top),(HHDM+0x1000,HHDM+0x5000));
        assert!(a.top<=b.bottom);
        assert_eq!(t.inspect(a.handle),Ok(a));
        assert_eq!(t.admit(3,pages(0x30000),HHDM),Err(StackError::Full));
    }
    #[test]
    fn admission_checks_pid_pmm_alias_and_atomic_no_mutation() {
        let mut t=StackLeaseTable::<2>::new();
        let a=t.admit(1,pages(0x1000),HHDM).unwrap();
        let invalid=[
            (0,pages(0x9000),HHDM,StackError::InvalidPid),
            (2,[0x9000,0xa000,0xc000,0xd000],HHDM,StackError::NotContiguous),
            (2,pages(0x5000),0,StackError::InvalidHhdm),
            (2,pages(0x9000),u64::MAX & !4095,StackError::InvalidRange),
            (2,pages(0x1000),HHDM,StackError::FrameAlias),
            (1,pages(0x9000),HHDM,StackError::DuplicatePid),
        ];
        for (pid,frames,offset,error) in invalid {
            assert_eq!(t.admit(pid,frames,offset),Err(error));
            assert_eq!(t.occupied(),1);
            assert_eq!(t.inspect(a.handle),Ok(a));
        }
    }
    #[test]
    fn refusing_live_stack_retirement_and_stale_token_after_reuse() {
        let mut t=StackLeaseTable::<1>::new();
        let a=t.admit(1,pages(0x1000),HHDM).unwrap();
        let mut g=gate();
        for n in 0..6 {
            g=gate();
            match n {
                0=>g.interrupts_disabled=false,
                1=>g.scheduler_stopped=false,
                2=>g.on_independent_supervisor_stack=false,
                3=>g.no_borrowed_trap_frame=false,
                4=>g.owning_pid_no_longer_live=false,
                _=>g.owning_user_cr3_inactive=false,
            }
            assert_eq!(t.retire(a.handle,g),Err(StackError::NotQuiescent));
        }
        assert_eq!(t.inspect(a.handle),Ok(a));
        assert_eq!(t.retire(a.handle,gate()),Ok(a.frames));
        assert_eq!(t.retire(a.handle,gate()),Err(StackError::NotLive));
        let b=t.admit(2,pages(0x1000),HHDM).unwrap();
        assert_eq!(b.handle.generation,a.handle.generation+1);
        assert_eq!(t.inspect(a.handle),Err(StackError::StaleHandle));
        assert_eq!(t.retire(a.handle,gate()),Err(StackError::StaleHandle));
        assert_eq!(t.retire(b.handle,gate()),Ok(b.frames));
        assert_eq!(t.occupied(),0);
    }
    #[test]
    fn refuses_invalid_alignment_physical_limits_and_zero_capacity() {
        let mut t=StackLeaseTable::<1>::new();
        assert_eq!(t.admit(1,[0,0x2000,0x3000,0x4000],HHDM),
            Err(StackError::InvalidFrame));
        assert_eq!(t.admit(1,[0x1001,0x2000,0x3000,0x4000],HHDM),
            Err(StackError::InvalidFrame));
        assert_eq!(t.admit(1,pages(0x1000),HHDM+1),
            Err(StackError::InvalidHhdm));
        assert_eq!(t.occupied(),0);
        let mut empty=StackLeaseTable::<0>::new();
        assert_eq!(empty.admit(1,pages(0x1000),HHDM),Err(StackError::Full));
    }
}
