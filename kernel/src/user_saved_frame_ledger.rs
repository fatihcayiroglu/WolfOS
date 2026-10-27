//! Exact copied GPR/IRET snapshots for the isolated BSP Ring3 switch path.
//!
//! This is a second, non-owning check of the real interrupt-stack bytes,
//! not an address-space owner or proof of an actual CPL3 interrupt. The
//! caller authenticates CR3, TSS.RSP0, FX and hardware trap provenance
//! before capture, and pins all stack pages until after retirement.
#[cfg(test)]
#[path = "user_syscall_abi.rs"]
mod standalone_abi;
#[cfg(test)]
use standalone_abi::{UserSyscallFrame, FRAME_BYTES};
#[cfg(not(test))]
use crate::user_syscall_abi::{UserSyscallFrame, FRAME_BYTES};

const KERNEL_LOW: u64 = 0xffff_8000_0000_0000;
const PHYSICAL_LIMIT: u64 = 1 << 52;
const STACK_BYTES: u64 = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub pid: u64,
    pub stack_generation: u64,
    pub root: u64,
    pub stack_bottom: u64,
    pub stack_top: u64,
    pub frame_at: u64,
}

impl Binding {
    fn valid(self) -> bool {
        self.pid != 0 && self.stack_generation != 0
            && self.root != 0 && self.root < PHYSICAL_LIMIT
            && self.root & 4095 == 0
            && self.stack_bottom >= KERNEL_LOW
            && self.stack_bottom & 4095 == 0
            && self.stack_bottom.checked_add(STACK_BYTES) == Some(self.stack_top)
            && self.stack_top & 15 == 0
            && self.stack_top.checked_sub(FRAME_BYTES as u64) == Some(self.frame_at)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { InvalidBinding, Occupied, Missing, StaleBinding, FrameChanged }

#[derive(Clone, Copy)]
struct Saved { binding: Binding, frame: UserSyscallFrame }

pub struct SavedFrameLedger<const SLOTS: usize> {
    entries: [Option<Saved>; SLOTS],
}

impl<const SLOTS: usize> SavedFrameLedger<SLOTS> {
    pub const fn new() -> Self { Self { entries: [None; SLOTS] } }

    /// Snapshot a kernel-created IRET frame before the first real CPL3 run.
    pub fn record_bootstrap(&mut self, slot: usize, binding: Binding,
                            frame: UserSyscallFrame) -> Result<(), Error> {
        if !binding.valid() { return Err(Error::InvalidBinding) }
        let entry = self.entries.get_mut(slot).ok_or(Error::InvalidBinding)?;
        if entry.is_some() { return Err(Error::Occupied) }
        *entry = Some(Saved { binding, frame });
        Ok(())
    }

    /// Copy an already authenticated real trap's complete 15 GPR + IRET
    /// words. PID1 may have no bootstrap record: its first frame is created
    /// by the Ring3 entry assembly, not by an earlier saved-stack pointer.
    pub fn capture_authenticated_trap(&mut self, slot: usize, binding: Binding,
                                      frame: UserSyscallFrame) -> Result<(), Error> {
        if !binding.valid() { return Err(Error::InvalidBinding) }
        let entry = self.entries.get_mut(slot).ok_or(Error::InvalidBinding)?;
        if entry.is_some_and(|old| old.binding != binding) {
            return Err(Error::StaleBinding)
        }
        *entry = Some(Saved { binding, frame });
        Ok(())
    }

    /// Refuse an altered saved pointer or ANY changed GPR/IRET word before
    /// a switch to this still-live PID's private CR3 and FXSAVE image.
    pub fn verify_resume(&self, slot: usize, binding: Binding,
                         observed: &UserSyscallFrame) -> Result<(), Error> {
        if !binding.valid() { return Err(Error::InvalidBinding) }
        let saved = self.entries.get(slot).ok_or(Error::InvalidBinding)?
            .as_ref().ok_or(Error::Missing)?;
        if saved.binding != binding { return Err(Error::StaleBinding) }
        if saved.frame != *observed { return Err(Error::FrameChanged) }
        Ok(())
    }

    /// Make exit irreversible in this ledger before frame reclaim can start.
    pub fn revoke(&mut self, slot: usize, binding: Binding) -> Result<(), Error> {
        let entry = self.entries.get_mut(slot).ok_or(Error::InvalidBinding)?;
        if entry.as_ref().is_none_or(|old| old.binding != binding) {
            return Err(Error::StaleBinding)
        }
        *entry = None;
        Ok(())
    }

    pub fn occupied(&self) -> usize {
        self.entries.iter().filter(|entry| entry.is_some()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(pid: u64) -> Binding {
        Binding {
            pid, stack_generation: 1, root: pid * 0x1000,
            stack_bottom: 0xffff_d000_0000_0000 + pid * 0x10000,
            stack_top: 0xffff_d000_0000_4000 + pid * 0x10000,
            frame_at: 0xffff_d000_0000_4000 + pid * 0x10000 - FRAME_BYTES as u64,
        }
    }

    #[test]
    fn bootstrap_capture_resume_and_revoke_exact_hardware_image() {
        let mut ledger = SavedFrameLedger::<2>::new();
        let initial = UserSyscallFrame::default();
        ledger.record_bootstrap(1, binding(2), initial).unwrap();
        assert_eq!(ledger.verify_resume(1, binding(2), &initial), Ok(()));
        let mut captured = initial;
        captured.registers.r12 = 2;
        captured.registers.rax = 0;
        captured.hardware.rflags = 0x202;
        ledger.capture_authenticated_trap(1, binding(2), captured).unwrap();
        assert_eq!(ledger.verify_resume(1, binding(2), &initial), Err(Error::FrameChanged));
        assert_eq!(ledger.verify_resume(1, binding(2), &captured), Ok(()));
        ledger.capture_authenticated_trap(0, binding(1), captured).unwrap();
        assert_eq!(ledger.occupied(), 2);
        ledger.revoke(1, binding(2)).unwrap();
        assert_eq!(ledger.verify_resume(1, binding(2), &captured), Err(Error::Missing));
        ledger.revoke(0, binding(1)).unwrap();
        assert_eq!(ledger.occupied(), 0);
    }

    #[test]
    fn wrong_generation_owner_root_stack_or_pointer_never_mutates_snapshot() {
        let mut ledger = SavedFrameLedger::<1>::new();
        let frame = UserSyscallFrame::default();
        ledger.record_bootstrap(0, binding(1), frame).unwrap();
        assert_eq!(ledger.record_bootstrap(0, binding(1), frame), Err(Error::Occupied));
        let mut stale = binding(1);
        stale.pid = 2;
        assert_eq!(ledger.capture_authenticated_trap(0, stale, frame), Err(Error::StaleBinding));
        stale = Binding { stack_generation: 2, ..binding(1) };
        assert_eq!(ledger.verify_resume(0, stale, &frame), Err(Error::StaleBinding));
        for invalid in [
            Binding { root: 0, ..binding(1) },
            Binding { root: 0x1001, ..binding(1) },
            Binding { stack_top: binding(1).stack_top - 16, ..binding(1) },
            Binding { frame_at: binding(1).frame_at - 8, ..binding(1) },
        ] {
            assert_eq!(ledger.capture_authenticated_trap(0, invalid, frame), Err(Error::InvalidBinding));
        }
        assert_eq!(ledger.revoke(0, binding(2)), Err(Error::StaleBinding));
        assert_eq!(ledger.verify_resume(0, binding(1), &frame), Ok(()));
    }

    #[test]
    fn each_register_and_iret_word_is_bound_to_the_saved_copy() {
        let mut ledger = SavedFrameLedger::<1>::new();
        let original = UserSyscallFrame::default();
        ledger.capture_authenticated_trap(0, binding(1), original).unwrap();
        let mut changed = original;
        changed.registers.r15 = 7;
        assert_eq!(ledger.verify_resume(0, binding(1), &changed), Err(Error::FrameChanged));
        changed = original;
        changed.registers.r8 = 9;
        assert_eq!(ledger.verify_resume(0, binding(1), &changed), Err(Error::FrameChanged));
        changed = original;
        changed.hardware.rip = 0x401000;
        assert_eq!(ledger.verify_resume(0, binding(1), &changed), Err(Error::FrameChanged));
        changed = original;
        changed.hardware.ss = 0x23;
        assert_eq!(ledger.verify_resume(0, binding(1), &changed), Err(Error::FrameChanged));
        assert_eq!(ledger.verify_resume(0, binding(1), &original), Ok(()));
    }
}
