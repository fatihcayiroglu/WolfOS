//! Bounded, allocation-free WolfOS userspace process ownership ledger.
//!
//! Each state transition is explicit: EMPTY -> READY -> RUNNING -> EXITED
//! -> REAPED. A PID is a monotonically increasing generation; a reaped
//! PID cannot be resurrected or double-freed. Physical frames are unique,
//! page-aligned, owned EXCLUSIVELY by one process, and may be released only
//! after its private CR3 has been deactivated. Reap returns the *exact*
//! owned frame set for the caller to release through the real PMM.
//!
//! This is NOT yet a multitasking scheduler, process table with multiple
//! concurrent entries, or user fault handler. One record models a single
//! active process; later work must add address-space ownership, scheduling,
//! capability handles, real kernel stack management and process creation.
//!
//! A tiny bounded lock guards this single record in the feature-isolated
//! QEMU test (interrupts disabled, single BSP). On contention it fails
//! closed instead of hanging indefinitely or permitting aliasing.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

pub const PAGE: u64 = 4096;
const MAX_PHYSICAL: u64 = 1 << 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Empty, Ready, Running, Exited, Reaped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessError {
    InvalidPid, StalePid, InvalidFrame, DuplicateFrame, InvalidRoot,
    AlreadyOwned, WrongState, WrongAddressSpace, ExitNotZero,
    ActiveCr3, LockBusy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessRecord<const N: usize> {
    pub pid: u64,
    pub state: ProcessState,
    pub cr3_root: u64,
    pub frames: [u64; N],
    pub exit_status: u32,
}
impl<const N: usize> ProcessRecord<N> {
    pub const fn empty() -> Self {
        Self {
            pid: 0, state: ProcessState::Empty, cr3_root: 0,
            frames: [0; N], exit_status: 0,
        }
    }

    /// Caller has just allocated all frames from its OWN PMM lease.
    /// On validation failure, the ledger is unchanged. The caller must
    /// dispose of its tentative PMM lease separately.
    pub fn admit(&mut self, pid: u64, root: u64, frames: [u64; N])
        -> Result<(), ProcessError>
    {
        if pid == 0 { return Err(ProcessError::InvalidPid) }
        if self.state != ProcessState::Empty && self.state != ProcessState::Reaped {
            return Err(ProcessError::AlreadyOwned);
        }
        if pid <= self.pid { return Err(ProcessError::StalePid) }
        if N == 0 || root != frames[0] { return Err(ProcessError::InvalidRoot) }
        for (i, frame) in frames.iter().copied().enumerate() {
            if frame == 0 || frame & (PAGE - 1) != 0 || frame >= MAX_PHYSICAL {
                return Err(ProcessError::InvalidFrame)
            }
            if frames[..i].contains(&frame) {
                return Err(ProcessError::DuplicateFrame)
            }
        }
        *self = Self {
            pid, state: ProcessState::Ready, cr3_root: root,
            frames, exit_status: 0,
        };
        Ok(())
    }

    /// Called ONLY once the hardware CR3 has switched into this root.
    pub fn mark_running(&mut self, pid: u64, active_cr3: u64)
        -> Result<(), ProcessError>
    {
        self.identity(pid)?;
        if self.state != ProcessState::Ready {
            return Err(ProcessError::WrongState)
        }
        if active_cr3 != self.cr3_root {
            return Err(ProcessError::WrongAddressSpace)
        }
        self.state = ProcessState::Running;
        Ok(())
    }

    /// Suspend a currently RUNNING user process only after a verified
    /// CPL3-to-CPL0 trap, while its real CR3 remains active. The saved
    /// full GPR/IRET and FPU context must already be retained by caller.
    /// No resource is released, and the monotonic PID identity is intact.
    pub fn park_running(&mut self, pid: u64, active_cr3: u64)
        -> Result<(), ProcessError>
    {
        self.identity(pid)?;
        if self.state != ProcessState::Running {
            return Err(ProcessError::WrongState)
        }
        if active_cr3 != self.cr3_root {
            return Err(ProcessError::WrongAddressSpace)
        }
        self.state = ProcessState::Ready;
        Ok(())
    }

    /// Called in kernel mode on a REAL user EXIT(0) trap.
    pub fn exit_zero(&mut self, pid: u64, active_cr3: u64)
        -> Result<(), ProcessError>
    {
        self.identity(pid)?;
        if self.state != ProcessState::Running {
            return Err(ProcessError::WrongState)
        }
        if active_cr3 != self.cr3_root {
            return Err(ProcessError::WrongAddressSpace)
        }
        self.state = ProcessState::Exited;
        self.exit_status = 0;
        Ok(())
    }

    /// Roll back a RESERVED/READY process before any user execution.
    /// A caller must supply the actual hardware CR3, already verified to
    /// differ from the tentative root. Returned frames remain the caller's
    /// responsibility and must be released exactly once through PMM.
    pub fn cancel_ready(&mut self, pid: u64, active_cr3: u64)
        -> Result<[u64; N], ProcessError>
    {
        self.identity(pid)?;
        if self.state != ProcessState::Ready {
            return Err(ProcessError::WrongState)
        }
        if active_cr3 == 0 || active_cr3 == self.cr3_root {
            return Err(ProcessError::ActiveCr3)
        }
        let owned = self.frames;
        self.frames = [0; N];
        self.cr3_root = 0;
        self.state = ProcessState::Reaped;
        Ok(owned)
    }

    /// Release authorization requires: correct PID, exited state and
    /// restored CR3 not equal to the private root. A successful reap
    /// marks ownership relinquished exactly once before any caller frees
    /// physical pages. The process generation remains to reject stale IDs.
    pub fn reap(&mut self, pid: u64, active_cr3: u64)
        -> Result<[u64; N], ProcessError>
    {
        self.identity(pid)?;
        if self.state != ProcessState::Exited {
            return Err(ProcessError::WrongState)
        }
        if active_cr3 == self.cr3_root || active_cr3 == 0 {
            return Err(ProcessError::ActiveCr3)
        }
        if self.exit_status != 0 { return Err(ProcessError::ExitNotZero) }
        let owned = self.frames;
        self.frames = [0; N];
        self.cr3_root = 0;
        self.state = ProcessState::Reaped;
        Ok(owned)
    }

    fn identity(&self, pid: u64) -> Result<(), ProcessError> {
        if pid == 0 { return Err(ProcessError::InvalidPid) }
        if pid != self.pid { return Err(ProcessError::StalePid) }
        Ok(())
    }
}

pub struct ProcessCell<const N: usize> {
    lock: AtomicBool,
    record: UnsafeCell<ProcessRecord<N>>,
}
// SAFETY: record is only accessed after acquiring the AtomicBool lock;
// the guard releases on all ordinary exits, no bare reference escapes.
unsafe impl<const N: usize> Sync for ProcessCell<N> {}

struct Unlock<'a>(&'a AtomicBool);
impl Drop for Unlock<'_> {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

impl<const N: usize> ProcessCell<N> {
    pub const fn new() -> Self {
        Self { lock: AtomicBool::new(false),
            record: UnsafeCell::new(ProcessRecord::empty()) }
    }
    pub fn with<R>(&self, f: impl FnOnce(&mut ProcessRecord<N>) -> R)
        -> Result<R, ProcessError>
    {
        if self.lock.compare_exchange(
            false, true, Ordering::Acquire, Ordering::Relaxed,
        ).is_err() {
            return Err(ProcessError::LockBusy);
        }
        let _unlock = Unlock(&self.lock);
        // SAFETY: exclusive AtomicBool lock acquired, not reentrant; the
        // guard runs even if a test closure unwinds on host.
        Ok(f(unsafe { &mut *self.record.get() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owned() -> [u64; 7] {
        [0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000]
    }

    #[test]
    fn actual_active_cr3_required_for_running_to_ready_and_resume() {
        let mut p=ProcessRecord::<7>::empty();
        p.admit(1,owned()[0],owned()).unwrap();
        assert_eq!(p.park_running(1,owned()[0]),Err(ProcessError::WrongState));
        p.mark_running(1,owned()[0]).unwrap();
        assert_eq!(p.park_running(2,owned()[0]),Err(ProcessError::StalePid));
        assert_eq!(p.park_running(1,0x9000),Err(ProcessError::WrongAddressSpace));
        assert_eq!(p.state,ProcessState::Running);
        p.park_running(1,owned()[0]).unwrap();
        assert_eq!(p.state,ProcessState::Ready);
        assert_eq!(p.reap(1,0x9000),Err(ProcessError::WrongState));
        p.mark_running(1,owned()[0]).unwrap();
        p.exit_zero(1,owned()[0]).unwrap();
        assert_eq!(p.park_running(1,owned()[0]),Err(ProcessError::WrongState));
    }
    #[test]
    fn complete_two_sequential_processes_and_no_duplicate_reap() {
        let mut p = ProcessRecord::<7>::empty();
        for pid in [1, 2] {
            p.admit(pid, owned()[0], owned()).unwrap();
            assert_eq!(p.state, ProcessState::Ready);
            p.mark_running(pid, owned()[0]).unwrap();
            p.exit_zero(pid, owned()[0]).unwrap();
            assert_eq!(p.reap(pid, 0x9000), Ok(owned()));
            assert_eq!(p.state, ProcessState::Reaped);
            assert_eq!(p.frames, [0; 7]);
            assert_eq!(p.reap(pid, 0x9000), Err(ProcessError::WrongState));
        }
        assert_eq!(p.admit(2, 0x1000, owned()), Err(ProcessError::StalePid));
        assert_eq!(p.admit(1, 0x1000, owned()), Err(ProcessError::StalePid));
    }
    #[test]
    fn rejected_tentative_resources_do_not_modify_the_ledger() {
        let mut p = ProcessRecord::<7>::empty();
        for frames in {
            let mut f = owned();
            f[6] = f[5];
            [f, { let mut a = owned(); a[3] = 1; a },
                { let mut a = owned(); a[4] = 0; a },
                { let mut a = owned(); a[2] = 1 << 52; a }]
        } {
            let original = p;
            assert!(p.admit(1, 0x1000, frames).is_err());
            assert_eq!(p, original);
        }
        assert_eq!(p.admit(0, 0x1000, owned()), Err(ProcessError::InvalidPid));
        assert_eq!(p.admit(1, 0x8000, owned()), Err(ProcessError::InvalidRoot));
        assert_eq!(p, ProcessRecord::empty());
    }

    #[test]
    fn active_root_never_freed_and_transitions_fail_closed() {
        let mut p = ProcessRecord::<7>::empty();
        p.admit(1, 0x1000, owned()).unwrap();
        let before = p;
        assert_eq!(p.exit_zero(1, 0x1000), Err(ProcessError::WrongState));
        assert_eq!(p.mark_running(2, 0x1000), Err(ProcessError::StalePid));
        assert_eq!(p.mark_running(1, 0x9000), Err(ProcessError::WrongAddressSpace));
        assert_eq!(p, before);
        p.mark_running(1, 0x1000).unwrap();
        assert_eq!(p.admit(2, 0x1000, owned()), Err(ProcessError::AlreadyOwned));
        assert_eq!(p.reap(1, 0x9000), Err(ProcessError::WrongState));
        assert_eq!(p.exit_zero(1, 0x9000), Err(ProcessError::WrongAddressSpace));
        p.exit_zero(1, 0x1000).unwrap();
        assert_eq!(p.reap(1, 0x1000), Err(ProcessError::ActiveCr3));
        assert_eq!(p.reap(1, 0), Err(ProcessError::ActiveCr3));
        assert_eq!(p.state, ProcessState::Exited);
        assert_eq!(p.reap(1, 0x9000), Ok(owned()));
    }

    #[test]
    fn failed_ready_admission_can_cancel_only_when_root_is_inactive() {
        let mut p = ProcessRecord::<7>::empty();
        p.admit(11, owned()[0], owned()).unwrap();
        let snapshot = p;
        assert_eq!(p.cancel_ready(11, 0), Err(ProcessError::ActiveCr3));
        assert_eq!(p.cancel_ready(11, owned()[0]), Err(ProcessError::ActiveCr3));
        assert_eq!(p.cancel_ready(12, 0x9000), Err(ProcessError::StalePid));
        assert_eq!(p, snapshot);
        assert_eq!(p.cancel_ready(11, 0x9000), Ok(owned()));
        assert_eq!(p.state, ProcessState::Reaped);
        assert_eq!(p.frames, [0; 7]);
        assert_eq!(p.cancel_ready(11, 0x9000), Err(ProcessError::WrongState));
        assert_eq!(p.reap(11, 0x9000), Err(ProcessError::WrongState));
        p.admit(12, owned()[0], owned()).unwrap();
        p.mark_running(12, owned()[0]).unwrap();
        assert_eq!(p.cancel_ready(12, 0x9000), Err(ProcessError::WrongState));
    }

    #[test]
    fn process_cell_carries_state_and_rejects_reentrancy() {
        let cell = ProcessCell::<7>::new();
        cell.with(|p| {
            p.admit(1, 0x1000, owned()).unwrap();
            assert_eq!(cell.with(|_| ()), Err(ProcessError::LockBusy));
        }).unwrap();
        assert_eq!(cell.with(|p| p.state), Ok(ProcessState::Ready));
    }

    #[test]
    fn lock_recovers_after_host_unwind() {
        let cell = ProcessCell::<7>::new();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cell.with(|_| panic!("test guard unwind")).ok();
        }));
        assert_eq!(cell.with(|p| p.state), Ok(ProcessState::Empty));
    }
}
