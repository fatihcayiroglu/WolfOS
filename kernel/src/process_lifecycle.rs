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
    Empty, Ready, Running, Blocked, Exited, Reaped,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessError {
    InvalidPid, StalePid, InvalidFrame, DuplicateFrame, InvalidRoot,
    AlreadyOwned, WrongState, WrongAddressSpace,
    ActiveCr3, LockBusy, InvalidFrameCount, PartialLease,
}

/// A fixed-capacity PMM handoff with an exact, nonzero live prefix.
/// Only as_slice() frames may be returned to PMM; tail slots are padding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CountedFrames<const N: usize> {
    pub frames: [u64; N],
    pub count: usize,
}
impl<const N: usize> CountedFrames<N> {
    pub fn as_slice(&self) -> &[u64] { &self.frames[..self.count] }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessRecord<const N: usize> {
    pub pid: u64,
    pub state: ProcessState,
    pub cr3_root: u64,
    pub frames: [u64; N],
    pub frame_count: usize,
    pub exit_status: u32,
}
impl<const N: usize> ProcessRecord<N> {
    pub const fn empty() -> Self {
        Self {
            pid: 0, state: ProcessState::Empty, cr3_root: 0,
            frames: [0; N], frame_count: 0, exit_status: 0,
        }
    }

    /// Backwards-compatible, *full* PMM lease admission.
    pub fn admit(&mut self, pid: u64, root: u64, frames: [u64; N])
        -> Result<(), ProcessError>
    {
        self.admit_counted(pid, root, frames, N)
    }

    /// Publish only the actual PMM-owned prefix, never unused zero padding.
    /// Invalid count, malformed tail, alias or PID leaves the ledger unchanged.
    /// The caller retains tentative PMM ownership on every failed admission.
    pub fn admit_counted(&mut self, pid: u64, root: u64, frames: [u64; N],
                         count: usize) -> Result<(), ProcessError>
    {
        if pid == 0 { return Err(ProcessError::InvalidPid) }
        if self.state != ProcessState::Empty && self.state != ProcessState::Reaped {
            return Err(ProcessError::AlreadyOwned);
        }
        if pid <= self.pid { return Err(ProcessError::StalePid) }
        if N == 0 { return Err(ProcessError::InvalidRoot) }
        if count == 0 || count > N || frames[count..].iter().any(|&f| f != 0) {
            return Err(ProcessError::InvalidFrameCount)
        }
        if root != frames[0] { return Err(ProcessError::InvalidRoot) }
        for (i, frame) in frames[..count].iter().copied().enumerate() {
            if frame == 0 || frame & (PAGE - 1) != 0 || frame >= MAX_PHYSICAL {
                return Err(ProcessError::InvalidFrame)
            }
            if frames[..i].contains(&frame) {
                return Err(ProcessError::DuplicateFrame)
            }
        }
        *self = Self {
            pid, state: ProcessState::Ready, cr3_root: root,
            frames, frame_count: count, exit_status: 0,
        };
        Ok(())
    }

    pub fn owned_frames(&self) -> &[u64] { &self.frames[..self.frame_count] }

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

    /// Suspend a RUNNING user after the trusted trap has saved its full
    /// GPR/IRET and FPU state. The supplied root must be the actual user CR3.
    /// All private PMM frames and the PID generation remain owned; this does
    /// not yet implement a wait event or any hardware scheduling.
    pub fn block_running(&mut self, pid: u64, active_cr3: u64)
        -> Result<(), ProcessError>
    {
        self.identity(pid)?;
        if self.state != ProcessState::Running {
            return Err(ProcessError::WrongState)
        }
        if active_cr3 != self.cr3_root {
            return Err(ProcessError::WrongAddressSpace)
        }
        self.state = ProcessState::Blocked;
        Ok(())
    }

    /// Wake only an existing BLOCKED owner from a trusted kernel event.
    /// Caller must independently verify the actual supervisor CR3 and event;
    /// this metadata check alone cannot authenticate an interrupt/wakeup.
    pub fn wake_blocked(&mut self, pid: u64, supervisor_cr3: u64)
        -> Result<(), ProcessError>
    {
        self.identity(pid)?;
        if self.state != ProcessState::Blocked {
            return Err(ProcessError::WrongState)
        }
        if supervisor_cr3 == 0 || supervisor_cr3 & (PAGE - 1) != 0
            || supervisor_cr3 >= MAX_PHYSICAL || supervisor_cr3 == self.cr3_root
        { return Err(ProcessError::ActiveCr3) }
        self.state = ProcessState::Ready;
        Ok(())
    }

    /// Record a trusted, actual RUNNING user exit status while its own CR3
    /// remains active. This is ownership metadata only: the caller must
    /// authenticate the trap, quiesce saved contexts and switch back to a
    /// distinct supervisor CR3 before releasing physical pages.
    pub fn exit_with_status(&mut self, pid: u64, active_cr3: u64, status: u32)
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
        self.exit_status = status;
        Ok(())
    }

    /// Compatibility path for the existing hardware EXIT(0) syscall.
    pub fn exit_zero(&mut self, pid: u64, active_cr3: u64)
        -> Result<(), ProcessError>
    {
        self.exit_with_status(pid, active_cr3, 0)
    }

    /// Shared release authorization; the caller must independently prove
    /// actual hardware CR3 and quiescence before releasing PMM frames.
    fn release_allowed(&self, pid: u64, expected: ProcessState, supervisor_cr3: u64)
        -> Result<(), ProcessError>
    {
        self.identity(pid)?;
        if self.state != expected { return Err(ProcessError::WrongState) }
        if supervisor_cr3 == 0 || supervisor_cr3 & (PAGE - 1) != 0
            || supervisor_cr3 >= MAX_PHYSICAL || supervisor_cr3 == self.cr3_root
        { return Err(ProcessError::ActiveCr3) }
        Ok(())
    }

    fn relinquish(&mut self, pid: u64, expected: ProcessState, supervisor_cr3: u64)
        -> Result<CountedFrames<N>, ProcessError>
    {
        self.release_allowed(pid, expected, supervisor_cr3)?;
        let owned = CountedFrames { frames: self.frames, count: self.frame_count };
        self.frames = [0; N];
        self.frame_count = 0;
        self.cr3_root = 0;
        self.state = ProcessState::Reaped;
        Ok(owned)
    }

    /// Count-aware rollback of a never-running READY owner.
    pub fn cancel_ready_counted(&mut self, pid: u64, supervisor_cr3: u64)
        -> Result<CountedFrames<N>, ProcessError>
    {
        self.relinquish(pid, ProcessState::Ready, supervisor_cr3)
    }

    /// Count-aware teardown of a BLOCKED owner. Wait and CPU/FX references
    /// must already have been independently retired by the trusted caller.
    pub fn cancel_blocked_counted(&mut self, pid: u64, supervisor_cr3: u64)
        -> Result<CountedFrames<N>, ProcessError>
    {
        self.relinquish(pid, ProcessState::Blocked, supervisor_cr3)
    }

    /// Count-aware reap, preserving the actual process exit code.
    pub fn reap_with_status_counted(&mut self, pid: u64, supervisor_cr3: u64)
        -> Result<(u32, CountedFrames<N>), ProcessError>
    {
        let status = self.exit_status;
        let owned = self.relinquish(pid, ProcessState::Exited, supervisor_cr3)?;
        Ok((status, owned))
    }

    pub fn reap_counted(&mut self, pid: u64, supervisor_cr3: u64)
        -> Result<CountedFrames<N>, ProcessError>
    {
        self.reap_with_status_counted(pid, supervisor_cr3).map(|(_, lease)| lease)
    }

    /// Legacy full-array return is forbidden for a partial lease: code
    /// freeing all N entries would attempt to free zero-padded tail slots.
    pub fn cancel_ready(&mut self, pid: u64, supervisor_cr3: u64)
        -> Result<[u64; N], ProcessError>
    {
        self.release_allowed(pid, ProcessState::Ready, supervisor_cr3)?;
        if self.frame_count != N { return Err(ProcessError::PartialLease) }
        self.cancel_ready_counted(pid, supervisor_cr3).map(|lease| lease.frames)
    }

    pub fn cancel_blocked(&mut self, pid: u64, supervisor_cr3: u64)
        -> Result<[u64; N], ProcessError>
    {
        self.release_allowed(pid, ProcessState::Blocked, supervisor_cr3)?;
        if self.frame_count != N { return Err(ProcessError::PartialLease) }
        self.cancel_blocked_counted(pid, supervisor_cr3).map(|lease| lease.frames)
    }

    pub fn reap_with_status(&mut self, pid: u64, supervisor_cr3: u64)
        -> Result<(u32, [u64; N]), ProcessError>
    {
        self.release_allowed(pid, ProcessState::Exited, supervisor_cr3)?;
        if self.frame_count != N { return Err(ProcessError::PartialLease) }
        self.reap_with_status_counted(pid, supervisor_cr3)
            .map(|(status, lease)| (status, lease.frames))
    }

    pub fn reap(&mut self, pid: u64, supervisor_cr3: u64)
        -> Result<[u64; N], ProcessError>
    {
        self.reap_with_status(pid, supervisor_cr3).map(|(_, frames)| frames)
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
    fn nonzero_exit_records_status_and_releases_once_after_cr3_departure() {
        let mut p = ProcessRecord::<7>::empty();
        p.admit(41, owned()[0], owned()).unwrap();
        assert_eq!(p.exit_with_status(41, owned()[0], 42),
                   Err(ProcessError::WrongState));
        p.mark_running(41, owned()[0]).unwrap();
        let before = p;
        assert_eq!(p.exit_with_status(42, owned()[0], 42),
                   Err(ProcessError::StalePid));
        assert_eq!(p.exit_with_status(41, 0x9000, 42),
                   Err(ProcessError::WrongAddressSpace));
        assert_eq!(p, before); // no partial state or spurious status
        p.exit_with_status(41, owned()[0], 0x8000_002a).unwrap();
        assert_eq!(p.state, ProcessState::Exited);
        assert_eq!(p.exit_status, 0x8000_002a);
        assert_eq!(p.reap_with_status(41, owned()[0]),
                   Err(ProcessError::ActiveCr3));
        assert_eq!(p.reap_with_status(41, 0x9000),
                   Ok((0x8000_002a, owned())));
        assert_eq!(p.state, ProcessState::Reaped);
        assert_eq!(p.frames, [0; 7]);
        assert_eq!(p.reap(41, 0x9000), Err(ProcessError::WrongState));
        p.admit(42, owned()[0], owned()).unwrap();
        assert_eq!(p.exit_status, 0);
        assert_eq!(p.reap_with_status(41, 0x9000), Err(ProcessError::StalePid));
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
    fn release_requires_bounded_page_aligned_supervisor_cr3_without_mutation() {
        let mut ready = ProcessRecord::<7>::empty();
        ready.admit(41, owned()[0], owned()).unwrap();
        let ready_before = ready;
        for invalid in [0, owned()[0], 0x9001, MAX_PHYSICAL, u64::MAX] {
            assert_eq!(ready.cancel_ready(41, invalid), Err(ProcessError::ActiveCr3));
            assert_eq!(ready, ready_before, "failed cancellation must keep all PMM leases");
        }
        assert_eq!(ready.cancel_ready(41, 0x9000), Ok(owned()));
        assert_eq!(ready.state, ProcessState::Reaped);
        assert_eq!(ready.frames, [0; 7]);

        let mut exited = ProcessRecord::<7>::empty();
        exited.admit(42, owned()[0], owned()).unwrap();
        exited.mark_running(42, owned()[0]).unwrap();
        exited.exit_zero(42, owned()[0]).unwrap();
        let exited_before = exited;
        for invalid in [0, owned()[0], 0x9001, MAX_PHYSICAL, u64::MAX] {
            assert_eq!(exited.reap(42, invalid), Err(ProcessError::ActiveCr3));
            assert_eq!(exited, exited_before, "failed reap must keep all PMM leases");
        }
        assert_eq!(exited.reap(42, 0x9000), Ok(owned()));
        assert_eq!(exited.state, ProcessState::Reaped);
        assert_eq!(exited.frames, [0; 7]);
    }

    #[test]
    fn blocked_owner_retains_all_frames_and_requires_exact_wake() {
        let mut p = ProcessRecord::<7>::empty();
        p.admit(17, owned()[0], owned()).unwrap();
        p.mark_running(17, owned()[0]).unwrap();
        let before = p;
        assert_eq!(p.block_running(18, owned()[0]), Err(ProcessError::StalePid));
        assert_eq!(p.block_running(17, 0x9000), Err(ProcessError::WrongAddressSpace));
        assert_eq!(p, before);

        p.block_running(17, owned()[0]).unwrap();
        assert_eq!(p.state, ProcessState::Blocked);
        assert_eq!(p.frames, owned());
        assert_eq!(p.cr3_root, owned()[0]);
        let blocked = p;
        assert_eq!(p.block_running(17, owned()[0]), Err(ProcessError::WrongState));
        assert_eq!(p.mark_running(17, owned()[0]), Err(ProcessError::WrongState));
        assert_eq!(p.cancel_ready(17, 0x9000), Err(ProcessError::WrongState));
        assert_eq!(p.reap(17, 0x9000), Err(ProcessError::WrongState));
        assert_eq!(p.exit_zero(17, owned()[0]), Err(ProcessError::WrongState));
        assert_eq!(p.wake_blocked(18, 0x9000), Err(ProcessError::StalePid));
        for invalid_root in [0, owned()[0], 0x9001, 1 << 52] {
            assert_eq!(p.wake_blocked(17, invalid_root), Err(ProcessError::ActiveCr3));
        }
        assert_eq!(p, blocked, "rejected operations cannot free a sleeping PID");

        p.wake_blocked(17, 0x9000).unwrap();
        assert_eq!(p.state, ProcessState::Ready);
        let ready = p;
        assert_eq!(p.wake_blocked(17, 0x9000), Err(ProcessError::WrongState));
        assert_eq!(p, ready);
        p.mark_running(17, owned()[0]).unwrap();
        p.exit_zero(17, owned()[0]).unwrap();
        assert_eq!(p.reap(17, 0x9000), Ok(owned()));
        assert_eq!(p.frames, [0; 7]);
        assert_eq!(p.wake_blocked(17, 0x9000), Err(ProcessError::WrongState));
    }

    #[test]
    fn blocked_cancellation_retains_leases_on_refusal_and_never_releases_twice() {
        let mut p = ProcessRecord::<7>::empty();
        p.admit(17, owned()[0], owned()).unwrap();
        assert_eq!(p.cancel_blocked(17, 0x9000), Err(ProcessError::WrongState));
        p.mark_running(17, owned()[0]).unwrap();
        p.block_running(17, owned()[0]).unwrap();
        let blocked = p;
        assert_eq!(p.cancel_blocked(18, 0x9000), Err(ProcessError::StalePid));
        for wrong_root in [0, owned()[0], 0x9001, MAX_PHYSICAL, u64::MAX] {
            assert_eq!(p.cancel_blocked(17, wrong_root), Err(ProcessError::ActiveCr3));
        }
        assert_eq!(p, blocked);
        assert_eq!(p.cancel_blocked(17, 0x9000), Ok(owned()));
        assert_eq!(p.state, ProcessState::Reaped);
        assert_eq!(p.frames, [0; 7]);
        assert_eq!(p.cr3_root, 0);
        assert_eq!(p.cancel_blocked(17, 0x9000), Err(ProcessError::WrongState));
        assert_eq!(p.wake_blocked(17, 0x9000), Err(ProcessError::WrongState));
        assert_eq!(p.reap(17, 0x9000), Err(ProcessError::WrongState));
        p.admit(18, owned()[0], owned()).unwrap();
        assert_eq!(p.cancel_blocked(17, 0x9000), Err(ProcessError::StalePid));
    }

    fn padded(start: u64, count: usize) -> [u64; 9] {
        core::array::from_fn(|i| if i < count { start + i as u64 * PAGE } else { 0 })
    }

    #[test]
    fn counted_admission_rejects_invalid_lengths_and_tails_atomically() {
        let mut p = ProcessRecord::<9>::empty();
        let six = padded(0x1000, 6);
        for invalid_count in [0, 10, usize::MAX] {
            let before = p;
            assert_eq!(p.admit_counted(1, six[0], six, invalid_count),
                       Err(ProcessError::InvalidFrameCount));
            assert_eq!(p, before);
        }
        let mut nonzero_tail = six;
        nonzero_tail[6] = 0xa000;
        assert_eq!(p.admit_counted(1, six[0], nonzero_tail, 6),
                   Err(ProcessError::InvalidFrameCount));
        let mut duplicate = six;
        duplicate[5] = duplicate[3];
        assert_eq!(p.admit_counted(1, six[0], duplicate, 6),
                   Err(ProcessError::DuplicateFrame));
        let mut unaligned = six;
        unaligned[4] += 1;
        assert_eq!(p.admit_counted(1, six[0], unaligned, 6),
                   Err(ProcessError::InvalidFrame));
        assert_eq!(p, ProcessRecord::empty());
        p.admit_counted(1, six[0], six, 6).unwrap();
        assert_eq!(p.frame_count, 6);
        assert_eq!(p.owned_frames(), &six[..6]);
        assert_eq!(p.frames[6..], [0; 3]);
    }

    #[test]
    fn counted_ready_and_blocked_releases_never_return_padding_to_legacy_caller() {
        let mut p = ProcessRecord::<9>::empty();
        let six = padded(0x1000, 6);
        p.admit_counted(1, six[0], six, 6).unwrap();
        let before = p;
        assert_eq!(p.cancel_ready(1, 0x90000), Err(ProcessError::PartialLease));
        assert_eq!(p.cancel_ready_counted(1, six[0]), Err(ProcessError::ActiveCr3));
        assert_eq!(p, before);
        let returned = p.cancel_ready_counted(1, 0x90000).unwrap();
        assert_eq!(returned.count, 6);
        assert_eq!(returned.as_slice(), &six[..6]);
        assert_eq!(returned.frames[6..], [0; 3]);
        assert_eq!(p.state, ProcessState::Reaped);
        assert_eq!(p.frame_count, 0);
        assert_eq!(p.cancel_ready_counted(1, 0x90000), Err(ProcessError::WrongState));

        let eight = padded(0x10000, 8);
        p.admit_counted(2, eight[0], eight, 8).unwrap();
        p.mark_running(2, eight[0]).unwrap();
        p.block_running(2, eight[0]).unwrap();
        let blocked = p;
        assert_eq!(p.cancel_blocked(2, 0x90000), Err(ProcessError::PartialLease));
        assert_eq!(p.cancel_blocked_counted(2, eight[0]), Err(ProcessError::ActiveCr3));
        assert_eq!(p, blocked);
        let released = p.cancel_blocked_counted(2, 0x90000).unwrap();
        assert_eq!(released.as_slice(), &eight[..8]);
        assert_eq!(p.frame_count, 0);
        assert_eq!(p.cancel_blocked_counted(2, 0x90000), Err(ProcessError::WrongState));
    }

    #[test]
    fn counted_reap_preserves_status_and_full_legacy_lease_behavior() {
        let mut p = ProcessRecord::<9>::empty();
        let seven = padded(0x1000, 7);
        p.admit_counted(17, seven[0], seven, 7).unwrap();
        p.mark_running(17, seven[0]).unwrap();
        p.exit_with_status(17, seven[0], 42).unwrap();
        let exited = p;
        assert_eq!(p.reap_with_status(17, 0x90000), Err(ProcessError::PartialLease));
        assert_eq!(p.reap_with_status_counted(17, seven[0]),
                   Err(ProcessError::ActiveCr3));
        assert_eq!(p, exited);
        let (status, returned) = p.reap_with_status_counted(17, 0x90000).unwrap();
        assert_eq!(status, 42);
        assert_eq!(returned.as_slice(), &seven[..7]);
        assert_eq!(p.frame_count, 0);
        assert_eq!(p.reap_counted(17, 0x90000), Err(ProcessError::WrongState));

        let nine = padded(0x10000, 9);
        p.admit(18, nine[0], nine).unwrap();
        assert_eq!(p.frame_count, 9);
        p.mark_running(18, nine[0]).unwrap();
        p.exit_zero(18, nine[0]).unwrap();
        assert_eq!(p.reap(18, 0x90000), Ok(nine));
        assert_eq!(p.frame_count, 0);
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
