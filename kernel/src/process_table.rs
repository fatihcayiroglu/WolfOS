//! Bounded, no-heap WolfOS *multi-resident* user process ownership table.
//!
//! Multiple disjoint physical address spaces may be RESERVED simultaneously;
//! this is NOT a concurrent user-mode task scheduler. Until CPU context
//! saving / TSS stacks / CR3 switching are generalized, ONLY ONE entry
//! can be RUNNING. PMM leases must be independently allocated by callers.
//! Every admission is transactional and checks cross-PID physical aliases.
//! Actual hardware CR3 must be read by the caller for start/cancel/reap.
//!
//! This module does not map pages, launch arbitrary ELF files, schedule
//! threads, allocate physical frames or free PMM memory.
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(test)]
#[path = "process_lifecycle.rs"]
pub(crate) mod standalone_process;
#[cfg(test)]
use standalone_process::{ProcessError, ProcessRecord, ProcessState};
#[cfg(not(test))]
use crate::process_lifecycle::{ProcessError, ProcessRecord, ProcessState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError {
    Full,
    PidExhausted,
    UnknownPid,
    PhysicalAlias,
    AnotherRunning,
    LockBusy,
    Process(ProcessError),
}

impl From<ProcessError> for TableError {
    fn from(err: ProcessError) -> Self { Self::Process(err) }
}

pub struct ProcessTable<const SLOTS: usize, const FRAMES: usize> {
    slots: [ProcessRecord<FRAMES>; SLOTS],
    last_pid: u64,
}
impl<const SLOTS: usize, const FRAMES: usize> ProcessTable<SLOTS, FRAMES> {
    pub const fn new() -> Self {
        Self {
            slots: [const { ProcessRecord::empty() }; SLOTS],
            last_pid: 0,
        }
    }

    pub fn occupied(&self) -> usize {
        self.slots.iter().filter(|p| Self::live(p.state)).count()
    }

    pub fn running(&self) -> usize {
        self.slots.iter().filter(|p| p.state == ProcessState::Running).count()
    }
    /// A supplied supervisor CR3 must not alias ANY resident user process,
    /// including a READY process with no prepared resume context yet.
    pub fn owns_live_cr3(&self, root: u64) -> bool {
        root != 0 && self.slots.iter().any(|p|
            Self::live(p.state) && p.cr3_root == root
        )
    }

    fn live(state: ProcessState) -> bool {
        matches!(state, ProcessState::Ready | ProcessState::Running | ProcessState::Exited)
    }

    /// A snapshot cannot mutate resources or authenticate a PID. A reaped
    /// record is not exposed as a live process.
    pub fn snapshot(&self, pid: u64) -> Option<ProcessRecord<FRAMES>> {
        self.slots.iter().copied().find(|r| r.pid == pid && Self::live(r.state))
    }

    fn record_mut(&mut self, pid: u64) -> Result<&mut ProcessRecord<FRAMES>, TableError> {
        if pid == 0 { return Err(TableError::UnknownPid) }
        self.slots.iter_mut()
            .find(|r| r.pid == pid && Self::live(r.state))
            .ok_or(TableError::UnknownPid)
    }

    /// PID is minted by this table, not accepted from a requester. No slot,
    /// frame, or PID generation is modified when admission is refused.
    pub fn reserve(&mut self, root: u64, frames: [u64; FRAMES])
        -> Result<u64, TableError>
    {
        let pid = self.last_pid.checked_add(1).ok_or(TableError::PidExhausted)?;
        let index = self.slots.iter().position(|r| !Self::live(r.state))
            .ok_or(TableError::Full)?;

        // Run the SAME strict per-process root/alignment/duplicate-frame
        // checks as the existing real-CPL3 process lifecycle tests.
        let mut candidate = ProcessRecord::empty();
        candidate.admit(pid, root, frames).map_err(TableError::from)?;

        // Comparing every physical frame (including each CR3 root) means
        // no process can claim a page table or leaf already owned by another
        // still-resident PID, even when the generations are different.
        for entry in self.slots.iter().filter(|r| Self::live(r.state)) {
            if frames.iter().any(|frame| entry.frames.contains(frame)) {
                return Err(TableError::PhysicalAlias)
            }
        }

        // Previous slot tombstones retain their PID; the global last_pid
        // is strictly greater than all previous generations.
        self.slots[index].admit(pid, root, frames).map_err(TableError::from)?;
        self.last_pid = pid;
        Ok(pid)
    }

    /// Current phase admits multiple READY entries but only ONE running
    /// task. A CPU scheduler requires separately saved user GPR/FPU/TSS
    /// context and explicit per-CPU CR3 before relaxing this restriction.
    pub fn mark_running(&mut self, pid: u64, actual_cr3: u64)
        -> Result<(), TableError>
    {
        if self.slots.iter().any(|r| r.pid != pid && r.state == ProcessState::Running) {
            return Err(TableError::AnotherRunning)
        }
        self.record_mut(pid)?.mark_running(pid, actual_cr3)
            .map_err(TableError::from)
    }

    /// Stop the sole RUNNING PID after a real hardware user trap and
    /// before activating a different private address space. The handler
    /// must already have saved all GPR, IRET and FPU state.
    pub fn park_running(&mut self, pid: u64, actual_cr3: u64)
        -> Result<(), TableError>
    {
        self.record_mut(pid)?.park_running(pid, actual_cr3)
            .map_err(TableError::from)
    }

    pub fn exit_zero(&mut self, pid: u64, actual_cr3: u64)
        -> Result<(), TableError>
    {
        self.record_mut(pid)?.exit_zero(pid, actual_cr3).map_err(TableError::from)
    }

    /// Only AFTER CPU CR3 is no longer this process's address space:
    /// return exact PMM-owned frames, and invalidate its live PID.
    pub fn reap(&mut self, pid: u64, actual_cr3: u64)
        -> Result<[u64; FRAMES], TableError>
    {
        self.record_mut(pid)?.reap(pid, actual_cr3).map_err(TableError::from)
    }

    /// Failure/rollback path for a never-running READY process.
    pub fn cancel_ready(&mut self, pid: u64, actual_cr3: u64)
        -> Result<[u64; FRAMES], TableError>
    {
        self.record_mut(pid)?.cancel_ready(pid, actual_cr3).map_err(TableError::from)
    }
}

/// Bounded nonreentrant lock for the table. Callers must disable local IRQs
/// before this lock until kernel preemption and lock ordering are designed.
pub struct ProcessTableCell<const SLOTS: usize, const FRAMES: usize> {
    held: AtomicBool,
    table: UnsafeCell<ProcessTable<SLOTS, FRAMES>>,
}
// SAFETY: with() accesses the table exclusively while the AtomicBool is
// held; no references escape the closure, and the guard unlocks on unwind.
unsafe impl<const SLOTS: usize, const FRAMES: usize> Sync
    for ProcessTableCell<SLOTS, FRAMES> {}

struct Release<'a>(&'a AtomicBool);
impl Drop for Release<'_> {
    fn drop(&mut self) { self.0.store(false, Ordering::Release); }
}

impl<const SLOTS: usize, const FRAMES: usize> ProcessTableCell<SLOTS, FRAMES> {
    pub const fn new() -> Self {
        Self { held: AtomicBool::new(false), table: UnsafeCell::new(ProcessTable::new()) }
    }
    pub fn with<T>(&self, f: impl FnOnce(&mut ProcessTable<SLOTS, FRAMES>) -> T)
        -> Result<T, TableError>
    {
        if self.held.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err() { return Err(TableError::LockBusy) }
        let _release = Release(&self.held);
        // SAFETY: only one owner after acquiring the lock.
        Ok(f(unsafe { &mut *self.table.get() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frames(start: u64) -> [u64; 7] {
        core::array::from_fn(|i| start + i as u64 * 4096)
    }

    #[test]
    fn bounded_round_robin_resumes_only_one_running_pid() {
        let mut t=ProcessTable::<2,7>::new();
        let a=frames(0x1000);let b=frames(0x10000);
        let x=t.reserve(a[0],a).unwrap();
        let y=t.reserve(b[0],b).unwrap();
        for _ in 0..32 {
            t.mark_running(x,a[0]).unwrap();
            assert_eq!(t.running(),1);
            assert_eq!(t.mark_running(y,b[0]),Err(TableError::AnotherRunning));
            assert_eq!(t.park_running(x,b[0]),
                Err(TableError::Process(ProcessError::WrongAddressSpace)));
            t.park_running(x,a[0]).unwrap();
            t.mark_running(y,b[0]).unwrap();
            assert_eq!(t.running(),1);
            t.park_running(y,b[0]).unwrap();
            assert_eq!(t.running(),0);
        }
        assert_eq!(t.cancel_ready(x,0x9000),Ok(a));
        assert_eq!(t.cancel_ready(y,0x9000),Ok(b));
        assert_eq!(t.occupied(),0);
    }
    #[test]
    fn three_resident_pids_reuse_slot_without_reusing_pid() {
        let mut t = ProcessTable::<3, 7>::new();
        let a = frames(0x1000);
        let b = frames(0x10000);
        let c = frames(0x20000);
        let d = frames(0x30000);
        assert_eq!(t.reserve(a[0], a), Ok(1));
        assert_eq!(t.reserve(b[0], b), Ok(2));
        assert_eq!(t.reserve(c[0], c), Ok(3));
        assert_eq!(t.occupied(), 3);
        assert_eq!(t.reserve(d[0], d), Err(TableError::Full));
        assert_eq!(t.cancel_ready(2, 0x90000), Ok(b));
        assert_eq!(t.snapshot(2), None);
        assert_eq!(t.reserve(d[0], d), Ok(4));
        assert_eq!(t.occupied(), 3);
        assert_eq!(t.snapshot(4).unwrap().frames, d);
        assert_eq!(t.cancel_ready(1, 0x90000), Ok(a));
        assert_eq!(t.cancel_ready(3, 0x90000), Ok(c));
        assert_eq!(t.cancel_ready(4, 0x90000), Ok(d));
        assert_eq!(t.occupied(), 0);
        assert_eq!(t.cancel_ready(2, 0x90000), Err(TableError::UnknownPid));
    }

    #[test]
    fn foreign_frame_or_root_alias_never_consumes_new_pid() {
        let mut t = ProcessTable::<3,7>::new();
        let a = frames(0x1000);
        let b = frames(0x10000);
        assert_eq!(t.reserve(a[0], a), Ok(1));
        let mut dup = b;
        dup[5] = a[6];
        assert_eq!(t.reserve(b[0], dup), Err(TableError::PhysicalAlias));
        let mut root_alias = b;
        root_alias[0] = a[1];
        assert_eq!(t.reserve(root_alias[0], root_alias),
            Err(TableError::PhysicalAlias));
        assert_eq!(t.occupied(), 1);
        assert_eq!(t.reserve(b[0], b), Ok(2));
    }

    #[test]
    fn rejects_malformed_claims_transactionally() {
        let mut t = ProcessTable::<2, 7>::new();
        let good = frames(0x1000);
        let mut duplicate = good;
        duplicate[5] = duplicate[4];
        assert_eq!(t.reserve(good[0], duplicate),
            Err(TableError::Process(ProcessError::DuplicateFrame)));
        assert_eq!(t.reserve(0x8000, good),
            Err(TableError::Process(ProcessError::InvalidRoot)));
        assert_eq!(t.occupied(), 0);
        assert_eq!(t.reserve(good[0], good), Ok(1));
        assert_eq!(t.cancel_ready(1, good[0]),
            Err(TableError::Process(ProcessError::ActiveCr3)));
        assert_eq!(t.cancel_ready(1, 0),
            Err(TableError::Process(ProcessError::ActiveCr3)));
        assert_eq!(t.occupied(), 1);
    }

    #[test]
    fn single_running_gate_and_post_exit_independent_reaping() {
        let mut t = ProcessTable::<3,7>::new();
        let a = frames(0x1000);
        let b = frames(0x10000);
        let c = frames(0x20000);
        let x = t.reserve(a[0], a).unwrap();
        let y = t.reserve(b[0], b).unwrap();
        let z = t.reserve(c[0], c).unwrap();
        assert_eq!(t.mark_running(x, b[0]),
            Err(TableError::Process(ProcessError::WrongAddressSpace)));
        t.mark_running(x, a[0]).unwrap();
        assert_eq!(t.mark_running(y, b[0]), Err(TableError::AnotherRunning));
        assert_eq!(t.reap(x, b[0]),
            Err(TableError::Process(ProcessError::WrongState)));
        t.exit_zero(x, a[0]).unwrap();
        t.mark_running(y, b[0]).unwrap();
        assert_eq!(t.running(), 1);
        assert_eq!(t.reap(x, a[0]),
            Err(TableError::Process(ProcessError::ActiveCr3)));
        assert_eq!(t.reap(x, b[0]), Ok(a));
        assert_eq!(t.reap(x, b[0]), Err(TableError::UnknownPid));
        t.exit_zero(y, b[0]).unwrap();
        assert_eq!(t.reap(y, 0x90000), Ok(b));
        assert_eq!(t.cancel_ready(z, 0x90000), Ok(c));
        assert_eq!(t.occupied(), 0);
    }

    #[test]
    fn no_slots_and_exhausted_pid_fail_closed() {
        let mut empty = ProcessTable::<0,7>::new();
        assert_eq!(empty.reserve(0x1000, frames(0x1000)), Err(TableError::Full));
        let mut t = ProcessTable::<1,7>::new();
        t.last_pid = u64::MAX;
        assert_eq!(t.reserve(0x1000, frames(0x1000)), Err(TableError::PidExhausted));
        assert_eq!(t.occupied(), 0);
    }

    #[test]
    fn cell_lock_is_nonreentrant_and_restored_after_unwind() {
        let cell = ProcessTableCell::<3,7>::new();
        cell.with(|table| {
            let a = frames(0x1000);
            assert_eq!(table.reserve(a[0], a), Ok(1));
            assert_eq!(cell.with(|_| ()), Err(TableError::LockBusy));
        }).unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cell.with(|_| panic!("recovery")).ok();
        }));
        assert_eq!(cell.with(|table| table.occupied()), Ok(1));
    }
}
