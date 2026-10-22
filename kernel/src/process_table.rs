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
use standalone_process::{ProcessError, ProcessRecord, ProcessState, PAGE};
#[cfg(not(test))]
use crate::process_lifecycle::{ProcessError, ProcessRecord, ProcessState, PAGE};

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
    /// A supplied supervisor CR3 must not use ANY frame leased to a live
    /// userspace process, even a non-root page-table/data frame. Looking only
    /// at the process PML4 root could wrongly authorize a handoff/reap under
    /// another page of the same live PMM lease. READY/BLOCKED/EXITED owners
    /// keep those frames pinned until their exact lease is relinquished.
    pub fn owns_live_cr3(&self, root: u64) -> bool {
        root != 0 && self.slots.iter().any(|p|
            Self::live(p.state) && p.frames.contains(&root)
        )
    }

    fn live(state: ProcessState) -> bool {
        matches!(state, ProcessState::Ready | ProcessState::Running | ProcessState::Blocked | ProcessState::Exited)
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


    /// Stage several independently allocated user PMM leases as one bounded,
    /// all-or-nothing metadata admission. Validate all roots and frames using
    /// the existing per-PID checks, including aliases BETWEEN new entrants.
    ///
    /// Nothing is published on failure: no partial READY owner, no spent PID
    /// generation and no altered frame lease. Tentative physical allocations
    /// remain the caller's responsibility regardless of the outcome. This
    /// does NOT launch ELFs, prepare user GPR/FX/IRET or start a scheduler.
    pub fn reserve_batch<const COUNT: usize>(
        &mut self, leases: [(u64, [u64; FRAMES]); COUNT],
    ) -> Result<[u64; COUNT], TableError> {
        // Stage on a private bounded stack copy rather than admitting the
        // first PID to the live ledger and attempting fallible rollback.
        // Reuse reserve(), so future single-owner validation also applies
        // to each member of a batch.
        let mut staged = Self { slots: self.slots, last_pid: self.last_pid };
        let mut minted = [0; COUNT];
        for (i, (root, frames)) in leases.into_iter().enumerate() {
            minted[i] = staged.reserve(root, frames)?;
        }
        *self = staged;
        Ok(minted)
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

    /// Block only the active RUNNING owner after the trusted CPL3 trap has
    /// saved its registers, IRET frame and FX state. Retain PMM/CR3 ownership.
    pub fn block_running(&mut self, pid: u64, actual_cr3: u64)
        -> Result<(), TableError>
    {
        self.record_mut(pid)?.block_running(pid, actual_cr3)
            .map_err(TableError::from)
    }

    /// Wake a BLOCKED owner, keeping all private frames pinned. The caller
    /// authenticates the event and reads the actual supervisor CR3 separately.
    /// Reject a supervisor CR3 that aliases ANY still-resident userspace root.
    /// No runtime scheduling, IRQ dispatch or frame handoff occurs here.
    pub fn wake_blocked(&mut self, pid: u64, supervisor_cr3: u64)
        -> Result<(), TableError>
    {
        if supervisor_cr3 == 0 || supervisor_cr3 & (PAGE - 1) != 0
            || supervisor_cr3 >= (1 << 52) || self.owns_live_cr3(supervisor_cr3)
        { return Err(TableError::Process(ProcessError::ActiveCr3)) }
        self.record_mut(pid)?.wake_blocked(pid, supervisor_cr3)
            .map_err(TableError::from)
    }

    /// Cancel a BLOCKED process only after the trusted caller has retired
    /// its matching EventWaitGate and Ring3RunQueue wait instance, quiesced
    /// saved interrupt/user CPU+FX contexts, and verified the real supervisor
    /// CR3. Reject every resident userspace root (not merely the victim's).
    /// Returned PMM leases remain the caller's exactly-once responsibility.
    /// No physical memory is freed here.
    pub fn cancel_blocked(&mut self, pid: u64, supervisor_cr3: u64)
        -> Result<[u64; FRAMES], TableError>
    {
        if supervisor_cr3 == 0 || supervisor_cr3 & (PAGE - 1) != 0
            || supervisor_cr3 >= (1 << 52) || self.owns_live_cr3(supervisor_cr3)
        { return Err(TableError::Process(ProcessError::ActiveCr3)) }
        self.record_mut(pid)?.cancel_blocked(pid, supervisor_cr3)
            .map_err(TableError::from)
    }

    pub fn exit_zero(&mut self, pid: u64, actual_cr3: u64)
        -> Result<(), TableError>
    {
        self.record_mut(pid)?.exit_zero(pid, actual_cr3).map_err(TableError::from)
    }

    /// Only AFTER independently verifying supervisor CR3 is not ANY live
    /// user's address space: relinquish exact PMM frame ownership once.
    /// The caller separately proves hardware quiescence and releases PMM.
    pub fn reap(&mut self, pid: u64, actual_cr3: u64)
        -> Result<[u64; FRAMES], TableError>
    {
        if actual_cr3 == 0 || actual_cr3 & (PAGE - 1) != 0
            || actual_cr3 >= (1 << 52) || self.owns_live_cr3(actual_cr3)
        { return Err(TableError::Process(ProcessError::ActiveCr3)) }
        self.record_mut(pid)?.reap(pid, actual_cr3).map_err(TableError::from)
    }

    /// Failure/rollback path for a never-running READY process. Reject an
    /// observed CR3 owned by any other still-resident user, not only this PID.
    pub fn cancel_ready(&mut self, pid: u64, actual_cr3: u64)
        -> Result<[u64; FRAMES], TableError>
    {
        if actual_cr3 == 0 || actual_cr3 & (PAGE - 1) != 0
            || actual_cr3 >= (1 << 52) || self.owns_live_cr3(actual_cr3)
        { return Err(TableError::Process(ProcessError::ActiveCr3)) }
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
    fn four_resident_owners_survive_mixed_block_wake_exit_and_teardown() {
        let mut t = ProcessTable::<4, 7>::new();
        let owned = [
            frames(0x1000), frames(0x10000),
            frames(0x20000), frames(0x30000),
        ];
        let pid = core::array::from_fn::<_, 4, _>(|i| {
            t.reserve(owned[i][0], owned[i]).unwrap()
        });
        assert_eq!(t.occupied(), 4);
        assert_eq!(t.running(), 0);

        t.mark_running(pid[0], owned[0][0]).unwrap();
        assert_eq!(t.mark_running(pid[1], owned[1][0]), Err(TableError::AnotherRunning));
        t.park_running(pid[0], owned[0][0]).unwrap();
        t.mark_running(pid[1], owned[1][0]).unwrap();
        t.block_running(pid[1], owned[1][0]).unwrap();
        t.mark_running(pid[2], owned[2][0]).unwrap();
        t.exit_zero(pid[2], owned[2][0]).unwrap();
        t.mark_running(pid[3], owned[3][0]).unwrap();
        t.park_running(pid[3], owned[3][0]).unwrap();
        assert_eq!(t.running(), 0);

        let snapshots = pid.map(|id| t.snapshot(id));
        assert_eq!(snapshots[0].unwrap().state, ProcessState::Ready);
        assert_eq!(snapshots[1].unwrap().state, ProcessState::Blocked);
        assert_eq!(snapshots[2].unwrap().state, ProcessState::Exited);
        assert_eq!(snapshots[3].unwrap().state, ProcessState::Ready);
        for root in owned.map(|frames| frames[0]) {
            assert_eq!(t.wake_blocked(pid[1], root),
                Err(TableError::Process(ProcessError::ActiveCr3)));
            assert_eq!(t.cancel_ready(pid[3], root),
                Err(TableError::Process(ProcessError::ActiveCr3)));
            assert_eq!(t.reap(pid[2], root),
                Err(TableError::Process(ProcessError::ActiveCr3)));
            assert_eq!(pid.map(|id| t.snapshot(id)), snapshots,
                "a foreign user CR3 must never mutate any owner");
        }

        t.wake_blocked(pid[1], 0x90000).unwrap();
        assert_eq!(t.snapshot(pid[1]).unwrap().state, ProcessState::Ready);
        assert_eq!(t.reap(pid[2], 0x90000), Ok(owned[2]));
        assert_eq!(t.snapshot(pid[2]), None);
        assert_eq!(t.cancel_ready(pid[3], 0x90000), Ok(owned[3]));
        assert_eq!(t.cancel_ready(pid[0], 0x90000), Ok(owned[0]));
        assert_eq!(t.snapshot(pid[1]).unwrap().frames, owned[1]);
        assert_eq!(t.cancel_ready(pid[1], 0x90000), Ok(owned[1]));
        assert_eq!(t.occupied(), 0);
        assert_eq!(t.running(), 0);
        for (i, id) in pid.iter().enumerate() {
            assert_eq!(t.snapshot(*id), None, "PID {i} must be retired");
            assert_eq!(t.cancel_ready(*id, 0x90000), Err(TableError::UnknownPid));
        }
    }


    #[test]
    fn nonroot_user_frames_cannot_authorize_foreign_supervisor_lease_release() {
        let mut t = ProcessTable::<3, 7>::new();
        let a = frames(0x1000);
        let b = frames(0x10000);
        let c = frames(0x20000);
        let x = t.reserve(a[0], a).unwrap();
        let y = t.reserve(b[0], b).unwrap();
        let z = t.reserve(c[0], c).unwrap();

        t.mark_running(x, a[0]).unwrap();
        t.block_running(x, a[0]).unwrap();
        t.mark_running(y, b[0]).unwrap();
        t.exit_zero(y, b[0]).unwrap();
        assert_eq!(t.running(), 0);
        let snapshot = (t.snapshot(x), t.snapshot(y), t.snapshot(z));
        let forbidden = [a[1], a[6], b[2], c[4], c[6]];
        for borrowed in forbidden {
            assert_ne!(borrowed, a[0]);
            assert_ne!(borrowed, b[0]);
            assert_ne!(borrowed, c[0]);
            assert!(t.owns_live_cr3(borrowed));
            assert_eq!(
                t.wake_blocked(x, borrowed),
                Err(TableError::Process(ProcessError::ActiveCr3)),
            );
            assert_eq!(
                t.cancel_blocked(x, borrowed),
                Err(TableError::Process(ProcessError::ActiveCr3)),
            );
            assert_eq!(
                t.reap(y, borrowed),
                Err(TableError::Process(ProcessError::ActiveCr3)),
            );
            assert_eq!(
                t.cancel_ready(z, borrowed),
                Err(TableError::Process(ProcessError::ActiveCr3)),
            );
            assert_eq!(
                (t.snapshot(x), t.snapshot(y), t.snapshot(z)),
                snapshot,
                "a live user-owned non-root frame must never pass for supervisor CR3",
            );
        }

        // Only a separately authenticated and unowned supervisor root
        // may authorize metadata transfer; this still does not free PMM pages.
        assert!(!t.owns_live_cr3(0x90000));
        assert_eq!(t.cancel_blocked(x, 0x90000), Ok(a));
        assert_eq!(t.reap(y, 0x90000), Ok(b));
        assert_eq!(t.cancel_ready(z, 0x90000), Ok(c));
        assert_eq!(t.running(), 0);
        assert_eq!(t.occupied(), 0);
    }

    #[test]
    fn reap_and_ready_cancel_reject_every_resident_foreign_cr3() {
        let mut t = ProcessTable::<3, 7>::new();
        let a = frames(0x1000);
        let b = frames(0x10000);
        let c = frames(0x20000);
        let x = t.reserve(a[0], a).unwrap();
        let y = t.reserve(b[0], b).unwrap();
        let z = t.reserve(c[0], c).unwrap();
        t.mark_running(x, a[0]).unwrap();
        t.exit_zero(x, a[0]).unwrap();
        let original = (t.snapshot(x), t.snapshot(y), t.snapshot(z));
        for foreign in [a[0], b[0], c[0], 0, 0x90001, 1 << 52] {
            assert_eq!(t.reap(x, foreign),
                Err(TableError::Process(ProcessError::ActiveCr3)));
            assert_eq!(t.cancel_ready(z, foreign),
                Err(TableError::Process(ProcessError::ActiveCr3)));
            assert_eq!((t.snapshot(x), t.snapshot(y), t.snapshot(z)), original,
                "rejected user CR3 may not transfer any PMM ownership");
        }
        assert_eq!(t.reap(x, 0x90000), Ok(a));
        assert_eq!(t.snapshot(x), None);
        assert_eq!(t.cancel_ready(z, b[0]),
            Err(TableError::Process(ProcessError::ActiveCr3)));
        assert_eq!(t.snapshot(z).unwrap().frames, c);
        assert_eq!(t.cancel_ready(z, 0x90000), Ok(c));
        assert_eq!(t.snapshot(z), None);
        assert_eq!(t.snapshot(y).unwrap().frames, b);
        assert_eq!(t.cancel_ready(y, 0x90000), Ok(b));
        assert_eq!(t.occupied(), 0);
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
        assert_eq!(t.reap(x, 0x90000),
            Err(TableError::Process(ProcessError::WrongState)));
        t.exit_zero(x, a[0]).unwrap();
        t.mark_running(y, b[0]).unwrap();
        assert_eq!(t.running(), 1);
        assert_eq!(t.reap(x, a[0]),
            Err(TableError::Process(ProcessError::ActiveCr3)));
        // Even a different PID's active user CR3 cannot authorize a reap.
        assert_eq!(t.reap(x, b[0]),
            Err(TableError::Process(ProcessError::ActiveCr3)));
        assert_eq!(t.snapshot(x).unwrap().frames, a);
        // The trusted caller separately verifies a supervisor CR3 and
        // quiesces this exited owner's CPU/FX before PMM reclamation.
        assert_eq!(t.reap(x, 0x90000), Ok(a));
        assert_eq!(t.reap(x, 0x90000), Err(TableError::UnknownPid));
        t.exit_zero(y, b[0]).unwrap();
        assert_eq!(t.reap(y, 0x90000), Ok(b));
        assert_eq!(t.cancel_ready(z, 0x90000), Ok(c));
        assert_eq!(t.occupied(), 0);
    }

    #[test]
    fn blocked_pid_stays_resident_until_authenticated_wake_and_cleanup() {
        let mut t = ProcessTable::<3, 7>::new();
        let a_frames = frames(0x1000);
        let b_frames = frames(0x10000);
        let a = t.reserve(a_frames[0], a_frames).unwrap();
        let b = t.reserve(b_frames[0], b_frames).unwrap();
        t.mark_running(a, a_frames[0]).unwrap();
        assert_eq!(t.block_running(a, b_frames[0]),
            Err(TableError::Process(ProcessError::WrongAddressSpace)));
        t.block_running(a, a_frames[0]).unwrap();
        assert_eq!(t.running(), 0);
        assert_eq!(t.occupied(), 2);
        assert_eq!(t.snapshot(a).unwrap().state, ProcessState::Blocked);
        assert_eq!(t.snapshot(a).unwrap().frames, a_frames);
        assert!(t.owns_live_cr3(a_frames[0]));

        let mut colliding = frames(0x30000);
        colliding[6] = a_frames[4];
        assert_eq!(t.reserve(colliding[0], colliding), Err(TableError::PhysicalAlias));
        assert_eq!(t.mark_running(a, a_frames[0]),
            Err(TableError::Process(ProcessError::WrongState)));
        assert_eq!(t.cancel_ready(a, 0x90000),
            Err(TableError::Process(ProcessError::WrongState)));
        assert_eq!(t.reap(a, 0x90000),
            Err(TableError::Process(ProcessError::WrongState)));

        t.mark_running(b, b_frames[0]).unwrap();
        t.park_running(b, b_frames[0]).unwrap();
        for invalid_cr3 in [0, a_frames[0], b_frames[0], 0x90001, 1 << 52] {
            assert_eq!(t.wake_blocked(a, invalid_cr3),
                Err(TableError::Process(ProcessError::ActiveCr3)));
        }
        assert_eq!(t.wake_blocked(99, 0x90000), Err(TableError::UnknownPid));
        assert_eq!(t.snapshot(a).unwrap().state, ProcessState::Blocked);
        assert_eq!(t.wake_blocked(a, 0x90000), Ok(()));
        assert_eq!(t.wake_blocked(a, 0x90000),
            Err(TableError::Process(ProcessError::WrongState)));
        assert_eq!(t.snapshot(a).unwrap().state, ProcessState::Ready);
        t.mark_running(a, a_frames[0]).unwrap();
        t.exit_zero(a, a_frames[0]).unwrap();
        assert_eq!(t.reap(a, 0x90000), Ok(a_frames));
        assert_eq!(t.cancel_ready(b, 0x90000), Ok(b_frames));
        assert_eq!(t.occupied(), 0);
        assert_eq!(t.wake_blocked(a, 0x90000), Err(TableError::UnknownPid));
    }

    #[test]
    fn blocked_cancellation_rejects_every_live_user_cr3_and_stale_pid() {
        let mut t = ProcessTable::<2, 7>::new();
        let a = frames(0x1000);
        let b = frames(0x10000);
        let pid_a = t.reserve(a[0], a).unwrap();
        let pid_b = t.reserve(b[0], b).unwrap();
        t.mark_running(pid_a, a[0]).unwrap();
        t.block_running(pid_a, a[0]).unwrap();
        assert_eq!(t.snapshot(pid_a).unwrap().state, ProcessState::Blocked);
        let prior_a = t.snapshot(pid_a);
        let prior_b = t.snapshot(pid_b);
        for invalid in [0, a[0], b[0], 0x90001, 1 << 52, u64::MAX] {
            assert_eq!(t.cancel_blocked(pid_a, invalid),
                Err(TableError::Process(ProcessError::ActiveCr3)));
            assert_eq!(t.snapshot(pid_a), prior_a);
            assert_eq!(t.snapshot(pid_b), prior_b);
        }
        assert_eq!(t.cancel_blocked(pid_b, 0x90000),
            Err(TableError::Process(ProcessError::WrongState)));
        assert_eq!(t.snapshot(pid_a), prior_a);
        assert_eq!(t.cancel_blocked(pid_a, 0x90000), Ok(a));
        assert_eq!(t.snapshot(pid_a), None);
        assert_eq!(t.occupied(), 1);
        assert!(!t.owns_live_cr3(a[0]));
        assert!(t.owns_live_cr3(b[0]));
        assert_eq!(t.wake_blocked(pid_a, 0x90000), Err(TableError::UnknownPid));
        assert_eq!(t.cancel_blocked(pid_a, 0x90000), Err(TableError::UnknownPid));
        assert_eq!(t.reap(pid_a, 0x90000), Err(TableError::UnknownPid));
        let replacement = t.reserve(a[0], a).unwrap();
        assert!(replacement > pid_b);
        assert_eq!(t.cancel_ready(replacement, 0x90000), Ok(a));
        assert_eq!(t.cancel_ready(pid_b, 0x90000), Ok(b));
        assert_eq!(t.occupied(), 0);
    }

    #[test]
    fn cr3_ownership_survives_exit_until_verified_reap_and_slot_reuse() {
        let mut table = ProcessTable::<1, 7>::new();
        let owned = frames(0x1000);
        let pid = table.reserve(owned[0], owned).unwrap();
        assert!(table.owns_live_cr3(owned[0]));

        table.mark_running(pid, owned[0]).unwrap();
        table.exit_zero(pid, owned[0]).unwrap();
        assert_eq!(table.snapshot(pid).unwrap().state, ProcessState::Exited);
        assert!(table.owns_live_cr3(owned[0]),
            "EXITED processes retain their CR3 and PMM ownership");

        assert_eq!(table.reap(pid, owned[0]),
            Err(TableError::Process(ProcessError::ActiveCr3)));
        assert_eq!(table.snapshot(pid).unwrap().frames, owned);
        assert!(table.owns_live_cr3(owned[0]),
            "refused reap must not release a live user CR3");

        assert_eq!(table.reap(pid, 0x90000), Ok(owned));
        assert_eq!(table.snapshot(pid), None);
        assert!(!table.owns_live_cr3(owned[0]));

        // The slot and frames may be reused, but the old PID must not be.
        let replacement = table.reserve(owned[0], owned).unwrap();
        assert!(replacement > pid);
        assert!(table.owns_live_cr3(owned[0]));
        assert_eq!(table.reap(pid, 0x90000), Err(TableError::UnknownPid));
        assert_eq!(table.snapshot(replacement).unwrap().frames, owned);
        assert_eq!(table.cancel_ready(replacement, 0x90000), Ok(owned));
        assert!(!table.owns_live_cr3(owned[0]));
        assert_eq!(table.occupied(), 0);
    }


    #[test]
    fn batched_admission_is_atomic_across_alias_full_and_invalid_members() {
        let mut t = ProcessTable::<3, 7>::new();
        let a = frames(0x1000);
        let b = frames(0x10000);
        let c = frames(0x20000);
        let d = frames(0x30000);
        let initial = t.reserve(a[0], a).unwrap();
        assert_eq!(initial, 1);
        let before = (t.slots, t.last_pid, t.occupied());
        // The third candidate aliases a frame belonging to the second
        // tentative process. The first successful *staged* PID is not spent.
        let mut alias = c;
        alias[5] = b[2];
        assert_eq!(
            t.reserve_batch([(b[0], b), (alias[0], alias)]),
            Err(TableError::PhysicalAlias),
        );
        assert_eq!((t.slots, t.last_pid, t.occupied()), before);

        // The third new process would exceed fixed capacity; no partial
        // transaction survives, even when the first two are valid.
        assert_eq!(
            t.reserve_batch([(b[0], b), (c[0], c), (d[0], d)]),
            Err(TableError::Full),
        );
        assert_eq!((t.slots, t.last_pid, t.occupied()), before);

        let mut duplicate = c;
        duplicate[6] = duplicate[4];
        assert_eq!(
            t.reserve_batch([(b[0], b), (duplicate[0], duplicate)]),
            Err(TableError::Process(ProcessError::DuplicateFrame)),
        );
        assert_eq!((t.slots, t.last_pid, t.occupied()), before);

        assert_eq!(t.reserve_batch([(b[0], b), (c[0], c)]), Ok([2, 3]));
        assert_eq!(t.occupied(), 3);
        assert_eq!(t.running(), 0);
        for (pid, lease) in [(1, a), (2, b), (3, c)] {
            assert_eq!(t.snapshot(pid).unwrap().frames, lease);
            assert_eq!(t.cancel_ready(pid, 0x90000), Ok(lease));
            assert_eq!(t.snapshot(pid), None);
        }
        assert_eq!(t.occupied(), 0);
        assert_eq!(t.reserve_batch::<0>([]), Ok([]));
        assert_eq!(t.last_pid, 3);
    }

    #[test]
    fn batched_admission_rejects_live_alias_and_pid_exhaustion_without_mutation() {
        let mut t = ProcessTable::<3, 7>::new();
        let a = frames(0x1000);
        let b = frames(0x10000);
        let c = frames(0x20000);
        let pid = t.reserve(a[0], a).unwrap();
        t.mark_running(pid, a[0]).unwrap();
        t.block_running(pid, a[0]).unwrap();
        let frozen = (t.slots, t.last_pid);
        let mut live_alias = b;
        live_alias[3] = a[6];
        assert_eq!(
            t.reserve_batch([(b[0], live_alias), (c[0], c)]),
            Err(TableError::PhysicalAlias),
        );
        assert_eq!((t.slots, t.last_pid), frozen);
        assert_eq!(t.snapshot(pid).unwrap().state, ProcessState::Blocked);
        t.cancel_blocked(pid, 0x90000).unwrap();

        // Even with empty slots, a two-PID batch cannot partially mint
        // u64::MAX and then wrap to zero on its second member.
        t.last_pid = u64::MAX - 1;
        let before = (t.slots, t.last_pid);
        assert_eq!(
            t.reserve_batch([(b[0], b), (c[0], c)]),
            Err(TableError::PidExhausted),
        );
        assert_eq!((t.slots, t.last_pid), before);
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
