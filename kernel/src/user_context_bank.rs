//! PID-bound saved CPL3 trap frames, private CR3 ownership and RSP0 stacks.
//!
//! This is a *preflight/context storage* facility. It deliberately DOES NOT
//! write CR3, TSS.RSP0, switch xstate, execute IRETQ, or schedule userspace.
//! A later hardware gate must pin mappings and perform those operations.
//! Only a verified kernel trap (or explicit bootstrap) may supply a frame.
//! The stored whole 15-GPR + 5-word IRETQ frame can be passed to the
//! existing assembly entry once the independently audited handoff exists.
#[cfg(test)]
#[path = "user_syscall_abi.rs"]
mod standalone_abi;
#[cfg(test)]
use standalone_abi::{valid_user_rflags, UserSyscallFrame, FRAME_BYTES};
#[cfg(not(test))]
use crate::user_syscall_abi::{valid_user_rflags, UserSyscallFrame, FRAME_BYTES};
#[cfg(test)]
#[path = "process_table.rs"]
mod standalone_table;
#[cfg(test)]
use standalone_table::ProcessTable;
#[cfg(not(test))]
use crate::process_table::ProcessTable;
#[cfg(test)]
#[path = "ring3_runqueue.rs"]
mod standalone_runqueue;
#[cfg(test)]
use standalone_runqueue::{Handle as RunHandle, Ring3RunQueue, State as RunState};
#[cfg(not(test))]
use crate::ring3_runqueue::{Handle as RunHandle, Ring3RunQueue, State as RunState};
#[cfg(test)]
use standalone_table::standalone_process::ProcessState;
#[cfg(not(test))]
use crate::process_lifecycle::ProcessState;

pub const KSTACK_BYTES: u64 = 16 * 1024;
const USER_MIN: u64 = 0x10000;
const USER_END: u64 = 0x0000_8000_0000_0000;
const KERNEL_START: u64 = 0xffff_8000_0000_0000;
const PHYS_END: u64 = 1 << 52;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    InvalidPid, NotResident, WrongState, BadCr3,
    BadUserPointer, BadSelectors, BadFlags,
    BadKernelStack, KernelStackOverlap, FrameOutsideKernelStack,
    AlreadyPrepared, Full, NotPrepared, OnlyOnePrepared, ActiveUserCr3,
    StaleProcess, NotRetired, SchedulerMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOrigin {
    /// Kernel-created initial frame, NOT captured from actual user execution.
    Bootstrap,
    /// Real, checked TSS.RSP0 interrupt stack copy; PID is RUNNING under CR3.
    HardwareTrap,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelStack {
    pub bottom: u64,
    pub top: u64,
}

impl KernelStack {
    pub fn valid(self) -> bool {
        self.bottom >= KERNEL_START
            && self.bottom & 15 == 0 && self.top & 15 == 0
            && self.bottom.checked_add(KSTACK_BYTES) == Some(self.top)
    }
    pub fn overlaps(self, other: Self) -> bool {
        self.bottom < other.top && other.bottom < self.top
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredUserFrame {
    pub pid: u64,
    pub cr3_root: u64,
    pub kernel_stack: KernelStack,
    pub frame: UserSyscallFrame,
    pub origin: FrameOrigin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResumePlan {
    pub pid: u64,
    pub cr3_root: u64,
    pub rsp0: u64,
    pub frame: UserSyscallFrame,
    pub origin: FrameOrigin,
}

/// Fixed table stores whole register/IRET frames, never pointers into a
/// previous trap stack. This prevents a later interrupt stack overwrite
/// from changing the stored return frame. The caller still must validate
/// all mapped pages and active hardware state immediately before IRETQ.
pub struct UserContextBank<const SLOTS: usize> {
    entries: [Option<StoredUserFrame>; SLOTS],
}

impl<const SLOTS: usize> UserContextBank<SLOTS> {
    pub const fn new() -> Self { Self { entries: [None; SLOTS] } }

    pub fn count(&self) -> usize {
        self.entries.iter().filter(|x| x.is_some()).count()
    }

    pub fn snapshot(&self, pid: u64) -> Option<StoredUserFrame> {
        self.entries.iter().flatten().copied().find(|x| x.pid == pid)
    }

    fn validate_frame(frame: &UserSyscallFrame) -> Result<(), ContextError> {
        if !(USER_MIN..USER_END).contains(&frame.hardware.rip)
            || !(USER_MIN..USER_END).contains(&frame.hardware.rsp)
        { return Err(ContextError::BadUserPointer) }
        let cs = frame.hardware.cs;
        let ss = frame.hardware.ss;
        if cs > u16::MAX as u64 || ss > u16::MAX as u64
            || cs & 7 != 3 || ss & 7 != 3
            || cs & !7 == 0 || ss & !7 == 0
            || cs & 4 != 0 || ss & 4 != 0
            || cs >> 3 == ss >> 3
        { return Err(ContextError::BadSelectors) }
        if !valid_user_rflags(frame.hardware.rflags) {
            return Err(ContextError::BadFlags)
        }
        Ok(())
    }

    fn insert<const N: usize>(
        &mut self, table: &ProcessTable<SLOTS, N>,
        pid: u64, root: u64, stack: KernelStack, frame: UserSyscallFrame,
        origin: FrameOrigin, trap_at: Option<u64>,
    ) -> Result<(), ContextError> {
        if pid == 0 { return Err(ContextError::InvalidPid) }
        let process = table.snapshot(pid).ok_or(ContextError::NotResident)?;
        if process.cr3_root != root || root == 0 || root & 4095 != 0
            || root >= PHYS_END
        { return Err(ContextError::BadCr3) }
        if process.state != (match origin {
            FrameOrigin::Bootstrap => ProcessState::Ready,
            FrameOrigin::HardwareTrap => ProcessState::Running,
        }) { return Err(ContextError::WrongState) }
        if !stack.valid() { return Err(ContextError::BadKernelStack) }
        Self::validate_frame(&frame)?;
        if let Some(at) = trap_at {
            if at & 7 != 0 || at < stack.bottom
                || at.checked_add(FRAME_BYTES as u64)
                    .is_none_or(|end| end > stack.top)
            { return Err(ContextError::FrameOutsideKernelStack) }
        } else if origin != FrameOrigin::Bootstrap {
            return Err(ContextError::FrameOutsideKernelStack)
        }
        // Duplicate PIDs and overlapping per-process kernel RSP0 stacks
        // are rejected independently of private userspace PMM ownership.
        if self.snapshot(pid).is_some() {
            return Err(ContextError::AlreadyPrepared)
        }
        if self.entries.iter().flatten().any(|x| x.kernel_stack.overlaps(stack)) {
            return Err(ContextError::KernelStackOverlap)
        }
        let slot = self.entries.iter().position(Option::is_none)
            .ok_or(ContextError::Full)?;
        self.entries[slot] = Some(StoredUserFrame {
            pid, cr3_root: root, kernel_stack: stack, frame, origin,
        });
        Ok(())
    }

    /// Seed initial IRETQ-like frame from an audited loader plan. The caller
    /// must ensure lower-half RIP/RSP are backed by this process's own pages;
    /// this metadata check by itself does NOT prove a page is mapped.
    pub fn prepare_bootstrap<const N: usize>(
        &mut self, table: &ProcessTable<SLOTS,N>,
        pid: u64, root: u64, stack: KernelStack, frame: UserSyscallFrame,
    ) -> Result<(), ContextError> {
        self.insert(table, pid, root, stack, frame, FrameOrigin::Bootstrap, None)
    }

    /// Snapshot the entire hardware trap, but only from a live PID whose
    /// actual CR3 is independently checked by the caller at the trap site.
    /// This DOES NOT suspend the process or switch the CPU.
    pub fn capture_trap<const N: usize>(
        &mut self, table: &ProcessTable<SLOTS,N>,
        pid: u64, actual_cr3: u64, stack: KernelStack, trap_at: u64,
        frame: UserSyscallFrame,
    ) -> Result<(), ContextError> {
        self.insert(table, pid, actual_cr3, stack, frame,
                    FrameOrigin::HardwareTrap, Some(trap_at))
    }

    /// Return next *metadata* candidate in PID order. The supplied boot CR3
    /// MUST be read from actual hardware on a disjoint supervisor stack.
    /// Does not mutate process state or activate any context. It refuses a
    /// still-live user CR3 to avoid authorizing an unsafe return.
    pub fn plan_next<const N: usize>(
        &self, table: &ProcessTable<SLOTS,N>, current_pid: u64,
        actual_kernel_cr3: u64,
    ) -> Result<ResumePlan, ContextError> {
        if actual_kernel_cr3 == 0 || actual_kernel_cr3 & 4095 != 0
            || actual_kernel_cr3 >= PHYS_END
        { return Err(ContextError::BadCr3) }
        // Check every live PID in the ownership registry, not just
        // prepared frames: an unprepared READY process also owns its CR3.
        if table.owns_live_cr3(actual_kernel_cr3) {
            return Err(ContextError::ActiveUserCr3)
        }
        if self.snapshot(current_pid).is_none() {
            return Err(ContextError::NotPrepared)
        }
        let mut eligible = 0;
        let mut best_above: Option<StoredUserFrame> = None;
        let mut best_any: Option<StoredUserFrame> = None;
        for ctx in self.entries.iter().flatten().copied() {
            let process = table.snapshot(ctx.pid).ok_or(ContextError::StaleProcess)?;
            if process.cr3_root != ctx.cr3_root { return Err(ContextError::StaleProcess) }
            if process.cr3_root == actual_kernel_cr3 {
                return Err(ContextError::ActiveUserCr3)
            }
            // A BLOCKED PID stays resident and owns its CR3, frames and
            // saved context. Audit that context, but never select it until
            // an independently authorized wake changes its state to READY.
            if !matches!(process.state,
                ProcessState::Ready | ProcessState::Running | ProcessState::Blocked) {
                return Err(ContextError::WrongState)
            }
            if !ctx.kernel_stack.valid() { return Err(ContextError::BadKernelStack) }
            Self::validate_frame(&ctx.frame)?;
            if process.state == ProcessState::Blocked {
                if ctx.pid == current_pid { return Err(ContextError::WrongState) }
                continue;
            }
            if ctx.pid != current_pid {
                eligible += 1;
                if best_any.is_none_or(|old| ctx.pid < old.pid) { best_any = Some(ctx); }
                if ctx.pid > current_pid
                    && best_above.is_none_or(|old| ctx.pid < old.pid) {
                    best_above = Some(ctx);
                }
            }
        }
        if eligible == 0 { return Err(ContextError::OnlyOnePrepared) }
        let next = best_above.or(best_any).ok_or(ContextError::OnlyOnePrepared)?;
        Ok(ResumePlan { pid: next.pid, cr3_root: next.cr3_root,
            rsp0: next.kernel_stack.top, frame: next.frame, origin: next.origin })
    }

    /// Plan an explicitly selected READY PID from a trusted scheduler policy.
    /// This is metadata only: it does NOT prove a timer IRQ, load CR3, switch
    /// TSS/FX state, or execute IRETQ. The caller must independently check the
    /// scheduler's generation-safe handle and authenticate both trap frames.
    ///
    /// Validate the *whole* resident bank first (including a stale unrelated
    /// context), then refuse the current PID or any non-READY destination.
    /// A policy may choose a different READY PID than the PID-order fallback.
    pub fn plan_selected<const N: usize>(
        &self, table: &ProcessTable<SLOTS,N>,
        current_pid: u64, selected_pid: u64, actual_kernel_cr3: u64,
    ) -> Result<ResumePlan, ContextError> {
        if selected_pid == 0 || selected_pid == current_pid {
            return Err(ContextError::InvalidPid)
        }
        // plan_next audits every prepared context and verifies that the
        // supplied supervisor root is not owned by ANY live user process.
        let _ = self.plan_next(table, current_pid, actual_kernel_cr3)?;
        let selected = self.snapshot(selected_pid).ok_or(ContextError::NotPrepared)?;
        let process = table.snapshot(selected_pid).ok_or(ContextError::StaleProcess)?;
        if process.state != ProcessState::Ready {
            return Err(ContextError::WrongState)
        }
        Ok(ResumePlan {
            pid: selected.pid, cr3_root: selected.cr3_root,
            rsp0: selected.kernel_stack.top, frame: selected.frame,
            origin: selected.origin,
        })
    }

    /// Validate a scheduler-selected post-park handoff before any hardware
    /// IRETQ/CR3/TSS/FX action. The *trusted trap handler* must have already
    /// authenticated IRQ/syscall provenance, saved GPR/FX state, and parked
    /// the source in the process registry. No hardware state is changed here.
    ///
    /// Require the last actual timer/yield policy decision to identify the
    /// exact source and destination (a newly woken READY PID is insufficient).
    /// This still does NOT authenticate real IRQ/syscall provenance.
    /// Require exact generation-safe source/destination queue handles and
    /// one policy RUNNING target, then audit every runnable queue member
    /// against resident PID/context ownership. EXited queue tombstones do not
    /// need a live process record. This never attributes a hardware IRQ.
    pub fn plan_queue_handoff<const N: usize>(
        &self, table: &ProcessTable<SLOTS, N>,
        queue: &Ring3RunQueue<SLOTS>,
        from: RunHandle, to: RunHandle, actual_kernel_cr3: u64,
    ) -> Result<ResumePlan, ContextError> {
        if from.pid == 0 || to.pid == 0 || from == to {
            return Err(ContextError::SchedulerMismatch)
        }
        let slots = queue.slots();
        if queue.running() != Some(to)
            || queue.last_policy_handoff() != Some((from, to))
            || !slots.iter().any(|s| s.handle == from && s.state == RunState::Ready)
            || !slots.iter().any(|s| s.handle == to && s.state == RunState::Running)
        { return Err(ContextError::SchedulerMismatch) }
        // All user contexts must be parked before privileged-state
        // restoration. A RUNNING registry owner hidden behind an EXITED
        // policy tombstone must not authorize a second CPU owner.
        if table.running() != 0 {
            return Err(ContextError::WrongState)
        }

        for slot in slots {
            if !matches!(slot.state, RunState::Ready | RunState::Running) {
                continue
            }
            let process = table.snapshot(slot.handle.pid).ok_or(ContextError::StaleProcess)?;
            if process.state != ProcessState::Ready {
                return Err(ContextError::WrongState)
            }
            let stored = self.snapshot(slot.handle.pid).ok_or(ContextError::NotPrepared)?;
            if stored.cr3_root != process.cr3_root {
                return Err(ContextError::StaleProcess)
            }
        }
        self.plan_selected(table, from.pid, to.pid, actual_kernel_cr3)
    }

    /// A context can be removed only after ProcessTable has revoked that
    /// PID via cancellation/reaping; never free a saved live trap frame.
    pub fn retire<const N: usize>(
        &mut self, table: &ProcessTable<SLOTS,N>, pid: u64,
    ) -> Result<(), ContextError> {
        let index = self.entries.iter().position(|e| e.is_some_and(|x| x.pid == pid))
            .ok_or(ContextError::NotPrepared)?;
        if table.snapshot(pid).is_some() { return Err(ContextError::NotRetired) }
        self.entries[index] = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(start: u64) -> [u64;7] {
        core::array::from_fn(|i| start + (i as u64) * 4096)
    }
    fn stack(at: u64) -> KernelStack {
        KernelStack { bottom: at, top: at + KSTACK_BYTES }
    }
    fn frame(rip: u64, marker: u64) -> UserSyscallFrame {
        let mut x = UserSyscallFrame::default();
        x.hardware.rip = rip;
        x.hardware.rsp = 0x405000;
        x.hardware.cs = 0x2b;
        x.hardware.ss = 0x23;
        x.hardware.rflags = 0x2;
        x.registers.rax = marker;
        x.registers.r12 = marker.wrapping_mul(3);
        x
    }
    fn two() -> (ProcessTable<2,7>,UserContextBank<2>) {
        let mut t = ProcessTable::new();
        t.reserve(0x1000,frames(0x1000)).unwrap();
        t.reserve(0x10000,frames(0x10000)).unwrap();
        (t,UserContextBank::new())
    }

    #[test]
    fn four_policy_handoffs_bind_generation_cr3_rsp0_and_full_gprs() {
        let mut table = ProcessTable::<4, 7>::new();
        let mut contexts = UserContextBank::<4>::new();
        let mut queue = Ring3RunQueue::<4>::new();
        let mut handles = [RunHandle { pid: 0, generation: 0 }; 4];
        let roots = [0x10000, 0x20000, 0x30000, 0x40000];
        let bottom = 0xffff_8000_0300_0000;
        for i in 0..4 {
            let pid = table.reserve(roots[i], frames(roots[i])).unwrap();
            handles[i] = queue.admit(pid).unwrap();
            contexts.prepare_bootstrap(
                &table, pid, roots[i],
                stack(bottom + (i as u64) * 0x10000),
                frame(0x401000 + (i as u64) * 0x1000, 200 + pid),
            ).unwrap();
        }
        assert_eq!(queue.start_next(), Ok(handles[0]));
        for turn in 0..32 {
            let from = handles[turn % 4];
            let to = if turn % 2 == 0 {
                queue.timer_tick(from).unwrap()
            } else {
                queue.voluntary_yield(from).unwrap()
            };
            assert_eq!(to, handles[(turn + 1) % 4]);
            let planned = contexts.plan_queue_handoff(
                &table, &queue, from, to, 0x90000,
            ).unwrap();
            assert_eq!(planned.pid, to.pid);
            assert_eq!(planned.cr3_root, roots[(to.pid - 1) as usize]);
            assert_eq!(planned.rsp0,
                bottom + (to.pid - 1) * 0x10000 + KSTACK_BYTES);
            assert_eq!(planned.frame.registers.rax, 200 + to.pid);
            assert_eq!(planned.frame.registers.r12, (200 + to.pid) * 3);
            assert_eq!(planned.origin, FrameOrigin::Bootstrap);
        }
        assert_eq!(queue.timer_switches(), 16,
                   "voluntary syscall yields cannot forge timer switches");
        assert_eq!(table.running(), 0,
                   "policy-only planning cannot start actual user processes");
        assert_eq!(contexts.count(), 4);
    }

    #[test]
    fn wrong_generation_target_or_blocked_source_never_gets_a_resume_plan() {
        let mut table = ProcessTable::<4, 7>::new();
        let mut contexts = UserContextBank::<4>::new();
        let mut queue = Ring3RunQueue::<4>::new();
        let roots = [0x10000, 0x20000, 0x30000, 0x40000];
        let mut h = [RunHandle { pid: 0, generation: 0 }; 4];
        for i in 0..4 {
            let pid = table.reserve(roots[i], frames(roots[i])).unwrap();
            h[i] = queue.admit(pid).unwrap();
            contexts.prepare_bootstrap(
                &table, pid, roots[i],
                stack(0xffff_8000_0400_0000 + (i as u64) * 0x10000),
                frame(0x401000 + (i as u64) * 0x1000, pid),
            ).unwrap();
        }
        queue.start_next().unwrap();
        assert_eq!(queue.timer_tick(h[0]), Ok(h[1]));
        let good = contexts.plan_queue_handoff(&table, &queue, h[0], h[1], 0x90000);
        assert_eq!(good.unwrap().pid, 2);
        let forged_from = RunHandle { generation: h[0].generation + 1, ..h[0] };
        let forged_to = RunHandle { generation: h[1].generation + 1, ..h[1] };
        for (from, to) in [(forged_from, h[1]), (h[0], forged_to),
                           (h[0], h[2]), (h[1], h[1])] {
            assert_eq!(
                contexts.plan_queue_handoff(&table, &queue, from, to, 0x90000),
                Err(ContextError::SchedulerMismatch)
            );
        }
        assert_eq!(contexts.plan_queue_handoff(&table, &queue, h[0], h[1], roots[2]),
            Err(ContextError::ActiveUserCr3));
        table.mark_running(h[2].pid, roots[2]).unwrap();
        assert_eq!(contexts.plan_queue_handoff(&table, &queue, h[0], h[1], 0x90000),
            Err(ContextError::WrongState));
        table.park_running(h[2].pid, roots[2]).unwrap();
        table.cancel_ready(h[2].pid, 0x90000).unwrap();
        assert_eq!(contexts.plan_queue_handoff(&table, &queue, h[0], h[1], 0x90000),
            Err(ContextError::StaleProcess));
        assert_eq!(queue.running(), Some(h[1]));
        assert_eq!(queue.timer_switches(), 1);
    }

    #[test]
    fn absent_unrelated_context_and_blocked_source_fail_closed() {
        let mut table = ProcessTable::<4, 7>::new();
        let mut contexts = UserContextBank::<4>::new();
        let mut queue = Ring3RunQueue::<4>::new();
        let roots = [0x10000, 0x20000, 0x30000, 0x40000];
        let mut h = [RunHandle { pid: 0, generation: 0 }; 4];
        for i in 0..4 {
            let pid = table.reserve(roots[i], frames(roots[i])).unwrap();
            h[i] = queue.admit(pid).unwrap();
            if i != 3 {
                contexts.prepare_bootstrap(
                    &table, pid, roots[i],
                    stack(0xffff_8000_0500_0000 + (i as u64) * 0x10000),
                    frame(0x401000 + (i as u64) * 0x1000, pid),
                ).unwrap();
            }
        }
        queue.start_next().unwrap();
        assert_eq!(queue.timer_tick(h[0]), Ok(h[1]));
        assert_eq!(contexts.plan_queue_handoff(&table, &queue, h[0], h[1], 0x90000),
            Err(ContextError::NotPrepared),
            "a missing fourth READY context invalidates the full ledger");
        contexts.prepare_bootstrap(
            &table, h[3].pid, roots[3],
            stack(0xffff_8000_0503_0000),
            frame(0x404000, 4),
        ).unwrap();
        assert_eq!(contexts.plan_queue_handoff(&table, &queue, h[0], h[1], 0x90000)
            .unwrap().pid, h[1].pid);
        // A RUNNING table process hidden behind a non-runnable queue slot
        // must not coexist with any planned new hardware activation.
        queue.cancel(h[3]).unwrap();
        table.mark_running(h[3].pid, roots[3]).unwrap();
        assert_eq!(contexts.plan_queue_handoff(&table, &queue, h[0], h[1], 0x90000),
            Err(ContextError::WrongState));
        table.park_running(h[3].pid, roots[3]).unwrap();
        assert_eq!(contexts.plan_queue_handoff(&table, &queue, h[0], h[1], 0x90000)
            .unwrap().pid, h[1].pid);
        // h1 becomes BLOCKED and h2 becomes RUNNING. A blocked source is
        // not an authorized timer/yield handoff even if a target is runnable.
        assert_eq!(queue.block_current(h[1]), Ok(Some(h[2])));
        assert_eq!(contexts.plan_queue_handoff(&table, &queue, h[1], h[2], 0x90000),
            Err(ContextError::SchedulerMismatch));
    }

    #[test]
    fn four_private_contexts_follow_explicit_non_pid_order_selection() {
        let mut t = ProcessTable::<4, 7>::new();
        let mut bank = UserContextBank::<4>::new();
        let roots = [0x10000, 0x20000, 0x30000, 0x40000];
        let bottom = 0xffff_8000_0100_0000;
        for i in 0..4 {
            let pid = t.reserve(roots[i], frames(roots[i])).unwrap();
            assert_eq!(pid, (i + 1) as u64);
            bank.prepare_bootstrap(&t, pid, roots[i],
                stack(bottom + (i as u64) * 0x10000),
                frame(0x401000 + (i as u64) * 0x1000, 100 + pid)).unwrap();
        }
        // Deliberately NOT the PID-order sequence used by plan_next.
        for (from, to) in [(1, 4), (4, 2), (2, 3), (3, 1)] {
            let selected = bank.plan_selected(&t, from, to, 0x90000).unwrap();
            assert_eq!(selected.pid, to);
            assert_eq!(selected.cr3_root, roots[(to - 1) as usize]);
            assert_eq!(selected.rsp0,
                bottom + ((to - 1) as u64) * 0x10000 + KSTACK_BYTES);
            assert_eq!(selected.frame.registers.rax, 100 + to);
            assert_eq!(selected.frame.registers.r12, (100 + to) * 3);
            assert_eq!(selected.origin, FrameOrigin::Bootstrap);
        }
        assert_eq!(bank.count(), 4);
        assert_eq!(t.occupied(), 4);
        assert_eq!(t.running(), 0);
    }

    #[test]
    fn selected_context_refuses_running_stale_and_unprepared_targets() {
        let mut t = ProcessTable::<4, 7>::new();
        let mut bank = UserContextBank::<4>::new();
        let roots = [0x10000, 0x20000, 0x30000, 0x40000];
        for i in 0..4 {
            let pid = t.reserve(roots[i], frames(roots[i])).unwrap();
            bank.prepare_bootstrap(&t, pid, roots[i],
                stack(0xffff_8000_0200_0000 + (i as u64) * 0x10000),
                frame(0x401000 + (i as u64) * 0x1000, pid)).unwrap();
        }
        let first = bank.snapshot(1).unwrap();
        assert_eq!(bank.plan_selected(&t, 1, 1, 0x90000),
            Err(ContextError::InvalidPid));
        assert_eq!(bank.plan_selected(&t, 1, 0, 0x90000),
            Err(ContextError::InvalidPid));
        assert_eq!(bank.plan_selected(&t, 1, 99, 0x90000),
            Err(ContextError::NotPrepared));
        assert_eq!(bank.plan_selected(&t, 1, 2, roots[2]),
            Err(ContextError::ActiveUserCr3));
        assert_eq!(bank.plan_selected(&t, 99, 2, 0x90000),
            Err(ContextError::NotPrepared));
        t.mark_running(4, roots[3]).unwrap();
        assert_eq!(bank.plan_selected(&t, 1, 4, 0x90000),
            Err(ContextError::WrongState));
        t.park_running(4, roots[3]).unwrap();
        t.cancel_ready(3, 0x90000).unwrap();
        // A revoked unrelated PID invalidates the *whole* context bank.
        assert_eq!(bank.plan_selected(&t, 1, 2, 0x90000),
            Err(ContextError::StaleProcess));
        bank.retire(&t, 3).unwrap();
        assert_eq!(bank.plan_selected(&t, 1, 3, 0x90000),
            Err(ContextError::NotPrepared));
        assert_eq!(bank.plan_selected(&t, 1, 2, 0x90000).unwrap().pid, 2);
        assert_eq!(bank.snapshot(1), Some(first));
        assert_eq!(bank.count(), 3);
    }

    #[test]
    fn whole_frames_survive_interleaved_selection_and_pid_revocation() {
        let (mut t, mut bank) = two();
        let a = frame(0x401000, 11);
        let b = frame(0x402000, 22);
        bank.prepare_bootstrap(&t, 1, 0x1000, stack(0xffff_8000_0010_0000), a).unwrap();
        bank.prepare_bootstrap(&t, 2, 0x10000, stack(0xffff_8000_0011_0000), b).unwrap();
        for i in 0..128 {
            let from = if i % 2 == 0 { 1 } else { 2 };
            let planned = bank.plan_next(&t, from, 0x90000).unwrap();
            assert_eq!(planned.pid, if from == 1 { 2 } else { 1 });
            assert_eq!(planned.frame, if from == 1 { b } else { a });
            assert_eq!(planned.origin, FrameOrigin::Bootstrap);
        }
        assert_eq!(bank.retire(&t,1),Err(ContextError::NotRetired));
        t.cancel_ready(1,0x90000).unwrap();
        assert_eq!(bank.plan_next(&t,2,0x90000),Err(ContextError::StaleProcess));
        bank.retire(&t,1).unwrap();
        let pid3 = t.reserve(0x20000,frames(0x20000)).unwrap();
        assert_eq!(pid3,3);
        let c = frame(0x403000,33);
        bank.prepare_bootstrap(&t,3,0x20000,stack(0xffff_8000_0010_0000),c).unwrap();
        assert_eq!(bank.plan_next(&t,2,0x90000).unwrap().pid,3);
    }

    #[test]
    fn fails_closed_on_aliasing_kernel_stacks_invalid_frames_and_roots() {
        let (t, mut bank) = two();
        let bottom = 0xffff_8000_0010_0000;
        let clean = frame(0x401000,1);
        bank.prepare_bootstrap(&t,1,0x1000,stack(bottom),clean).unwrap();
        assert_eq!(bank.prepare_bootstrap(&t,2,0x10000,stack(bottom + 0x2000),clean),
            Err(ContextError::KernelStackOverlap));
        assert_eq!(bank.prepare_bootstrap(&t,2,0x1000,stack(bottom + 0x10000),clean),
            Err(ContextError::BadCr3));
        let mut bad = clean;
        bad.hardware.cs = 8;
        assert_eq!(bank.prepare_bootstrap(&t,2,0x10000,stack(bottom + 0x10000),bad),
            Err(ContextError::BadSelectors));
        bad = clean; bad.hardware.rflags = 0x202;
        assert_eq!(bank.prepare_bootstrap(&t,2,0x10000,stack(bottom + 0x10000),bad),
            Err(ContextError::BadFlags));
        bad = clean; bad.hardware.rip = u64::MAX;
        assert_eq!(bank.prepare_bootstrap(&t,2,0x10000,stack(bottom + 0x10000),bad),
            Err(ContextError::BadUserPointer));
        assert_eq!(bank.plan_next(&t,1,0x10000),Err(ContextError::ActiveUserCr3));
        assert_eq!(bank.count(),1);
    }

    #[test]
    fn hardware_capture_requires_running_pid_and_in_stack_iret_frame() {
        let (mut t,mut bank) = two();
        let x = frame(0x401080,73);
        let k = stack(0xffff_8000_0010_0000);
        assert_eq!(bank.capture_trap(&t,1,0x1000,k,k.top - 256,x),
            Err(ContextError::WrongState));
        t.mark_running(1,0x1000).unwrap();
        assert_eq!(bank.capture_trap(&t,1,0x10000,k,k.top - 256,x),
            Err(ContextError::BadCr3));
        assert_eq!(bank.capture_trap(&t,1,0x1000,k,k.bottom,x),
            Ok(()));
        assert_eq!(bank.snapshot(1).unwrap().frame.registers.r12,219);
        assert_eq!(bank.capture_trap(&t,1,0x1000,k,k.top - 16,x),
            Err(ContextError::FrameOutsideKernelStack));
        assert_eq!(bank.count(),1);
    }

    #[test]
    fn woken_ready_pid_cannot_forge_the_source_of_a_resume_plan() {
        let mut table = ProcessTable::<3, 7>::new();
        let mut contexts = UserContextBank::<3>::new();
        let mut queue = Ring3RunQueue::<3>::new();
        let roots = [0x10000, 0x20000, 0x30000];
        let bottom = 0xffff_8000_0600_0000;
        let mut h = [RunHandle { pid: 0, generation: 0 }; 3];
        for i in 0..3 {
            let pid = table.reserve(roots[i], frames(roots[i])).unwrap();
            h[i] = queue.admit(pid).unwrap();
            contexts.prepare_bootstrap(
                &table, pid, roots[i],
                stack(bottom + (i as u64) * 0x10000),
                frame(0x401000 + (i as u64) * 0x1000, 400 + pid),
            ).unwrap();
        }
        assert_eq!(queue.start_next(), Ok(h[0]));
        assert_eq!(queue.block_current(h[0]), Ok(Some(h[1])));
        assert_eq!(contexts.plan_queue_handoff(&table, &queue, h[0], h[1], 0x90000),
            Err(ContextError::SchedulerMismatch),
            "BLOCK does not authorize a hardware timer/yield transition");
        queue.wake(h[0]).unwrap();
        assert_eq!(contexts.plan_queue_handoff(&table, &queue, h[0], h[1], 0x90000),
            Err(ContextError::SchedulerMismatch),
            "READY after wake cannot masquerade as the interrupted PID");

        assert_eq!(queue.timer_tick(h[1]), Ok(h[2]));
        assert_eq!(contexts.plan_queue_handoff(&table, &queue, h[0], h[2], 0x90000),
            Err(ContextError::SchedulerMismatch),
            "an unrelated READY source cannot borrow another PID's IRQ");
        assert_eq!(contexts.plan_queue_handoff(&table, &queue, h[1], h[2], 0x90000)
            .unwrap().pid, h[2].pid);
        assert_eq!(queue.timer_tick(h[2]), Ok(h[0]));
        let resumed = contexts.plan_queue_handoff(
            &table, &queue, h[2], h[0], 0x90000,
        ).unwrap();
        assert_eq!(resumed.pid, h[0].pid);
        assert_eq!(resumed.cr3_root, roots[0]);
        assert_eq!(resumed.rsp0, bottom + KSTACK_BYTES);
        assert_eq!(resumed.frame.registers.rax, 400 + h[0].pid);
        assert_eq!(resumed.frame.registers.r12, (400 + h[0].pid) * 3);
        assert_eq!(resumed.origin, FrameOrigin::Bootstrap);
        assert_eq!(queue.timer_switches(), 2);
        assert_eq!(table.running(), 0, "this is metadata only, not an IRQ proof");
    }

    #[test]
    fn blocked_registry_pid_is_ineligible_until_wake_without_losing_ownership() {
        let mut table = ProcessTable::<3, 7>::new();
        let mut contexts = UserContextBank::<3>::new();
        let mut queue = Ring3RunQueue::<3>::new();
        let roots = [0x10000, 0x20000, 0x30000];
        let bottom = 0xffff_8000_0700_0000;
        let mut h = [RunHandle { pid: 0, generation: 0 }; 3];
        for i in 0..3 {
            let pid = table.reserve(roots[i], frames(roots[i])).unwrap();
            h[i] = queue.admit(pid).unwrap();
            contexts.prepare_bootstrap(
                &table, pid, roots[i],
                stack(bottom + (i as u64) * 0x10000),
                frame(0x401000 + (i as u64) * 0x1000, 500 + pid),
            ).unwrap();
        }
        assert_eq!(queue.start_next(), Ok(h[0]));
        table.mark_running(h[0].pid, roots[0]).unwrap();
        table.block_running(h[0].pid, roots[0]).unwrap();
        assert_eq!(queue.block_current(h[0]), Ok(Some(h[1])));
        assert_eq!(table.running(), 0);
        assert_eq!(table.occupied(), 3);
        assert_eq!(table.snapshot(h[0].pid).unwrap().frames, frames(roots[0]));
        assert_eq!(queue.last_policy_handoff(), None);
        assert_eq!(contexts.plan_next(&table, h[1].pid, 0x90000)
            .unwrap().pid, h[2].pid);
        assert_eq!(contexts.plan_next(&table, h[0].pid, 0x90000),
            Err(ContextError::WrongState),
            "a BLOCKED PID cannot masquerade as the running source");
        assert_eq!(contexts.plan_selected(&table, h[1].pid, h[0].pid, 0x90000),
            Err(ContextError::WrongState),
            "a BLOCKED process still owns its context but cannot resume");

        assert_eq!(queue.timer_tick(h[1]), Ok(h[2]));
        assert_eq!(contexts.plan_queue_handoff(&table, &queue, h[1], h[2], 0x90000)
            .unwrap().pid, h[2].pid);
        table.wake_blocked(h[0].pid, 0x90000).unwrap();
        queue.wake(h[0]).unwrap();
        assert_eq!(queue.timer_tick(h[2]), Ok(h[0]));
        let resumed = contexts.plan_queue_handoff(
            &table, &queue, h[2], h[0], 0x90000,
        ).unwrap();
        assert_eq!(resumed.pid, h[0].pid);
        assert_eq!(resumed.cr3_root, roots[0]);
        assert_eq!(resumed.rsp0, bottom + KSTACK_BYTES);
        assert_eq!(resumed.frame.registers.rax, 500 + h[0].pid);
        assert_eq!(resumed.frame.registers.r12, (500 + h[0].pid) * 3);
        assert_eq!(resumed.origin, FrameOrigin::Bootstrap);
        assert_eq!(contexts.count(), 3, "block/wake never reaps a user context");
        assert_eq!(table.occupied(), 3, "block/wake never releases user PMM frames");
        assert_eq!(table.running(), 0, "policy-only: no hardware IRQ is claimed");
    }

    #[test]
    fn empty_banks_and_unavailable_next_fail_closed() {
        let (t,mut bank) = two();
        assert_eq!(bank.plan_next(&t,1,0x90000),Err(ContextError::NotPrepared));
        bank.prepare_bootstrap(&t,1,0x1000,stack(0xffff_8000_0010_0000),
            frame(0x401000,1)).unwrap();
        assert_eq!(bank.plan_next(&t,1,0x90000),Err(ContextError::OnlyOnePrepared));
        assert_eq!(bank.prepare_bootstrap(&t,1,0x1000,stack(0xffff_8000_0012_0000),
            frame(0x401000,1)),Err(ContextError::AlreadyPrepared));
        assert_eq!(bank.count(),1);
    }
}
