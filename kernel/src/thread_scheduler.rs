//! WolfOS P1 experimental kernel task control blocks and per-CPU run queues.
//!
//! Each CPU owns an independent ready/blocked FIFO and executes cooperative
//! state-machine task *steps*. Tasks have Ready, Running, Blocked and Finished
//! states, and explicit yield/block/wake transitions. This is NOT a saved
//! register/stack context switch, a preemptive scheduler, nor user processes.
//! All structures are statically bounded for the boot acceptance milestone.
//!
//! APIC interrupts remain disabled; queue locks MUST NOT be reentered from
//! interrupt handlers. Future preemption will require IRQ-safe locks.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};

pub const MAX_CPUS: usize = 256;
pub const THREAD_COUNT: usize = 256;
const STEPS_PER_THREAD: u8 = 4;
const EMPTY: u8 = 0;
const READY: u8 = 1;
const RUNNING: u8 = 2;
const BLOCKED: u8 = 3;
const FINISHED: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadState {
    Ready,
    Running,
    Blocked,
    Finished,
}
impl ThreadState {
    fn decode(value: u8) -> Option<Self> {
        match value {
            READY => Some(Self::Ready),
            RUNNING => Some(Self::Running),
            BLOCKED => Some(Self::Blocked),
            FINISHED => Some(Self::Finished),
            _ => None,
        }
    }
}

struct Thread {
    state: AtomicU8,
    progress: AtomicU8,
    digest: AtomicU64,
}
impl Thread {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EMPTY),
            progress: AtomicU8::new(0),
            digest: AtomicU64::new(0),
        }
    }
}

/// Two fixed FIFOs, each sized to hold every TCB in the worst case.
struct QueueInner {
    ready: [usize; THREAD_COUNT],
    ready_head: usize,
    ready_tail: usize,
    ready_count: usize,
    blocked: [usize; THREAD_COUNT],
    blocked_head: usize,
    blocked_tail: usize,
    blocked_count: usize,
}
impl QueueInner {
    const fn new() -> Self {
        Self {
            ready: [0; THREAD_COUNT],
            ready_head: 0,
            ready_tail: 0,
            ready_count: 0,
            blocked: [0; THREAD_COUNT],
            blocked_head: 0,
            blocked_tail: 0,
            blocked_count: 0,
        }
    }

    fn push_ready(&mut self, tid: usize) -> bool {
        if self.ready_count == THREAD_COUNT { return false; }
        self.ready[self.ready_tail] = tid;
        self.ready_tail = (self.ready_tail + 1) % THREAD_COUNT;
        self.ready_count += 1;
        true
    }
    fn pop_ready(&mut self) -> Option<usize> {
        if self.ready_count == 0 { return None; }
        let tid = self.ready[self.ready_head];
        self.ready_head = (self.ready_head + 1) % THREAD_COUNT;
        self.ready_count -= 1;
        Some(tid)
    }
    fn push_blocked(&mut self, tid: usize) -> bool {
        if self.blocked_count == THREAD_COUNT { return false; }
        self.blocked[self.blocked_tail] = tid;
        self.blocked_tail = (self.blocked_tail + 1) % THREAD_COUNT;
        self.blocked_count += 1;
        true
    }
    fn pop_blocked(&mut self) -> Option<usize> {
        if self.blocked_count == 0 { return None; }
        let tid = self.blocked[self.blocked_head];
        self.blocked_head = (self.blocked_head + 1) % THREAD_COUNT;
        self.blocked_count -= 1;
        Some(tid)
    }
}

struct PerCpuQueue {
    held: AtomicBool,
    inner: UnsafeCell<QueueInner>,
}

// SAFETY: all mutable access to each QueueInner is serialized by held
// (Acquire/Release). No references to the inner storage escape a locked call.
// Never call queue methods from interrupts until IRQ-safe locking exists.
unsafe impl Sync for PerCpuQueue {}

impl PerCpuQueue {
    const fn new() -> Self {
        Self {
            held: AtomicBool::new(false),
            inner: UnsafeCell::new(QueueInner::new()),
        }
    }

    fn with<T>(&self, action: impl FnOnce(&mut QueueInner) -> T) -> T {
        while self.held.compare_exchange_weak(
            false, true, Ordering::Acquire, Ordering::Relaxed
        ).is_err() {
            core::hint::spin_loop();
        }
        struct Release<'a>(&'a AtomicBool);
        impl Drop for Release<'_> {
            fn drop(&mut self) { self.0.store(false, Ordering::Release); }
        }
        let _release = Release(&self.held);
        // SAFETY: the current caller exclusively holds the atomic lock.
        action(unsafe { &mut *self.inner.get() })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadReport {
    pub threads: usize,
    pub cpus: usize,
    pub active: usize,
    pub yielded: usize,
    pub blocked: usize,
    pub woken: usize,
    pub finished: usize,
}

pub struct TaskManager {
    configured: AtomicUsize,
    tcb: [Thread; THREAD_COUNT],
    per_cpu: [PerCpuQueue; MAX_CPUS],
    per_cpu_finished: [AtomicUsize; MAX_CPUS],
    yields: AtomicUsize,
    blocks: AtomicUsize,
    wakes: AtomicUsize,
    finished: AtomicUsize,
    error: AtomicBool,
}

impl TaskManager {
    pub const fn new() -> Self {
        Self {
            configured: AtomicUsize::new(0),
            tcb: [const { Thread::new() }; THREAD_COUNT],
            per_cpu: [const { PerCpuQueue::new() }; MAX_CPUS],
            per_cpu_finished: [const { AtomicUsize::new(0) }; MAX_CPUS],
            yields: AtomicUsize::new(0),
            blocks: AtomicUsize::new(0),
            wakes: AtomicUsize::new(0),
            finished: AtomicUsize::new(0),
            error: AtomicBool::new(false),
        }
    }

    /// BSP-only, one shot. No secondary CPU may be running yet.
    pub fn configure(&self, cpus: usize) -> bool {
        if !(1..=MAX_CPUS).contains(&cpus) || cpus > THREAD_COUNT ||
            self.configured.load(Ordering::Relaxed) != 0
        {
            return false;
        }
        for tid in 0..THREAD_COUNT {
            let cpu = tid % cpus;
            self.tcb[tid].state.store(READY, Ordering::Relaxed);
            if !self.per_cpu[cpu].with(|q| q.push_ready(tid)) {
                self.error.store(true, Ordering::Release);
                return false;
            }
        }
        self.configured.store(cpus, Ordering::Release);
        true
    }

    pub fn thread_state(&self, tid: usize) -> Option<ThreadState> {
        ThreadState::decode(self.tcb.get(tid)?.state.load(Ordering::Acquire))
    }

    fn step_digest(before: u64, tid: usize, step: u8) -> u64 {
        (before ^ (tid as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ (step as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9))
            .rotate_left(13).wrapping_mul(0xD6E8_FEB8_6659_FD93)
    }

    fn expected_digest(tid: usize) -> u64 {
        let mut x = 0u64;
        for step in 1..=STEPS_PER_THREAD {
            x = Self::step_digest(x, tid, step);
        }
        x
    }

    fn transition(&self, tid: usize, from: u8, to: u8) -> bool {
        if self.tcb[tid].state.compare_exchange(
            from, to, Ordering::AcqRel, Ordering::Acquire
        ).is_err() {
            self.error.store(true, Ordering::Release);
            return false;
        }
        true
    }

    fn run_step(&self, cpu: usize, tid: usize) -> bool {
        if tid >= THREAD_COUNT || tid % self.configured.load(Ordering::Acquire) != cpu {
            self.error.store(true, Ordering::Release);
            return false;
        }
        if !self.transition(tid, READY, RUNNING) { return false; }
        let thread = &self.tcb[tid];
        let next = thread.progress.load(Ordering::Relaxed) + 1;
        if next > STEPS_PER_THREAD {
            self.error.store(true, Ordering::Release);
            return false;
        }
        let prior = thread.digest.load(Ordering::Relaxed);
        thread.digest.store(Self::step_digest(prior, tid, next), Ordering::Relaxed);
        thread.progress.store(next, Ordering::Relaxed);

        if next == STEPS_PER_THREAD {
            if !self.transition(tid, RUNNING, FINISHED) { return false; }
            self.per_cpu_finished[cpu].fetch_add(1, Ordering::Relaxed);
            self.finished.fetch_add(1, Ordering::Release);
        } else if next == 2 {
            if !self.transition(tid, RUNNING, BLOCKED) { return false; }
            if !self.per_cpu[cpu].with(|q| q.push_blocked(tid)) {
                self.error.store(true, Ordering::Release);
                return false;
            }
            self.blocks.fetch_add(1, Ordering::Release);
        } else {
            if !self.transition(tid, RUNNING, READY) { return false; }
            if !self.per_cpu[cpu].with(|q| q.push_ready(tid)) {
                self.error.store(true, Ordering::Release);
                return false;
            }
            self.yields.fetch_add(1, Ordering::Release);
        }
        true
    }

    /// Execute the CPU's task-state steps cooperatively. This function never
    /// changes RSP, saves registers, or dispatches user-mode instructions.
    /// When no task is ready, it explicitly wakes one blocked local task.
    pub fn run_cpu(&self, cpu: usize) -> bool {
        let cpus = self.configured.load(Ordering::Acquire);
        if cpu >= cpus || cpus == 0 { return false; }

        loop {
            if let Some(tid) = self.per_cpu[cpu].with(|q| q.pop_ready()) {
                if !self.run_step(cpu, tid) { return false; }
                continue;
            }

            let blocked = self.per_cpu[cpu].with(|q| q.pop_blocked());
            let Some(tid) = blocked else { break; };
            if !self.transition(tid, BLOCKED, READY) { return false; }
            if !self.per_cpu[cpu].with(|q| q.push_ready(tid)) {
                self.error.store(true, Ordering::Release);
                return false;
            }
            self.wakes.fetch_add(1, Ordering::Release);
        }
        true
    }

    /// BSP-only, after all workers have returned and AP_DONE Acquire observed.
    pub fn verify(&self) -> Option<ThreadReport> {
        let cpus = self.configured.load(Ordering::Acquire);
        if cpus == 0 || self.error.load(Ordering::Acquire) ||
            self.finished.load(Ordering::Acquire) != THREAD_COUNT
        {
            return None;
        }
        let yields = self.yields.load(Ordering::Acquire);
        let blocks = self.blocks.load(Ordering::Acquire);
        let wakes = self.wakes.load(Ordering::Acquire);
        if yields != THREAD_COUNT * 2 ||
            blocks != THREAD_COUNT || wakes != THREAD_COUNT
        {
            return None;
        }

        for tid in 0..THREAD_COUNT {
            let thread = &self.tcb[tid];
            if self.thread_state(tid) != Some(ThreadState::Finished) ||
                thread.progress.load(Ordering::Relaxed) != STEPS_PER_THREAD ||
                thread.digest.load(Ordering::Relaxed) != Self::expected_digest(tid)
            {
                return None;
            }
        }

        let mut completed = 0usize;
        for cpu in 0..MAX_CPUS {
            let amount = self.per_cpu_finished[cpu].load(Ordering::Relaxed);
            if cpu < cpus && amount == 0 { return None; }
            if cpu >= cpus && amount != 0 { return None; }
            completed = completed.checked_add(amount)?;
            let empty = self.per_cpu[cpu].with(|q| q.ready_count == 0 && q.blocked_count == 0);
            if !empty { return None; }
        }
        if completed != THREAD_COUNT { return None; }
        Some(ThreadReport {
            threads: THREAD_COUNT, cpus, active: cpus,
            yielded: yields, blocked: blocks, woken: wakes, finished: completed,
        })
    }
}

pub static BOOT_TASKS: TaskManager = TaskManager::new();

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    // Use permanent test fixtures like BOOT_TASKS: large static runqueue
    // arrays must NOT be constructed on the Rust test harness's 2 MiB stack.
    fn verify_multicore(cpus: usize, manager: &'static TaskManager) {
        assert!(manager.configure(cpus));
        assert_eq!(manager.thread_state(0), Some(ThreadState::Ready));
        assert!(manager.verify().is_none());
        thread::scope(|scope| {
            for cpu in 1..cpus {
                let manager = &manager;
                scope.spawn(move || assert!(manager.run_cpu(cpu)));
            }
            assert!(manager.run_cpu(0));
        });
        let report = manager.verify().expect("all task states and digests verified");
        assert_eq!(report.finished, THREAD_COUNT);
        assert_eq!(report.yielded, THREAD_COUNT * 2);
        assert_eq!(report.blocked, THREAD_COUNT);
        assert_eq!(report.woken, THREAD_COUNT);
        assert_eq!(report.active, cpus);
        assert_eq!(manager.thread_state(0), Some(ThreadState::Finished));
        assert!(!manager.configure(cpus), "one-shot boot setup");
    }

    #[test]
    fn runs_one_cpu() {
        static MANAGER: TaskManager = TaskManager::new();
        verify_multicore(1, &MANAGER);
    }
    #[test]
    fn runs_four_cpus() {
        static MANAGER: TaskManager = TaskManager::new();
        verify_multicore(4, &MANAGER);
    }
    #[test]
    fn runs_sixteen_cpus() {
        static MANAGER: TaskManager = TaskManager::new();
        verify_multicore(16, &MANAGER);
    }

    #[test]
    fn refuses_invalid_and_incomplete_execution() {
        static MANAGER: TaskManager = TaskManager::new();
        let manager = &MANAGER;
        assert!(!manager.run_cpu(0));
        assert!(!manager.configure(0));
        assert!(!manager.configure(MAX_CPUS + 1));
        assert_eq!(manager.thread_state(THREAD_COUNT), None);
        assert!(manager.configure(4));
        assert!(!manager.run_cpu(4));
        assert!(manager.run_cpu(0));
        assert!(manager.verify().is_none(), "three CPU queues were left pending");
    }
}
