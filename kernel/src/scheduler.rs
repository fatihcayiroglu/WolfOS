//! WolfOS early cooperative SMP job dispatcher (no_std).
//!
//! There is one static bounded batch of deterministic kernel jobs. Each CPU
//! executes a unique seed job (guaranteeing genuine participation) and then
//! claims further jobs from a shared atomic FIFO index. A per-job state and
//! digest prove exactly-once completion after the SMP completion barrier.
//!
//! NOT a preemptive scheduler, runnable thread queue, context switch, timer,
//! or userspace interface. One boot-time batch only; no dynamic allocation.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};

pub const MAX_WORKERS: usize = 256;
pub const JOB_COUNT: usize = 512;
const HASH_ROUNDS: usize = 512;
const PENDING: u8 = 0;
const RUNNING: u8 = 1;
const FINISHED: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub jobs: usize,
    pub workers: usize,
    pub active_cpus: usize,
    pub bsp_jobs: usize,
    pub ap_jobs: usize,
}

pub struct JobQueue {
    workers: AtomicUsize,
    next: AtomicUsize,
    completed: AtomicUsize,
    error: AtomicBool,
    states: [AtomicU8; JOB_COUNT],
    outputs: [AtomicU64; JOB_COUNT],
    counts: [AtomicUsize; MAX_WORKERS],
}

impl JobQueue {
    pub const fn new() -> Self {
        Self {
            workers: AtomicUsize::new(0),
            next: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            error: AtomicBool::new(false),
            states: [const { AtomicU8::new(PENDING) }; JOB_COUNT],
            outputs: [const { AtomicU64::new(0) }; JOB_COUNT],
            counts: [const { AtomicUsize::new(0) }; MAX_WORKERS],
        }
    }

    /// BSP only: initialize exactly once before any AP is released.
    pub fn configure(&self, workers: usize) -> bool {
        if !(1..=MAX_WORKERS).contains(&workers) || workers > JOB_COUNT {
            return false;
        }
        if self.workers.load(Ordering::Relaxed) != 0 {
            return false;
        }
        // With no APs running, initialize the shared claim cursor first.
        self.next.store(workers, Ordering::Relaxed);
        self.workers.store(workers, Ordering::Release);
        true
    }

    fn digest(id: usize) -> u64 {
        let mut x = 0x574F_4C46_4A4F_4253_u64 ^ id as u64;
        for round in 0..HASH_ROUNDS {
            x ^= (round as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            x = x.rotate_left(9).wrapping_mul(0xD6E8_FEB8_6659_FD93);
        }
        x
    }

    fn execute(&self, cpu: usize, id: usize) -> bool {
        if id >= JOB_COUNT ||
            self.states[id].compare_exchange(
                PENDING, RUNNING, Ordering::AcqRel, Ordering::Acquire
            ).is_err()
        {
            self.error.store(true, Ordering::Release);
            return false;
        }

        let result = Self::digest(id);
        self.outputs[id].store(result, Ordering::Relaxed);
        self.states[id].store(FINISHED, Ordering::Release);
        self.counts[cpu].fetch_add(1, Ordering::Relaxed);
        self.completed.fetch_add(1, Ordering::Release);
        true
    }

    /// Run the boot CPU's or AP's cooperative worker until no jobs remain.
    /// Each CPU first executes job #cpu (an affinity seed) before claiming
    /// the remainder with fetch_add. Every job is checked for double claims.
    pub fn run_worker(&self, cpu: usize) -> bool {
        let workers = self.workers.load(Ordering::Acquire);
        if workers == 0 || cpu >= workers { return false; }
        if !self.execute(cpu, cpu) { return false; }
        loop {
            let task = self.next.fetch_add(1, Ordering::Relaxed);
            if task >= JOB_COUNT { break; }
            if !self.execute(cpu, task) { return false; }
        }
        true
    }

    /// BSP only. Call after all APs published release-ordered completion.
    /// Rejects unfinished, duplicate, incorrect or unaccounted jobs.
    pub fn verify(&self, bsp_cpu: usize) -> Option<Report> {
        let workers = self.workers.load(Ordering::Acquire);
        if workers == 0 || bsp_cpu >= workers ||
            self.error.load(Ordering::Acquire) ||
            self.completed.load(Ordering::Acquire) != JOB_COUNT
        {
            return None;
        }
        let mut accounted = 0usize;
        for id in 0..JOB_COUNT {
            if self.states[id].load(Ordering::Acquire) != FINISHED ||
               self.outputs[id].load(Ordering::Relaxed) != Self::digest(id)
            {
                return None;
            }
        }
        for cpu in 0..MAX_WORKERS {
            let count = self.counts[cpu].load(Ordering::Relaxed);
            if cpu < workers && count == 0 { return None; }
            if cpu >= workers && count != 0 { return None; }
            accounted = accounted.checked_add(count)?;
        }
        if accounted != JOB_COUNT { return None; }
        let bsp_jobs = self.counts[bsp_cpu].load(Ordering::Relaxed);
        Some(Report {
            jobs: JOB_COUNT,
            workers,
            active_cpus: workers,
            bsp_jobs,
            ap_jobs: JOB_COUNT - bsp_jobs,
        })
    }
}

pub static BOOT_QUEUE: JobQueue = JobQueue::new();

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn parallel_test(cpu_count: usize) {
        let queue = JobQueue::new();
        assert!(queue.configure(cpu_count));
        assert!(queue.verify(0).is_none(), "unfinished work cannot be certified");
        thread::scope(|scope| {
            let jobs = &queue;
            for cpu in 1..cpu_count {
                scope.spawn(move || assert!(jobs.run_worker(cpu)));
            }
            assert!(jobs.run_worker(0));
        });
        let report = queue.verify(0).expect("every job must run exactly once");
        assert_eq!(report.jobs, JOB_COUNT);
        assert_eq!(report.active_cpus, cpu_count);
        assert_eq!(report.bsp_jobs + report.ap_jobs, JOB_COUNT);
        assert!(!queue.configure(cpu_count), "queue is one-shot");
        assert!(!queue.run_worker(0), "CPU cannot replay its seed job");
        assert!(queue.verify(0).is_none(), "duplicate attempt taints queue");
    }

    #[test]
    fn one_cpu() { parallel_test(1); }
    #[test]
    fn four_cpus() { parallel_test(4); }
    #[test]
    fn sixteen_cpus() { parallel_test(16); }

    #[test]
    fn initialization_and_partial_work_fail_closed() {
        let queue = JobQueue::new();
        assert!(!queue.configure(0));
        assert!(!queue.configure(MAX_WORKERS + 1));
        assert!(!queue.run_worker(0));
        assert!(queue.configure(4));
        assert!(!queue.run_worker(4));
        assert!(queue.run_worker(0));
        assert!(queue.verify(0).is_none(), "three CPUs never ran seed tasks");
    }
}
