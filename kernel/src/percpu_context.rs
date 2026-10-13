//! Real cooperative register/RSP switches on EACH Limine CPU.
//!
//! A permanently allocated, uniquely CPU-owned pair of kernel TCBs executes
//! on private 8 KiB stacks. Every CPU (BSP and AP) runs its own ready FIFO,
//! drives Ready/Running/Blocked/Finished transitions and verifies real stack
//! resumes. No context or stack is ever shared or migrated between CPUs.
//!
//! The BSP observes AP records ONLY after reading AP_DONE with Acquire order.
//! External interrupts stay disabled. No preemption, cross-CPU migration,
//! ring 3, FPU/SIMD save, TLS/GS or full production thread scheduler.

use core::arch::global_asm;
use core::cell::UnsafeCell;

use crate::context_switch;
use crate::smp::MAX_BOOT_CPUS;
use crate::thread_scheduler::ThreadState;

const THREADS_PER_CPU: usize = 2;
const STACK_BYTES: usize = 8 * 1024;
const ROUNDS: usize = 3;
const EVENTS: usize = THREADS_PER_CPU * ROUNDS;
const MAX_DISPATCHES: usize = EVENTS + THREADS_PER_CPU;
const CANARY: u64 = 0x574F_4C46_5043_5354;
const BANK_BYTES: usize = MAX_BOOT_CPUS * THREADS_PER_CPU * STACK_BYTES;
const MAX_BANK_BYTES: usize = 4 * 1024 * 1024;
const _: () = assert!(BANK_BYTES <= MAX_BANK_BYTES);

#[repr(align(16))]
struct Stack([u8; STACK_BYTES]);

struct Task {
    stack: Stack,
    rsp: usize,
    state: ThreadState,
    progress: usize,
    checksum: u64,
}
impl Task {
    const fn new() -> Self {
        Self {
            stack: Stack([0; STACK_BYTES]),
            rsp: 0,
            state: ThreadState::Ready,
            progress: 0,
            checksum: 0,
        }
    }
}

struct CpuRun {
    tasks: [Task; THREADS_PER_CPU],
    scheduler_rsp: usize,
    ready: [usize; THREADS_PER_CPU],
    head: usize,
    tail: usize,
    ready_count: usize,
    blocked: Option<usize>,
    active: Option<usize>,
    events: [u8; EVENTS],
    event_count: usize,
    dispatches: usize,
    switches: usize,
    yields: usize,
    blocks: usize,
    wakes: usize,
    finished: usize,
    started: bool,
    done: bool,
    bad: bool,
}
impl CpuRun {
    const fn new() -> Self {
        Self {
            tasks: [const { Task::new() }; THREADS_PER_CPU],
            scheduler_rsp: 0,
            ready: [0; THREADS_PER_CPU],
            head: 0,
            tail: 0,
            ready_count: 0,
            blocked: None,
            active: None,
            events: [0; EVENTS],
            event_count: 0,
            dispatches: 0,
            switches: 0,
            yields: 0,
            blocks: 0,
            wakes: 0,
            finished: 0,
            started: false,
            done: false,
            bad: false,
        }
    }
    fn enqueue(&mut self, task: usize) -> bool {
        if task >= THREADS_PER_CPU || self.ready_count == THREADS_PER_CPU {
            return false;
        }
        self.ready[self.tail] = task;
        self.tail = (self.tail + 1) % THREADS_PER_CPU;
        self.ready_count += 1;
        true
    }
    fn pop(&mut self) -> Option<usize> {
        if self.ready_count == 0 { return None; }
        let task = self.ready[self.head];
        self.head = (self.head + 1) % THREADS_PER_CPU;
        self.ready_count -= 1;
        Some(task)
    }
    fn wake(&mut self) -> bool {
        // TCB 1 blocks on its first event. Wake only after TCB 0 has had
        // a further opportunity to execute (three total dispatches).
        if self.dispatches < 3 { return true; }
        let Some(task) = self.blocked else { return true; };
        if self.tasks[task].state != ThreadState::Blocked { return false; }
        self.tasks[task].state = ThreadState::Ready;
        if !self.enqueue(task) { return false; }
        self.blocked = None;
        self.wakes += 1;
        true
    }
}

struct CpuSlot(UnsafeCell<CpuRun>);

// SAFETY: a slot is owned exclusively by the CPU with the matching Limine
// directory index. Its mutable references never cross a context switch.
// BSP reads AP slots only after the AP publishes AP_DONE with Release and
// BSP observes that with Acquire. APs cannot subsequently mutate the slot.
unsafe impl Sync for CpuSlot {}

impl CpuSlot {
    const fn new() -> Self { Self(UnsafeCell::new(CpuRun::new())) }
}
static CPUS: [CpuSlot; MAX_BOOT_CPUS] =
    [const { CpuSlot::new() }; MAX_BOOT_CPUS];

fn with_cpu<T>(cpu: usize, operation: impl FnOnce(&mut CpuRun) -> T) -> T {
    // SAFETY: unique CPU owner, no overlapping mutable borrow across
    // register/RSP switching, and no reentrant interrupt access.
    unsafe { operation(&mut *CPUS[cpu].0.get()) }
}
fn scheduler_rsp(cpu: usize) -> *mut usize {
    // SAFETY: CPU slot is validated by the caller, form raw pointer only.
    unsafe { core::ptr::addr_of_mut!((*CPUS[cpu].0.get()).scheduler_rsp) }
}
fn thread_rsp(cpu: usize, id: usize) -> *mut usize {
    // SAFETY: both indexes are validated, and TCB stack stays allocated.
    unsafe { core::ptr::addr_of_mut!((*CPUS[cpu].0.get()).tasks[id].rsp) }
}
fn stack_base(cpu: usize, id: usize) -> usize {
    // SAFETY: indexes valid; no aliasing Rust reference is created.
    let raw = unsafe { core::ptr::addr_of_mut!((*CPUS[cpu].0.get()).tasks[id].stack) };
    raw.cast::<u8>() as usize
}

// r12 = CPU directory index, r13 = task ID. The initial synthetic switch
// frame loads them via the six callee-saved pops. Then the trampoline passes
// the arguments in RDI/RSI and realigns RSP for the SysV call ABI.
global_asm!(
    ".global wolfos_percpu_context_start",
    ".type wolfos_percpu_context_start, @function",
    "wolfos_percpu_context_start:",
    "mov rdi, r12",
    "mov rsi, r13",
    "sub rsp, 8",
    "call wolfos_percpu_context_rust",
    "ud2",
);
unsafe extern "C" {
    fn wolfos_percpu_context_start();
}

fn prepare(cpu: usize, id: usize) -> bool {
    if cpu >= MAX_BOOT_CPUS || id >= THREADS_PER_CPU { return false; }
    let base = stack_base(cpu, id);
    let Some(top) = base.checked_add(STACK_BYTES) else { return false; };
    if base % 16 != 0 || top % 16 != 0 { return false; }
    // Saved layout: r15,r14,r13,r12,rbp,rbx,PC,unused.
    // First RET enters trampoline with RSP % 16 == 8.
    const WORDS: usize = 8;
    let rsp = top - WORDS * core::mem::size_of::<usize>();
    // SAFETY: this CPU owns the never-used stack, during its bootstrap.
    unsafe {
        (base as *mut u64).write_volatile(CANARY ^ ((cpu as u64) << 16) ^ id as u64);
        core::ptr::write_bytes(rsp as *mut u8, 0, WORDS * 8);
        (rsp as *mut usize).add(2).write(id);  // r13
        (rsp as *mut usize).add(3).write(cpu); // r12
        (rsp as *mut usize).add(6).write(wolfos_percpu_context_start as usize);
    }
    with_cpu(cpu, |c| c.tasks[id].rsp = rsp);
    true
}

fn stack_ok(cpu: usize, id: usize) -> bool {
    if cpu >= MAX_BOOT_CPUS || id >= THREADS_PER_CPU { return false; }
    let base = stack_base(cpu, id);
    let found = unsafe { (base as *const u64).read_volatile() };
    found == (CANARY ^ ((cpu as u64) << 16) ^ id as u64)
}
fn resume_pointer_ok(cpu: usize, id: usize, rsp: usize) -> bool {
    let base = stack_base(cpu, id);
    rsp >= base + 512 && rsp < base + STACK_BYTES
}
fn digest(prior: u64, cpu: usize, id: usize, round: usize) -> u64 {
    (prior ^ (cpu as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
       ^ (id as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9)
       ^ (round as u64).wrapping_mul(0x94D0_49BB_1331_11EB))
        .rotate_left(11).wrapping_mul(0xD6E8_FEB8_6659_FD93)
}

fn execute_step(cpu: usize, id: usize, round: usize, checksum: u64) -> bool {
    with_cpu(cpu, |c| {
        if c.active != Some(id) ||
           c.tasks[id].state != ThreadState::Running ||
           c.tasks[id].progress != round ||
           c.event_count >= EVENTS
        {
            c.bad = true;
            return false;
        }
        c.events[c.event_count] = id as u8;
        c.event_count += 1;
        c.tasks[id].progress += 1;
        c.tasks[id].checksum = checksum;
        if round + 1 == ROUNDS {
            c.tasks[id].state = ThreadState::Finished;
            c.finished += 1;
        } else if id == 1 && round == 0 {
            c.tasks[id].state = ThreadState::Blocked;
            if c.blocked.replace(id).is_some() {
                c.bad = true;
                return false;
            }
            c.blocks += 1;
        } else {
            c.tasks[id].state = ThreadState::Ready;
            if !c.enqueue(id) {
                c.bad = true;
                return false;
            }
            c.yields += 1;
        }
        c.active = None;
        true
    })
}

#[unsafe(no_mangle)]
extern "C" fn wolfos_percpu_context_rust(cpu: usize, id: usize) -> ! {
    if cpu >= MAX_BOOT_CPUS || id >= THREADS_PER_CPU {
        crate::halt_forever();
    }
    let mut checksum = 0u64;
    for round in 0..ROUNDS {
        if !stack_ok(cpu, id) { crate::halt_forever(); }
        checksum = digest(checksum, cpu, id, round + 1);
        if !execute_step(cpu, id, round, checksum) {
            crate::halt_forever();
        }
        with_cpu(cpu, |c| c.switches += 1);
        // SAFETY: only this CPU can touch either raw saved-RSP slot.
        // All mutable TCB borrows ended before the context switch.
        unsafe { context_switch::switch_raw(thread_rsp(cpu, id), scheduler_rsp(cpu)); }
        if round + 1 == ROUNDS { crate::halt_forever(); }
    }
    crate::halt_forever()
}

/// Execute two real, suspended/resumed Rust threads on the caller's own CPU.
/// Each CPU uses ONLY its own slot, with IRQs disabled. No serial writes.
pub fn run(cpu: usize) -> bool {
    if cpu >= MAX_BOOT_CPUS { return false; }
    x86_64::instructions::interrupts::disable();
    if !with_cpu(cpu, |c| {
        if c.started { return false; }
        c.started = true;
        true
    }) {
        return false;
    }
    for id in 0..THREADS_PER_CPU {
        if !prepare(cpu, id) || !with_cpu(cpu, |c| c.enqueue(id)) {
            return false;
        }
    }
    for _ in 0..MAX_DISPATCHES {
        let selected = with_cpu(cpu, |c| {
            if !c.wake() { c.bad = true; return None; }
            let id = c.pop()?;
            if c.tasks[id].state != ThreadState::Ready {
                c.bad = true;
                return None;
            }
            c.tasks[id].state = ThreadState::Running;
            c.active = Some(id);
            c.dispatches += 1;
            c.switches += 1;
            Some(id)
        });
        let Some(id) = selected else { break; };
        // SAFETY: each task frame is initialized or was suspended by
        // this same CPU. IRQs masked, no shared TCB data or active borrow.
        unsafe { context_switch::switch_raw(scheduler_rsp(cpu), thread_rsp(cpu, id)); }
        if !stack_ok(cpu, id) ||
            with_cpu(cpu, |c| c.bad || c.active.is_some())
        {
            return false;
        }
    }
    let good = check_cpu(cpu, false);
    if good {
        with_cpu(cpu, |c| c.done = true);
    }
    good
}

// For caller CPU and, after an AP_DONE Acquire, for BSP reading an AP's slot.
fn check_cpu(cpu: usize, require_done: bool) -> bool {
    if cpu >= MAX_BOOT_CPUS { return false; }
    let valid = with_cpu(cpu, |c| {
        if !c.started || c.bad ||
            (require_done && !c.done) ||
            c.dispatches != EVENTS || c.switches != EVENTS * 2 ||
            c.event_count != EVENTS || c.ready_count != 0 ||
            c.active.is_some() || c.blocked.is_some() ||
            c.yields != 3 || c.blocks != 1 || c.wakes != 1 ||
            c.finished != THREADS_PER_CPU ||
            c.events != [0, 1, 0, 0, 1, 1]
        {
            return false;
        }
        for id in 0..THREADS_PER_CPU {
            let t = &c.tasks[id];
            if t.state != ThreadState::Finished ||
                t.progress != ROUNDS ||
                !resume_pointer_ok(cpu, id, t.rsp)
            {
                return false;
            }
            let mut expected = 0u64;
            for step in 1..=ROUNDS {
                expected = digest(expected, cpu, id, step);
            }
            if expected != t.checksum { return false; }
        }
        true
    });
    valid && (0..THREADS_PER_CPU).all(|id| stack_ok(cpu, id))
}

/// BSP only: AP_DONE Release/Acquire has ordered all per-core writes.
/// An unstarted or partially completed processor is a failed test.
pub fn verify_all(cpu_count: usize) -> bool {
    if cpu_count == 0 || cpu_count > MAX_BOOT_CPUS { return false; }
    (0..cpu_count).all(|cpu| check_cpu(cpu, true))
}

pub const THREADS_PER_PROCESSOR: usize = THREADS_PER_CPU;
pub const SWITCHES_PER_PROCESSOR: usize = EVENTS * 2;
pub const YIELDS_PER_PROCESSOR: usize = 3;
pub const STACK_KIB: usize = STACK_BYTES / 1024;
pub const MAX_BANK_KIB: usize = BANK_BYTES / 1024;
