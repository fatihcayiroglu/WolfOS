//! Generic indexed, stack-backed kernel TCBs: 256-task BSP acceptance.
//!
//! Uses the same ThreadState lifecycle as the existing 256-task SMP
//! state-machine scheduler, but every task here has its *own real* Rust
//! call stack and saved RSP. New contexts all enter through ONE x86-64
//! trampoline that supplies the TCB index in r12 -> rdi.
//!
//! Single-core cooperative prototype: APs are parked, IRQs stay disabled,
//! FPU/SIMD, TLS/GS, CR3 switching and context migration are NOT supported.

use core::arch::global_asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::context_switch;
use crate::serial;
use crate::thread_scheduler::{ThreadState, THREAD_COUNT};

pub const CONTEXT_TASKS: usize = 256;
const STACK_BYTES: usize = 16 * 1024;
const STACK_BANK_BYTES: usize = CONTEXT_TASKS * STACK_BYTES;
const MAX_STACK_BANK_BYTES: usize = 4 * 1024 * 1024;
// Reject accidental static kernel-stack expansion, TCB overflow or event ID truncation.
const _: () = assert!(STACK_BANK_BYTES <= MAX_STACK_BANK_BYTES);
const _: () = assert!(CONTEXT_TASKS <= THREAD_COUNT);
const _: () = assert!(CONTEXT_TASKS <= u8::MAX as usize + 1);
const ROUNDS: usize = 4;
const EXPECTED_EVENTS: usize = CONTEXT_TASKS * ROUNDS;
const MAX_DISPATCHES: usize = EXPECTED_EVENTS + CONTEXT_TASKS;
const CANARY: u64 = 0x574F_4C46_4241_5443;
const BLOCKED_ID: usize = 1;
const WAKE_AFTER_DISPATCHES: usize = 20;

#[repr(align(16))]
struct Stack([u8; STACK_BYTES]);

struct Tcb {
    stack: Stack,
    saved_rsp: usize,
    state: ThreadState,
    progress: usize,
    digest: u64,
}

impl Tcb {
    const fn new() -> Self {
        Self {
            stack: Stack([0; STACK_BYTES]),
            saved_rsp: 0,
            state: ThreadState::Ready,
            progress: 0,
            digest: 0,
        }
    }
}

struct Dispatcher {
    tcbs: [Tcb; CONTEXT_TASKS],
    bsp_rsp: usize,
    ready: [usize; CONTEXT_TASKS],
    head: usize,
    tail: usize,
    ready_len: usize,
    active: Option<usize>,
    blocked: Option<usize>,
    events: [u8; EXPECTED_EVENTS],
    events_len: usize,
    dispatches: usize,
    switches: usize,
    yields: usize,
    blocks: usize,
    wakes: usize,
    finished: usize,
    corrupt: bool,
}

impl Dispatcher {
    const fn new() -> Self {
        Self {
            tcbs: [const { Tcb::new() }; CONTEXT_TASKS],
            bsp_rsp: 0,
            ready: [0; CONTEXT_TASKS],
            head: 0,
            tail: 0,
            ready_len: 0,
            active: None,
            blocked: None,
            events: [0; EXPECTED_EVENTS],
            events_len: 0,
            dispatches: 0,
            switches: 0,
            yields: 0,
            blocks: 0,
            wakes: 0,
            finished: 0,
            corrupt: false,
        }
    }

    fn enqueue(&mut self, id: usize) -> bool {
        if id >= CONTEXT_TASKS || self.ready_len >= CONTEXT_TASKS {
            return false;
        }
        self.ready[self.tail] = id;
        self.tail = (self.tail + 1) % CONTEXT_TASKS;
        self.ready_len += 1;
        true
    }

    fn dequeue(&mut self) -> Option<usize> {
        if self.ready_len == 0 { return None; }
        let id = self.ready[self.head];
        self.head = (self.head + 1) % CONTEXT_TASKS;
        self.ready_len -= 1;
        Some(id)
    }

    fn wake_if_due(&mut self) -> bool {
        if self.dispatches < WAKE_AFTER_DISPATCHES { return true; }
        let Some(id) = self.blocked else { return true; };
        if self.tcbs[id].state != ThreadState::Blocked { return false; }
        self.tcbs[id].state = ThreadState::Ready;
        if !self.enqueue(id) { return false; }
        self.blocked = None;
        self.wakes += 1;
        true
    }
}

// Only the BSP may access this fixed-size test instance, and every live
// mutable borrow ends before switching the CPU's RSP to another Rust stack.
struct ExclusiveDispatcher(UnsafeCell<Dispatcher>);
// SAFETY: BSP-only access with maskable IRQs off; APs are parked.
unsafe impl Sync for ExclusiveDispatcher {}
static DISPATCHER: ExclusiveDispatcher = ExclusiveDispatcher(UnsafeCell::new(Dispatcher::new()));
static STARTED: AtomicBool = AtomicBool::new(false);

fn with_dispatcher<T>(work: impl FnOnce(&mut Dispatcher) -> T) -> T {
    // SAFETY: all access stays on the BSP and never overlaps across a switch.
    unsafe { work(&mut *DISPATCHER.0.get()) }
}

fn bsp_rsp_ptr() -> *mut usize {
    unsafe { core::ptr::addr_of_mut!((*DISPATCHER.0.get()).bsp_rsp) }
}
fn task_rsp_ptr(id: usize) -> *mut usize {
    // SAFETY: id always originates from the bounded ready queue.
    unsafe { core::ptr::addr_of_mut!((*DISPATCHER.0.get()).tcbs[id].saved_rsp) }
}
fn stack_bottom(id: usize) -> usize {
    // SAFETY: valid index < CONTEXT_TASKS. Only a raw address is formed.
    let raw = unsafe { core::ptr::addr_of_mut!((*DISPATCHER.0.get()).tcbs[id].stack) };
    raw.cast::<u8>() as usize
}

// New contexts restore r12 from initial frame. This small trampoline
// transfers the TCB identifier into SysV arg1 (RDI) and aligns RSP
// before calling the shared Rust entry. No Rust compiler-generated
// prologue executes before RSP is appropriately aligned.
global_asm!(
    ".global wolfos_batch_thread_start",
    ".type wolfos_batch_thread_start, @function",
    "wolfos_batch_thread_start:",
    "mov rdi, r12",
    "sub rsp, 8",
    "call wolfos_batch_rust_entry",
    "ud2",
);

unsafe extern "C" {
    fn wolfos_batch_thread_start();
}

fn prepare(id: usize) -> bool {
    if id >= CONTEXT_TASKS { return false; }
    let bottom = stack_bottom(id);
    let Some(top) = bottom.checked_add(STACK_BYTES) else { return false; };
    if bottom % 16 != 0 || top % 16 != 0 { return false; }

    // Initial switch frame: r15, r14, r13, r12 (= id), rbp, rbx,
    // trampoline return PC, dummy return PC. Eight words place
    // RSP mod 16 = 8 on entry to the trampoline.
    const FRAME_WORDS: usize = 8;
    let sp = top - FRAME_WORDS * core::mem::size_of::<usize>();
    // SAFETY: initialized only by BSP before any thread can execute.
    unsafe {
        (bottom as *mut u64).write_volatile(CANARY ^ id as u64);
        core::ptr::write_bytes(sp as *mut u8, 0, FRAME_WORDS * 8);
        (sp as *mut usize).add(3).write(id); // r12
        (sp as *mut usize).add(6).write(wolfos_batch_thread_start as usize);
    }
    with_dispatcher(|d| d.tcbs[id].saved_rsp = sp);
    true
}

fn saved_stack_pointer_ok(id: usize, saved: usize) -> bool {
    if id >= CONTEXT_TASKS { return false; }
    let bottom = stack_bottom(id);
    let Some(top) = bottom.checked_add(STACK_BYTES) else { return false; };
    // Context save happens inside the task's call frames and leaves headroom
    // above the bottom canary. This rejects a pointer into any other TCB.
    saved >= bottom + 1024 && saved < top
}

fn canary_ok(id: usize) -> bool {
    if id >= CONTEXT_TASKS { return false; }
    let bottom = stack_bottom(id);
    // SAFETY: first 8 bytes are a sentinel outside all active call frames.
    unsafe { (bottom as *const u64).read_volatile() == (CANARY ^ id as u64) }
}

fn digest_step(previous: u64, id: usize, round: usize) -> u64 {
    (previous ^ (id as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ (round as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9))
        .rotate_left(13)
        .wrapping_mul(0xD6E8_FEB8_6659_FD93)
}

fn task_step(id: usize, round: usize, digest: u64) -> bool {
    with_dispatcher(|d| {
        if d.active != Some(id) ||
            d.tcbs[id].state != ThreadState::Running ||
            d.tcbs[id].progress != round ||
            d.events_len >= EXPECTED_EVENTS
        {
            d.corrupt = true;
            return false;
        }

        d.events[d.events_len] = id as u8;
        d.events_len += 1;
        d.tcbs[id].progress += 1;
        d.tcbs[id].digest = digest;

        if round + 1 == ROUNDS {
            d.tcbs[id].state = ThreadState::Finished;
            d.finished += 1;
        } else if id == BLOCKED_ID && round == 0 {
            d.tcbs[id].state = ThreadState::Blocked;
            if d.blocked.replace(id).is_some() {
                d.corrupt = true;
                return false;
            }
            d.blocks += 1;
        } else {
            d.tcbs[id].state = ThreadState::Ready;
            if !d.enqueue(id) {
                d.corrupt = true;
                return false;
            }
            d.yields += 1;
        }
        d.active = None;
        true
    })
}

fn return_to_dispatcher(id: usize) {
    with_dispatcher(|d| d.switches += 1);
    // SAFETY: TCB owns the currently running RSP; BSP's RSP was saved by
    // the exact switch routine. No mutable Rust borrow spans the switch.
    unsafe { context_switch::switch_raw(task_rsp_ptr(id), bsp_rsp_ptr()); }
}

// Called only from the assembly trampoline; each TCB has its own real
// Rust stack and local digest/round variables survive every yield.
#[unsafe(no_mangle)]
extern "C" fn wolfos_batch_rust_entry(id: usize) -> ! {
    if id >= CONTEXT_TASKS { crate::halt_forever(); }
    let mut digest = 0u64;
    for round in 0..ROUNDS {
        if !canary_ok(id) { crate::halt_forever(); }
        digest = digest_step(digest, id, round + 1);
        if !task_step(id, round, digest) { crate::halt_forever(); }
        return_to_dispatcher(id);
        // A finished TCB is never eligible for another dispatch.
        if round + 1 == ROUNDS { crate::halt_forever(); }
    }
    crate::halt_forever()
}

/// BSP-only one-shot QEMU acceptance, run after all AP jobs have finished.
pub fn verify() -> bool {
    x86_64::instructions::interrupts::disable();
    if CONTEXT_TASKS > THREAD_COUNT ||
        STARTED.swap(true, Ordering::AcqRel)
    {
        return false;
    }

    for id in 0..CONTEXT_TASKS {
        if !prepare(id) || !with_dispatcher(|d| d.enqueue(id)) {
            serial::write_line("WOLFOS_CTX_BATCH_ERROR initialization");
            return false;
        }
    }

    for _ in 0..MAX_DISPATCHES {
        let current = with_dispatcher(|d| {
            if !d.wake_if_due() {
                d.corrupt = true;
                return None;
            }
            let id = d.dequeue()?;
            if d.tcbs[id].state != ThreadState::Ready {
                d.corrupt = true;
                return None;
            }
            d.tcbs[id].state = ThreadState::Running;
            d.active = Some(id);
            d.dispatches += 1;
            d.switches += 1;
            Some(id)
        });
        let Some(id) = current else { break; };
        // SAFETY: initialized or suspended context of the selected TCB.
        // BSP is the only CPU that dispatches this test batch.
        unsafe { context_switch::switch_raw(bsp_rsp_ptr(), task_rsp_ptr(id)); }
        if !canary_ok(id) ||
            with_dispatcher(|d| d.corrupt || d.active.is_some())
        {
            return false;
        }
    }

    let ok = with_dispatcher(|d| {
        if d.corrupt || d.ready_len != 0 || d.blocked.is_some() ||
           d.events_len != EXPECTED_EVENTS ||
           d.dispatches != EXPECTED_EVENTS ||
           d.switches != EXPECTED_EVENTS * 2 ||
           d.yields != CONTEXT_TASKS * (ROUNDS - 1) - 1 ||
           d.blocks != 1 || d.wakes != 1 || d.finished != CONTEXT_TASKS
        {
            return false;
        }

        // First dispatch round must visit all TCBs in FIFO order.
        for id in 0..CONTEXT_TASKS {
            if d.events[id] as usize != id { return false; }
        }
        for id in 0..CONTEXT_TASKS {
            let tcb = &d.tcbs[id];
            if tcb.state != ThreadState::Finished ||
               tcb.progress != ROUNDS ||
               !saved_stack_pointer_ok(id, tcb.saved_rsp)
            {
                return false;
            }
            let mut expected = 0u64;
            for round in 1..=ROUNDS {
                expected = digest_step(expected, id, round);
            }
            if tcb.digest != expected { return false; }
            if d.events.iter().filter(|&&event| event as usize == id).count() != ROUNDS {
                return false;
            }
        }
        true
    });

    if !ok || !(0..CONTEXT_TASKS).all(canary_ok) {
        serial::write_line("WOLFOS_CTX_BATCH_ERROR scheduling_or_resume");
        return false;
    }
    serial::write_fmt(format_args!(
        "WOLFOS_CTX_BATCH_OK threads={} dispatches={} switches={} yields={} blocked=1 woken=1 finished={} stack_kib=16 bank_kib={}\n",
        CONTEXT_TASKS, EXPECTED_EVENTS, EXPECTED_EVENTS * 2,
        CONTEXT_TASKS * (ROUNDS - 1) - 1, CONTEXT_TASKS,
        STACK_BANK_BYTES / 1024
    ));
    true
}
