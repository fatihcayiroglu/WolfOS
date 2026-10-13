//! Three real stack-backed kernel thread control blocks, scheduled on BSP.
//!
//! Reuses WolfOS's x86-64 callee-saved register/RSP context switch from P1.
//! Three TCBs own distinct 16 KiB stacks; Ready/Running/Blocked/Finished
//! transitions dispatch and resume actual suspended Rust call frames.
//!
//! Boot acceptance only: the BSP is the sole owner, maskable IRQs are off,
//! APs are parked, and the one blocked thread is woken by deterministic
//! scheduler policy. No thread migration, timer preemption, heap, Ring 3,
//! FPU/SIMD context management, TLS or IRQ-safe locking.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::{context_switch, serial};
use crate::thread_scheduler::ThreadState;

const THREADS: usize = 3;
const STACK_BYTES: usize = 16 * 1024;
const ROUNDS: usize = 3;
const EVENTS_EXPECTED: usize = THREADS * ROUNDS;
const MAX_DISPATCHES: usize = 32;
const CANARY: u64 = 0x574F_4C46_4B54_4342;

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
    tcbs: [Tcb; THREADS],
    bsp_rsp: usize,
    ready: [usize; THREADS],
    head: usize,
    tail: usize,
    ready_len: usize,
    active: Option<usize>,
    blocked: Option<usize>,
    events: [u8; EVENTS_EXPECTED],
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
            tcbs: [const { Tcb::new() }; THREADS],
            bsp_rsp: 0,
            ready: [0; THREADS],
            head: 0,
            tail: 0,
            ready_len: 0,
            active: None,
            blocked: None,
            events: [0; EVENTS_EXPECTED],
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
        if id >= THREADS || self.ready_len >= THREADS { return false; }
        self.ready[self.tail] = id;
        self.tail = (self.tail + 1) % THREADS;
        self.ready_len += 1;
        true
    }

    fn dequeue(&mut self) -> Option<usize> {
        if self.ready_len == 0 { return None; }
        let id = self.ready[self.head];
        self.head = (self.head + 1) % THREADS;
        self.ready_len -= 1;
        Some(id)
    }

    fn wake_if_due(&mut self) -> bool {
        // Thread 1 blocks after its first actual context. Delay waking it
        // until other threads have had at least four total dispatches.
        if self.dispatches < 4 { return true; }
        let Some(id) = self.blocked else { return true; };
        if self.tcbs[id].state != ThreadState::Blocked { return false; }
        self.tcbs[id].state = ThreadState::Ready;
        if !self.enqueue(id) { return false; }
        self.blocked = None;
        self.wakes += 1;
        true
    }
}

struct ExclusiveDispatcher(UnsafeCell<Dispatcher>);
// SAFETY: initialized and accessed only on the BSP, with maskable interrupts
// disabled; no AP, interrupt handler or other kernel subsystem touches it.
// Every mutable borrow ends before invoking assembly context switching.
unsafe impl Sync for ExclusiveDispatcher {}

static DISPATCHER: ExclusiveDispatcher = ExclusiveDispatcher(UnsafeCell::new(Dispatcher::new()));
static STARTED: AtomicBool = AtomicBool::new(false);

fn with_dispatcher<R>(f: impl FnOnce(&mut Dispatcher) -> R) -> R {
    // SAFETY: execution is restricted to a single BSP call chain. Despite
    // switching Rust stacks, no mutable borrow spans a switch call.
    unsafe { f(&mut *DISPATCHER.0.get()) }
}

// Raw pointers to saved RSP fields, valid for the entire lifetime of this
// static Dispatcher. No Rust reference is held through the stack switch.
fn bsp_rsp_ptr() -> *mut usize {
    unsafe { core::ptr::addr_of_mut!((*DISPATCHER.0.get()).bsp_rsp) }
}
fn tcb_rsp_ptr(id: usize) -> *mut usize {
    unsafe { core::ptr::addr_of_mut!((*DISPATCHER.0.get()).tcbs[id].saved_rsp) }
}
fn stack_bottom(id: usize) -> usize {
    let raw = unsafe { core::ptr::addr_of_mut!((*DISPATCHER.0.get()).tcbs[id].stack) };
    raw.cast::<u8>() as usize
}

fn initialize_frame(id: usize, entry: extern "C" fn() -> !) -> bool {
    let bottom = stack_bottom(id);
    let Some(top) = bottom.checked_add(STACK_BYTES) else { return false; };
    if bottom % 16 != 0 || top % 16 != 0 { return false; }

    // 6 popped callee-saved GPRs + return PC + a dummy return address.
    // With eight words, the initial RET enters Rust with RSP % 16 == 8.
    const FRAME_WORDS: usize = 8;
    let sp = top - FRAME_WORDS * core::mem::size_of::<usize>();
    unsafe {
        (bottom as *mut u64).write_volatile(CANARY ^ id as u64);
        core::ptr::write_bytes(sp as *mut u8, 0, FRAME_WORDS * 8);
        (sp as *mut usize).add(6).write(entry as usize);
    }
    with_dispatcher(|d| { d.tcbs[id].saved_rsp = sp; });
    true
}

fn canary_ok(id: usize) -> bool {
    let bottom = stack_bottom(id);
    unsafe { (bottom as *const u64).read_volatile() == (CANARY ^ id as u64) }
}

fn step_digest(previous: u64, id: usize, step: usize) -> u64 {
    (previous ^ (id as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ (step as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9))
        .rotate_left(13)
        .wrapping_mul(0xD6E8_FEB8_6659_FD93)
}

fn finish_step(id: usize, round: usize, checksum: u64) -> bool {
    with_dispatcher(|d| {
        if d.active != Some(id) ||
            d.tcbs[id].state != ThreadState::Running ||
            d.tcbs[id].progress != round ||
            d.events_len >= EVENTS_EXPECTED
        {
            d.corrupt = true;
            return false;
        }
        d.events[d.events_len] = (id + 1) as u8;
        d.events_len += 1;
        d.tcbs[id].progress += 1;
        d.tcbs[id].digest = checksum;
        if round + 1 == ROUNDS {
            d.tcbs[id].state = ThreadState::Finished;
            d.finished += 1;
        } else if id == 1 && round == 0 {
            d.tcbs[id].state = ThreadState::Blocked;
            if d.blocked.is_some() {
                d.corrupt = true;
                return false;
            }
            d.blocked = Some(id);
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

fn context_to_bsp(id: usize) {
    with_dispatcher(|d| { d.switches += 1; });
    // SAFETY: BSP's saved stack was produced by the same switch primitive.
    // The running thread owns its saved RSP and has released all borrows.
    unsafe { context_switch::switch_raw(tcb_rsp_ptr(id), bsp_rsp_ptr()); }
}

fn thread_body(id: usize) -> ! {
    let mut checksum = 0u64;
    for round in 0..ROUNDS {
        if !canary_ok(id) { crate::halt_forever(); }
        checksum = step_digest(checksum, id, round + 1);
        if !finish_step(id, round, checksum) { crate::halt_forever(); }
        context_to_bsp(id);
        // Resuming here proves the Rust call frame, loop index and checksum
        // survived a real register/stack switch.
        if round + 1 == ROUNDS { crate::halt_forever(); }
    }
    crate::halt_forever()
}

extern "C" fn thread_zero() -> ! { thread_body(0) }
extern "C" fn thread_one() -> ! { thread_body(1) }
extern "C" fn thread_two() -> ! { thread_body(2) }

pub fn verify() -> bool {
    x86_64::instructions::interrupts::disable();
    if STARTED.swap(true, Ordering::AcqRel) { return false; }
    for (id, entry) in [thread_zero as extern "C" fn() -> !, thread_one, thread_two]
        .into_iter().enumerate()
    {
        if !initialize_frame(id, entry) ||
            !with_dispatcher(|d| d.enqueue(id))
        {
            serial::write_line("WOLFOS_KTHREAD_ERROR initial_context");
            return false;
        }
    }

    for _ in 0..MAX_DISPATCHES {
        let current = with_dispatcher(|d| {
            if !d.wake_if_due() { d.corrupt = true; return None; }
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
        // SAFETY: no mutable borrow spans this call. The selected READY TCB
        // has an initialized or previously suspended frame; only BSP runs it.
        unsafe { context_switch::switch_raw(bsp_rsp_ptr(), tcb_rsp_ptr(id)); }
        if !canary_ok(id) { return false; }
        if with_dispatcher(|d| d.corrupt || d.active.is_some()) { return false; }
    }

    const EXPECTED_EVENTS: [u8; EVENTS_EXPECTED] = [1, 2, 3, 1, 3, 1, 2, 3, 2];
    let good = with_dispatcher(|d| {
        if d.corrupt || d.ready_len != 0 || d.blocked.is_some() ||
            d.events_len != EVENTS_EXPECTED ||
            d.events != EXPECTED_EVENTS ||
            d.dispatches != EVENTS_EXPECTED ||
            d.switches != EVENTS_EXPECTED * 2 ||
            d.yields != 5 || d.blocks != 1 || d.wakes != 1 ||
            d.finished != THREADS
        {
            return false;
        }
        for id in 0..THREADS {
            if d.tcbs[id].state != ThreadState::Finished ||
                d.tcbs[id].progress != ROUNDS { return false; }
            let mut expected = 0u64;
            for step in 1..=ROUNDS {
                expected = step_digest(expected, id, step);
            }
            if expected != d.tcbs[id].digest { return false; }
        }
        true
    });
    if !good || !(0..THREADS).all(canary_ok) {
        serial::write_line("WOLFOS_KTHREAD_ERROR scheduling_or_resume");
        return false;
    }
    serial::write_line(
        "WOLFOS_KTHREAD_OK threads=3 dispatches=9 switches=18 yields=5 blocked=1 woken=1 finished=3 stack_kib=16"
    );
    true
}
