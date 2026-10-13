//! Two real Rust execution contexts dispatched by PIT IRQ0 tick epochs.
//!
//! Isolation: timer-smoke only; one BSP, all APs parked, 8259 IRQ0 only.
//! The interrupt handler NEVER context-switches. Each worker observes a new
//! hardware tick with IRQs enabled, masks interrupts, then voluntarily yields
//! at a safe ABI boundary. This is tick-driven cooperative dispatch, NOT
//! preemptive interruption of an uncooperative kernel thread.

use core::arch::global_asm;
use core::cell::UnsafeCell;

use crate::{context_switch, timer};

const WORKERS: usize = 2;
const ROUNDS: usize = 3;
const EVENTS: usize = WORKERS * ROUNDS;
const STACK_BYTES: usize = 16 * 1024;
const CANARY: u64 = 0x574f_4c46_5449_434b;
const MAX_WAIT_SPINS: u64 = 500_000_000;

#[repr(align(16))]
struct Stack([u8; STACK_BYTES]);

struct State {
    stacks: [Stack; WORKERS],
    rsp: [usize; WORKERS],
    bsp_rsp: usize,
    active: Option<usize>,
    progress: [usize; WORKERS],
    events: [u8; EVENTS],
    epochs: [u64; EVENTS],
    event_count: usize,
    switches: usize,
    started: bool,
    failed: bool,
}

impl State {
    const fn new() -> Self {
        Self {
            stacks: [const { Stack([0; STACK_BYTES]) }; WORKERS],
            rsp: [0; WORKERS],
            bsp_rsp: 0,
            active: None,
            progress: [0; WORKERS],
            events: [0; EVENTS],
            epochs: [0; EVENTS],
            event_count: 0,
            switches: 0,
            started: false,
            failed: false,
        }
    }
}

struct StateCell(UnsafeCell<State>);
// SAFETY: only BSP touches State, and IRQ0 reads/writes a distinct AtomicU64
// owned by timer.rs. Each closure ends before any context switch; APs park.
unsafe impl Sync for StateCell {}

static STATE: StateCell = StateCell(UnsafeCell::new(State::new()));

fn with_state<T>(f: impl FnOnce(&mut State) -> T) -> T {
    // SAFETY: only BSP, IRQs masked while accessing State. No task or IRQ
    // holds a Rust mutable borrow across a context switch.
    unsafe { f(&mut *STATE.0.get()) }
}

fn stack_bottom(id: usize) -> usize {
    // SAFETY: index is validated by caller, raw pointer only.
    let ptr = unsafe { core::ptr::addr_of_mut!((*STATE.0.get()).stacks[id]) };
    ptr.cast::<u8>() as usize
}

fn saved_rsp_ptr(id: usize) -> *mut usize {
    // SAFETY: raw pointer, unique BSP-owned RSP slot for each worker.
    unsafe { core::ptr::addr_of_mut!((*STATE.0.get()).rsp[id]) }
}
fn bsp_rsp_ptr() -> *mut usize {
    unsafe { core::ptr::addr_of_mut!((*STATE.0.get()).bsp_rsp) }
}

fn stack_ok(id: usize) -> bool {
    let base = stack_bottom(id);
    // SAFETY: the static bank outlives both threads, and canary is never
    // touched by live stack frames.
    unsafe { (base as *const u64).read_volatile() == (CANARY ^ id as u64) }
}

fn saved_rsp_ok(id: usize, rsp: usize) -> bool {
    let base = stack_bottom(id);
    rsp >= base + 512 && rsp < base + STACK_BYTES
}

// Synthetic initial frame: r15, r14, r13, r12, rbp, rbx, PC, dummy.
// r12 is the worker ID, recovered by the context switch's POP r12.
global_asm!(
    ".global wolfos_tick_worker_start",
    ".type wolfos_tick_worker_start, @function",
    "wolfos_tick_worker_start:",
    "mov rdi, r12",
    "sub rsp, 8",
    "call wolfos_tick_worker_rust",
    "ud2",
);
unsafe extern "C" {
    fn wolfos_tick_worker_start();
}

fn prepare(id: usize) -> bool {
    if id >= WORKERS { return false; }
    let base = stack_bottom(id);
    let Some(top) = base.checked_add(STACK_BYTES) else { return false; };
    if base % 16 != 0 || top % 16 != 0 { return false; }
    const FRAME_WORDS: usize = 8;
    let rsp = top - FRAME_WORDS * core::mem::size_of::<usize>();
    // SAFETY: worker not started; BSP exclusively initializes permanent
    // mapped memory and ABI-compatible synthetic switch frame.
    unsafe {
        (base as *mut u64).write_volatile(CANARY ^ id as u64);
        core::ptr::write_bytes(rsp as *mut u8, 0, FRAME_WORDS * 8);
        (rsp as *mut usize).add(3).write(id); // r12
        (rsp as *mut usize).add(6).write(wolfos_tick_worker_start as usize);
    }
    with_state(|s| s.rsp[id] = rsp);
    true
}

fn record_step(id: usize, round: usize, epoch: u64) -> bool {
    with_state(|s| {
        if s.active != Some(id) || s.progress[id] != round || s.event_count >= EVENTS {
            s.failed = true;
            return false;
        }
        // Every separate work dispatch must have its own later IRQ epoch.
        if s.event_count != 0 && epoch <= s.epochs[s.event_count - 1] {
            s.failed = true;
            return false;
        }
        s.events[s.event_count] = id as u8;
        s.epochs[s.event_count] = epoch;
        s.event_count += 1;
        s.progress[id] += 1;
        s.active = None;
        true
    })
}

#[unsafe(no_mangle)]
extern "C" fn wolfos_tick_worker_rust(id: usize) -> ! {
    if id >= WORKERS { crate::halt_forever(); }
    for round in 0..ROUNDS {
        if !stack_ok(id) { crate::halt_forever(); }
        // The worker executes on a private real stack while genuine PIT
        // interrupts fire. Only the atomic tick counter is IRQ-shared.
        let start_tick = timer::ticks();
        x86_64::instructions::interrupts::enable();
        let mut seen = None;
        for _ in 0..MAX_WAIT_SPINS {
            let tick = timer::ticks();
            if tick > start_tick {
                seen = Some(tick);
                break;
            }
            core::hint::spin_loop();
        }
        // All stack/context mutation must occur with interrupts disabled.
        x86_64::instructions::interrupts::disable();
        let Some(epoch) = seen else { crate::halt_forever(); };
        if !record_step(id, round, epoch) { crate::halt_forever(); }
        // SAFETY: exclusive BSP ownership; no Rust reference lives across
        // this switch, interrupts are masked, and both slots are distinct.
        unsafe { context_switch::switch_raw(saved_rsp_ptr(id), bsp_rsp_ptr()); }
    }
    crate::halt_forever()
}

/// BSP-only proof: switch on two independent Rust stacks after a new timer
/// epoch. Called with interrupts masked while PIT IRQ0 is configured.
pub fn verify() -> bool {
    if x86_64::instructions::interrupts::are_enabled() { return false; }
    if !with_state(|s| {
        if s.started { return false; }
        s.started = true;
        true
    }) { return false; }
    for id in 0..WORKERS {
        if !prepare(id) { return false; }
    }
    for event in 0..EVENTS {
        let id = event % WORKERS;
        let ready = with_state(|s| {
            if s.failed || s.active.is_some() || s.progress[id] != event / WORKERS {
                s.failed = true;
                return false;
            }
            s.active = Some(id);
            s.switches += 1;
            true
        });
        if !ready { return false; }
        // SAFETY: BSP-only scheduler RSP, private context RSP and masked IRQs.
        // Worker restores IRQs while running, then masks them before yielding.
        unsafe { context_switch::switch_raw(bsp_rsp_ptr(), saved_rsp_ptr(id)); }
        if x86_64::instructions::interrupts::are_enabled() { return false; }
        if !with_state(|s| {
            s.switches += 1;
            !s.failed && s.active.is_none()
        }) || !stack_ok(id) { return false; }
    }
    let good = with_state(|s| {
        if s.failed || s.event_count != EVENTS || s.switches != EVENTS * 2
            || s.active.is_some() || s.progress != [ROUNDS; WORKERS]
            || s.events != [0, 1, 0, 1, 0, 1]
        { return false; }
        for event in 1..EVENTS {
            if s.epochs[event] <= s.epochs[event - 1] { return false; }
        }
        for id in 0..WORKERS {
            if !saved_rsp_ok(id, s.rsp[id]) { return false; }
        }
        true
    });
    good && (0..WORKERS).all(stack_ok)
}

pub const THREAD_COUNT: usize = WORKERS;
pub const DISPATCH_COUNT: usize = EVENTS;
pub const SWITCH_COUNT: usize = EVENTS * 2;
pub const STACK_KIB: usize = STACK_BYTES / 1024;
