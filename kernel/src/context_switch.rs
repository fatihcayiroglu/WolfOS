//! First real x86-64 cooperative kernel execution-context switch.
//!
//! The initial roundtrip acceptance exercise runs ONLY on the BSP after
//! the SMP boot tests finish. Two independently stacked Rust functions yield
//! to one another and resume their original call frames. Six System V ABI
//! nonvolatile GPRs and RSP are preserved by an audited assembly routine.
//!
//! NOT a full thread scheduler: no interrupts/preemption, FPU/SIMD switch,
//! CR3/address-space switching, TLS, per-thread TSS/RSP0, Ring 3 or migration.
//! Worker stacks are statically allocated with canaries (no guard pages).
//! APs are parked before this single-CPU context-switch test begins.

use core::arch::global_asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use crate::serial;

const STACK_BYTES: usize = 16 * 1024;
const CANARY: u64 = 0x574F_4C46_4354_5853;
const ITERATIONS: usize = 3;
const EXPECTED_SWITCHES: usize = ITERATIONS * 2 + 1;

#[repr(align(16))]
struct Stack([u8; STACK_BYTES]);

struct Stacks(UnsafeCell<[Stack; 2]>);
// SAFETY: the BSP is the only CPU permitted to access these stacks, and
// no interrupt handler or other kernel function touches the storage.
unsafe impl Sync for Stacks {}

static STACKS: Stacks = Stacks(UnsafeCell::new([const { Stack([0; STACK_BYTES]) }; 2]));

struct SavedStack(UnsafeCell<usize>);
// SAFETY: accesses to these RSP cells occur exclusively on the BSP while
// maskable interrupts are disabled. No AP reads or writes them.
unsafe impl Sync for SavedStack {}
static BSP_RSP: SavedStack = SavedStack(UnsafeCell::new(0));
static A_RSP: SavedStack = SavedStack(UnsafeCell::new(0));
static B_RSP: SavedStack = SavedStack(UnsafeCell::new(0));

static EVENT_NEXT: AtomicUsize = AtomicUsize::new(0);
static EVENTS: [AtomicU8; 6] = [const { AtomicU8::new(0) }; 6];
static A_FINISHED: AtomicBool = AtomicBool::new(false);
static B_FINISHED: AtomicBool = AtomicBool::new(false);
static SWITCH_COUNT: AtomicUsize = AtomicUsize::new(0);

// System V x86-64 ABI. Input: rdi = &old_rsp, rsi = &new_rsp.
// A call enters with the return PC on the current stack. We save all
// six callee-saved general registers, write the old RSP, load the next
// context's saved RSP and restore those registers, then RET to its PC.
// Caller-saved GPRs and SIMD state are NOT preserved by this primitive;
// safe integration requires normal ABI call boundaries and no task-wide
// SIMD/FPU assumptions.
global_asm!(
    ".global wolfos_switch_context",
    ".type wolfos_switch_context, @function",
    "wolfos_switch_context:",
    "push rbx",
    "push rbp",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov [rdi], rsp",
    "mov rsp, [rsi]",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbp",
    "pop rbx",
    "ret",
);

unsafe extern "C" {
    fn wolfos_switch_context(previous: *mut usize, next: *const usize);
}

/// # Safety
/// Runs on the calling CPU (BSP or AP), with maskable interrupts disabled.
/// Both raw slots must be distinct, live and exclusively owned by that CPU.
/// The destination holds a valid suspended/ABI-aligned initial switch frame.
/// No mutable Rust borrow may span this call. Calls on distinct CPUs may
/// execute concurrently ONLY if their stack/RSP storage is disjoint.

pub(crate) unsafe fn switch_raw(previous: *mut usize, next: *const usize) {
    // SAFETY: caller maintains the exclusive stack/context ownership contract.
    unsafe { wolfos_switch_context(previous, next); }
}

fn bottom(index: usize) -> Option<usize> {
    if index >= 2 { return None; }
    // SAFETY: index is checked above and the static backing allocation
    // stays live. We form a raw pointer without creating an aliasing Rust
    // reference or dereferencing the stack's bytes.
    let ptr = unsafe { core::ptr::addr_of_mut!((*STACKS.0.get())[index]) };
    Some(ptr.cast::<u8>() as usize)
}

/// Build an initial callee-saved register frame + function return address.
/// Each new context starts as though it returned from the switch routine.
fn prepare(index: usize, start: extern "C" fn() -> !) -> Option<usize> {
    let base = bottom(index)?;
    let top = base.checked_add(STACK_BYTES)?;
    if base % 16 != 0 || top % 16 != 0 { return None; }
    // Six saved nonvolatile registers + entry PC + dummy return address.
    // Eight words place initial RSP % 16 == 8 after the final RET,
    // satisfying the System V AMD64 ABI on entering the Rust function.
    const WORDS: usize = 8;
    let sp = top.checked_sub(WORDS * core::mem::size_of::<usize>())?;
    // SAFETY: we own the full static stack, and this is before either
    // task executes. Writes are aligned and remain inside 16 KiB storage.
    unsafe {
        (base as *mut u64).write_volatile(CANARY ^ index as u64);
        core::ptr::write_bytes(sp as *mut u8, 0, WORDS * 8);
        (sp as *mut usize).add(6).write(start as usize);
    }
    Some(sp)
}

fn stack_intact(index: usize) -> bool {
    let Some(base) = bottom(index) else { return false; };
    // SAFETY: the first u64 is an exclusive sentinel outside the active
    // live stack frames and is only read on the BSP.
    unsafe { (base as *const u64).read_volatile() == (CANARY ^ index as u64) }
}

fn record(who: u8) -> bool {
    let next = EVENT_NEXT.fetch_add(1, Ordering::SeqCst);
    if next >= EVENTS.len() { return false; }
    EVENTS[next].store(who, Ordering::SeqCst);
    true
}

fn switch(previous: &SavedStack, next: &SavedStack) {
    SWITCH_COUNT.fetch_add(1, Ordering::Relaxed);
    // SAFETY: previous and next are distinct statically allocated RSP cells,
    // solely owned by the BSP. All target frames are initialized or were
    // suspended by this exact routine. Interrupts are disabled.
    unsafe { switch_raw(previous.0.get(), next.0.get()); }
}

// Task A and B are separate real Rust call stacks. These functions never
// return: task B eventually returns control to the original BSP stack.
extern "C" fn task_a() -> ! {
    for round in 0..ITERATIONS {
        if !record(1) || !stack_intact(0) { crate::halt_forever(); }
        if round + 1 == ITERATIONS {
            A_FINISHED.store(true, Ordering::Release);
        }
        switch(&A_RSP, &B_RSP);
    }
    // B must have switched to BSP and left A suspended on its last yield.
    crate::halt_forever()
}

extern "C" fn task_b() -> ! {
    for round in 0..ITERATIONS {
        if !record(2) || !stack_intact(1) { crate::halt_forever(); }
        if round + 1 == ITERATIONS {
            B_FINISHED.store(true, Ordering::Release);
            switch(&B_RSP, &BSP_RSP);
            crate::halt_forever();
        }
        switch(&B_RSP, &A_RSP);
    }
    crate::halt_forever()
}

/// BSP only, one-shot. Interrupts must remain disabled during this test.
/// A lost register/stack frame fails the QEMU smoke rather than reporting OK.
pub fn verify_roundtrip() -> bool {
    x86_64::instructions::interrupts::disable();
    let (Some(a), Some(b)) = (prepare(0, task_a), prepare(1, task_b)) else {
        serial::write_line("WOLFOS_CONTEXT_ERROR stack_initialization");
        return false;
    };
    // SAFETY: BSP-only use before any context is runnable, with IRQs masked.
    unsafe {
        *A_RSP.0.get() = a;
        *B_RSP.0.get() = b;
    }
    switch(&BSP_RSP, &A_RSP);

    let count = EVENT_NEXT.load(Ordering::Acquire);
    let switches = SWITCH_COUNT.load(Ordering::Relaxed);
    if count != 6 || switches != EXPECTED_SWITCHES ||
        !A_FINISHED.load(Ordering::Acquire) ||
        !B_FINISHED.load(Ordering::Acquire) ||
        !stack_intact(0) || !stack_intact(1)
    {
        serial::write_fmt(format_args!(
            "WOLFOS_CONTEXT_ERROR events={} switches={} a={} b={}\n",
            count, switches, A_FINISHED.load(Ordering::Acquire),
            B_FINISHED.load(Ordering::Acquire)
        ));
        return false;
    }
    for (index, event) in EVENTS.iter().enumerate() {
        if event.load(Ordering::Acquire) != (index % 2 + 1) as u8 {
            serial::write_line("WOLFOS_CONTEXT_ERROR incorrect_resume_order");
            return false;
        }
    }
    serial::write_fmt(format_args!(
        "WOLFOS_CONTEXT_OK tasks=2 switches={} events={} stacks_kib=16\n",
        switches, count
    ));
    true
}
