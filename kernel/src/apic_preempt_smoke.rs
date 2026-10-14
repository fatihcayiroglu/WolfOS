//! QEMU-only BSP proof of *involuntary* kernel-to-kernel task handoff.
//!
//! Three private kernel stacks run CPU-bound tasks that NEVER yield to one
//! another. A real periodic xAPIC interrupt stores the interrupted
//! 15-GPR + hardware trap-frame RSP and selects the other task's saved RSP.
//! Assembly pops the selected task's GPRs and IRETQs onto its stack.
//!
//! The task finishing the bounded proof voluntarily returns to the original
//! BSP test harness ONCE, with IF=0. This is not a production scheduler:
//! no dynamic tasks, IRQ-safe locking, XSAVE/AVX, CR3/TLS, ring 3,
//! migration, guard pages or AP-local interrupts. All work is BSP-owned.

use core::cell::UnsafeCell;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use x86_64::instructions::segmentation::{CS, SS, Segment};

use crate::{context_switch, kernel_trap_frame::{
    HardwareReturnFrame, KernelTrapFrame, SavedGprs, validate_kernel_resume
}, preempt_depth::PreemptDepth, fx_state, rr_policy,
    task_slot::{self, SlotTable, SlotState, SlotError, ReclaimGate}};

const TASK_COUNT: usize = 3;
const SLOT_COUNT: usize = 4; // fourth slot is NOT runnable at boot
const LIVE_TASK: usize = 3;
const LIVE_REQUIRED_IRQS: u64 = 4;
const LIVE_FROZEN_REQUIRED: u64 = 4;
const LIVE_XMM0: u64 = 0x53a7_1199_cafe_f00d;
const STACK_BYTES: usize = 16 * 1024;
const STOP_AFTER: u64 = 60;
const FINISH_AFTER_SWITCHES: u64 = 26;
const FINISH_FREEZE_REQUIRED: u64 = 6;
const WAKE_AFTER_BLOCKED_IRQS: u64 = 6;
const MIN_EPOCHS_PER_TASK: u64 = 4;
const MAX_TASK_SPINS: u64 = 200_000_000;
const CANARY: u64 = 0x574f_4c46_5052_454d;
const TASK_XMM0: [u64; TASK_COUNT] = [
    0x1122_3344_5566_7788,
    0x8877_6655_4433_2211,
    0x0f0e_0d0c_0b0a_0908,
];

#[repr(align(16))]
struct Stack([u8; STACK_BYTES]);
struct PrivateStacks(UnsafeCell<[Stack; SLOT_COUNT]>);
// SAFETY: only BSP runs; tasks own disjoint stacks. The interrupt handler
// observes saved frame addresses atomically but does not mutate live Rust
// data borrowed across an IRQ or context switch.
unsafe impl Sync for PrivateStacks {}
static STACKS: PrivateStacks =
    PrivateStacks(UnsafeCell::new([
        const { Stack([0; STACK_BYTES]) }; SLOT_COUNT
    ]));

/// Pure ownership metadata, separate from ready/finished IRQ bitmap state.
/// Only BSP mutates it when creating the smoke slots, under task2's
/// preemption-disabled Finished transition, and after BSP quiescence.
/// The IRQ callback NEVER accesses this UnsafeCell.
struct OwnedSlots(UnsafeCell<SlotTable<SLOT_COUNT>>);
// SAFETY: only BSP; the ISR never touches OwnedSlots, and APs are parked.
// Mutations do not overlap with another Rust reference to this allocation.
unsafe impl Sync for OwnedSlots {}
static SLOT_OWNERS: OwnedSlots = OwnedSlots(UnsafeCell::new(SlotTable::new()));

struct BspSlot(UnsafeCell<usize>);
// SAFETY: only BSP accesses these raw RSP slots while IF=0 and with all
// mutable Rust borrows ended. IRQ handler never reads or modifies them.
unsafe impl Sync for BspSlot {}
static BSP_RSP: BspSlot = BspSlot(UnsafeCell::new(0));
static START_RSP: BspSlot = BspSlot(UnsafeCell::new(0));
static EXIT_RSP: BspSlot = BspSlot(UnsafeCell::new(0));

static ACTIVE: AtomicBool = AtomicBool::new(false);
static STARTED: AtomicBool = AtomicBool::new(false);
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static FRAME_RSP: [AtomicUsize; SLOT_COUNT] =
    [const { AtomicUsize::new(0) }; SLOT_COUNT];
static WORK: [AtomicU64; TASK_COUNT] =
    [const { AtomicU64::new(0) }; TASK_COUNT];
static INTERRUPTED: [AtomicU64; TASK_COUNT] =
    [const { AtomicU64::new(0) }; TASK_COUNT];
static SWITCHES: AtomicU64 = AtomicU64::new(0);
static REJECTED: AtomicU64 = AtomicU64::new(0);
static EXIT_TASK: AtomicUsize = AtomicUsize::new(usize::MAX);
static CODE_SELECTOR: AtomicUsize = AtomicUsize::new(0);
static RUNNABLE: AtomicU64 = AtomicU64::new(0);
// Lifecycle phases: 0=not armed, 1=task1 blocked on its stack,
// 2=timer woke task1 (runnable), 3=task1 actually resumed on same stack.
// All test-owned by BSP; atomic so IRQ handler can observe without locks.
static BLOCK_PHASE: AtomicUsize = AtomicUsize::new(0);
static BLOCK_ENTRY_CAPTURED: AtomicBool = AtomicBool::new(false);
static BLOCK_SAVED_WORK: AtomicU64 = AtomicU64::new(0);
static BLOCK_OTHER_WORK: AtomicU64 = AtomicU64::new(0);
static BLOCKED_TIMER_IRQS: AtomicU64 = AtomicU64::new(0);
static BLOCK_FROZEN_SAMPLES: AtomicU64 = AtomicU64::new(0);
static BLOCK_SKIPPED: AtomicU64 = AtomicU64::new(0);
static BLOCK_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static WAKE_COUNT: AtomicU64 = AtomicU64::new(0);
static RESUME_COUNT: AtomicU64 = AtomicU64::new(0);
static BLOCK_ERRORS: AtomicU64 = AtomicU64::new(0);
static POST_WAKE_VISITS: [AtomicU64; TASK_COUNT] =
    [const { AtomicU64::new(0) }; TASK_COUNT];

// Proof-only finished-task lifecycle. 0=not requested; 1=task2 marks
// Finished while still running; 2=first genuine IRQ switches away.
// The stack and FXSAVE image remain allocated for diagnostic inspection.
static FINISH_PHASE: AtomicUsize = AtomicUsize::new(0);
static FINISHED: AtomicU64 = AtomicU64::new(0);
static FINISH_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static FINISH_WORK_SNAPSHOT: AtomicU64 = AtomicU64::new(0);
static FINISH_FROZEN_SAMPLES: AtomicU64 = AtomicU64::new(0);
static FINISH_SKIPS: AtomicU64 = AtomicU64::new(0);
static FINISH_ERRORS: AtomicU64 = AtomicU64::new(0);
static POST_FINISH_VISITS: [AtomicU64; 2] =
    [const { AtomicU64::new(0) }; 2];
static PREEMPT_DEPTH: PreemptDepth = PreemptDepth::new();
static DEFERRED_IRQS: AtomicU64 = AtomicU64::new(0);
static NESTED_GUARD_OK: AtomicBool = AtomicBool::new(false);
static XMM_READY: [AtomicBool; SLOT_COUNT] =
    [const { AtomicBool::new(false) }; SLOT_COUNT];
static FX_SWITCHES: AtomicU64 = AtomicU64::new(0);
static FX_OBSERVATIONS: AtomicU64 = AtomicU64::new(0);
static FX_BAD: AtomicU64 = AtomicU64::new(0);
static FX_WORK_CHECKS: AtomicU64 = AtomicU64::new(0);

// New slot3 is created and becomes Ready WHILE first-generation tasks0/1/2
// are executing with real IRQ-driven preemption. Epoch 0: absent, 1:
// admitted, 2: worker3 requested finish, 3: actual timer IRQ suspended it.
static LIVE_PHASE: AtomicUsize = AtomicUsize::new(0);
static LIVE_HANDLE_GEN: AtomicU64 = AtomicU64::new(0);
static LIVE_ADMISSIONS: AtomicU64 = AtomicU64::new(0);
static LIVE_TASK_WORK: AtomicU64 = AtomicU64::new(0);
static LIVE_INTERRUPTED: AtomicU64 = AtomicU64::new(0);
static LIVE_BAD: AtomicU64 = AtomicU64::new(0);
static LIVE_INITIAL_XMM: AtomicU64 = AtomicU64::new(0);
static LIVE_ENTRY_SEEN: AtomicBool = AtomicBool::new(false);
static LIVE_FINISHES: AtomicU64 = AtomicU64::new(0);
static LIVE_STOP_WORK: AtomicU64 = AtomicU64::new(0);
static LIVE_FROZEN: AtomicU64 = AtomicU64::new(0);
static LIVE_SURVIVOR_SWITCHES: AtomicU64 = AtomicU64::new(0);

// Second-generation task2 runs as a single IRQ-interruptible kernel worker
// after the original fixed 3-task scheduler has stopped on the BSP stack.
// Its execution starts from the *recycled synthetic GPR+IRETQ frame*.
// ACTIVE remains false: no retired first-generation task may be resumed.
const RECYCLE_MIN_IRQS: u64 = 4;
const RECYCLE_R12: u64 = 0x1234_5678_cafe_f001;
const RECYCLE_R15: u64 = 0xface_b00c_7654_3210;
const RECYCLE_XMM0: u64 = 0xa55a_f00d_9e37_cafe;
static RECYCLE_ACTIVE: AtomicBool = AtomicBool::new(false);
static RECYCLE_RETURNED: AtomicBool = AtomicBool::new(false);
static RECYCLE_WORK: AtomicU64 = AtomicU64::new(0);
static RECYCLE_IRQS: AtomicU64 = AtomicU64::new(0);
static RECYCLE_BAD: AtomicU64 = AtomicU64::new(0);
static RECYCLE_IRQ_FIRST_WORK: AtomicU64 = AtomicU64::new(0);
static RECYCLE_BASELINE_XMM: AtomicU64 = AtomicU64::new(0);
static RECYCLE_GENERATION: AtomicU64 = AtomicU64::new(0);
static RECYCLE_OBSERVED_XMM: AtomicU64 = AtomicU64::new(0);

// Written by assembly before the new Rust worker function's prologue.
// The exact initial values are restored by IRETQ, not passed as arguments.
#[unsafe(no_mangle)]
pub static WOLFOS_RECYCLE_ENTRY_R12: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
pub static WOLFOS_RECYCLE_ENTRY_R15: AtomicU64 = AtomicU64::new(0);
static RECYCLE_BSP_RSP: BspSlot = BspSlot(UnsafeCell::new(0));
static RECYCLE_TASK_EXIT_RSP: BspSlot = BspSlot(UnsafeCell::new(0));

fn stack_bottom(id: usize) -> usize {
    // SAFETY: id is always 0 or 1, and no Rust reference to the stack is
    // created, only the stable static allocation's raw address.
    let ptr = unsafe { core::ptr::addr_of_mut!((*STACKS.0.get())[id]) };
    ptr.cast::<u8>() as usize
}

fn stack_top(id: usize) -> usize {
    stack_bottom(id) + STACK_BYTES
}

fn canary_ok(id: usize) -> bool {
    // SAFETY: only called from BSP after both tasks are stopped with IF=0.
    unsafe {
        (stack_bottom(id) as *const u64).read_volatile() == (CANARY ^ id as u64)
    }
}

fn prepare() -> bool {
    let cs = CS::get_reg().0;
    let ss = SS::get_reg().0;
    if cs == 0 || cs & 3 != 0 || ss == 0 || ss & 3 != 0 {
        return false;
    }
    CODE_SELECTOR.store(usize::from(cs), Ordering::Relaxed);
    // Task 0 is entered once from a normal ABI call-switch boundary.
    // Task 1 and 2 start from validated fabricated IRETQ frames, then
    // execute on three independent kernel stacks. No task-to-task yield.
    for id in 0..TASK_COUNT {
        let bottom = stack_bottom(id);
        let top = stack_top(id);
        if bottom & 15 != 0 || top & 15 != 0 { return false; }
        // SAFETY: only BSP initializes inactive private stack storage before
        // any worker is runnable or interrupt delivery has been enabled.
        unsafe { (bottom as *mut u64).write_volatile(CANARY ^ id as u64); }
        if id == 0 {
            let rsp = top - 8 * size_of::<usize>();
            // Six nonvolatile GPRs + return-to-entry + dummy return address.
            unsafe {
                core::ptr::write_bytes(rsp as *mut u8, 0, 64);
                (rsp as *mut usize).add(6).write(task0 as usize);
                *START_RSP.0.get() = rsp;
            }
            FRAME_RSP[id].store(0, Ordering::Relaxed);
        } else {
            let start: extern "C" fn() -> ! = match id {
                1 => task1,
                2 => task2,
                _ => return false,
            };
            let saved_rsp = top - 8 - 64 - size_of::<KernelTrapFrame>();
            if saved_rsp & 7 != 0 { return false; }
            let frame = KernelTrapFrame {
                registers: SavedGprs::default(),
                hardware: HardwareReturnFrame {
                    rip: start as usize as u64,
                    cs: u64::from(cs),
                    rflags: 0x202,
                    rsp: (top - 8) as u64,
                    ss: u64::from(ss),
                },
            };
            // SAFETY: saved_rsp is 8-byte aligned and lies entirely inside
            // task id's dedicated 16 KiB kernel stack.
            let good = unsafe {
                (saved_rsp as *mut KernelTrapFrame).write(frame);
                validate_kernel_resume(
                    saved_rsp as u64, bottom as u64, top as u64, cs,
                    &*(saved_rsp as *const KernelTrapFrame)
                ).is_ok()
            };
            if !good { return false; }
            FRAME_RSP[id].store(saved_rsp, Ordering::Relaxed);
        }
    }
    true
}

/// Called only from a genuine BSP timer IRQ with IF=0. The current
/// blocked task remains executing until its first IRQ: take the WORK[1]
/// snapshot on that IRQ, not at the earlier block() call, to avoid falsely
/// treating pre-IRQ work as a scheduling violation.
///
/// While task1 is suspended and not runnable, every additional IRQ must
/// observe a frozen work counter. After a finite number of such IRQs,
/// the timer wakes task1 by restoring its runnable bit. Its original
/// saved trap frame and FX image remain untouched until selected again.
fn timer_block_wake(current: usize) {
    if BLOCK_PHASE.load(Ordering::Acquire) != 1 {
        return;
    }
    if current == 1 {
        if !BLOCK_ENTRY_CAPTURED.swap(true, Ordering::AcqRel) {
            BLOCK_SAVED_WORK.store(WORK[1].load(Ordering::Acquire), Ordering::Release);
            BLOCK_OTHER_WORK.store(
                WORK[0].load(Ordering::Acquire)
                    + WORK[2].load(Ordering::Acquire),
                Ordering::Release
            );
        }
        return;
    }
    if !BLOCK_ENTRY_CAPTURED.load(Ordering::Acquire) {
        BLOCK_ERRORS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if WORK[1].load(Ordering::Acquire) != BLOCK_SAVED_WORK.load(Ordering::Acquire) {
        BLOCK_ERRORS.fetch_add(1, Ordering::Relaxed);
    } else {
        BLOCK_FROZEN_SAMPLES.fetch_add(1, Ordering::Relaxed);
    }
    // With bit1 masked, a tick on task0 must skip task1 and select task2.
    if current == 0 {
        BLOCK_SKIPPED.fetch_add(1, Ordering::Relaxed);
    }
    let ticks = BLOCKED_TIMER_IRQS.fetch_add(1, Ordering::AcqRel) + 1;
    if ticks >= WAKE_AFTER_BLOCKED_IRQS {
        let other_work = WORK[0].load(Ordering::Acquire)
            + WORK[2].load(Ordering::Acquire);
        if other_work <= BLOCK_OTHER_WORK.load(Ordering::Acquire) {
            BLOCK_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
        let result = RUNNABLE.fetch_update(
            Ordering::AcqRel, Ordering::Acquire,
            |mask| rr_policy::wake_unfinished(
                mask, FINISHED.load(Ordering::Acquire), 1, TASK_COUNT
            ).ok()
        );
        if result.is_ok() {
            WAKE_COUNT.fetch_add(1, Ordering::Relaxed);
            BLOCK_PHASE.store(2, Ordering::Release);
        } else {
            BLOCK_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The first timer interrupt after task2 requests Finished captures its
/// final work count on the exact interrupted instruction frame. Subsequent
/// IRQs must not schedule task2 and must find its counter unchanged.
/// No stack memory is freed while its interrupted frame exists.
fn timer_finished_task_observation(current: usize) {
    match FINISH_PHASE.load(Ordering::Acquire) {
        1 if current == 2 => {
            FINISH_WORK_SNAPSHOT.store(
                WORK[2].load(Ordering::Acquire), Ordering::Release
            );
            FINISH_PHASE.store(2, Ordering::Release);
        }
        2 => {
            if current == 2 {
                // A finished task must NEVER be dispatched again.
                FINISH_ERRORS.fetch_add(1, Ordering::Relaxed);
                return;
            }
            if WORK[2].load(Ordering::Acquire)
                == FINISH_WORK_SNAPSHOT.load(Ordering::Acquire)
            {
                FINISH_FROZEN_SAMPLES.fetch_add(1, Ordering::Relaxed);
            } else {
                FINISH_ERRORS.fetch_add(1, Ordering::Relaxed);
            }
            if current == 1 {
                // With bit2 finished, RR must wrap directly from 1 to 0.
                FINISH_SKIPS.fetch_add(1, Ordering::Relaxed);
            }
        }
        _ => {}
    }
}

/// IRQ-time handoff decision. Only the BSP xAPIC timer handler can call it.
/// No allocations, logging, task changes inside Rust frame borrows, or
/// scheduler lock acquisition. The returned pointer is a *different live
/// private stack* only when both frames pass validation.
///
/// The assembly IRQ entry restores all GPRs and IRETQs using this pointer.
pub fn select_frame(frame_ptr: *const KernelTrapFrame) -> *const KernelTrapFrame {
    if !ACTIVE.load(Ordering::Relaxed) {
        // After the original three-task run has ended, a second-generation
        // task2 may be bootstrapped straight from its freshly rebuilt
        // IRETQ frame. The scheduler stays INACTIVE; the genuine xAPIC IRQ
        // must inspect its frame, EOI, and return to that SAME new task.
        if RECYCLE_ACTIVE.load(Ordering::Acquire) {
            let addr = frame_ptr as usize;
            let bottom = stack_bottom(2);
            let top = stack_top(2);
            let cs = CODE_SELECTOR.load(Ordering::Acquire) as u16;
            let in_stack = addr & 7 == 0
                && addr >= bottom + 512
                && addr.checked_add(size_of::<KernelTrapFrame>())
                    .is_some_and(|end| end <= top);
            let valid = in_stack && unsafe {
                validate_kernel_resume(
                    addr as u64, bottom as u64, top as u64, cs, &*frame_ptr
                ).is_ok()
            };
            if !valid {
                RECYCLE_BAD.fetch_add(1, Ordering::Relaxed);
            } else {
                let earlier = RECYCLE_IRQS.fetch_add(1, Ordering::Relaxed);
                if earlier == 0 {
                    RECYCLE_IRQ_FIRST_WORK.store(
                        RECYCLE_WORK.load(Ordering::Relaxed),
                        Ordering::Relaxed
                    );
                }
            }
        }
        return frame_ptr;
    }
    // The local APIC IRQ and its EOI still occur, but a held critical
    // section must NOT trigger a kernel stack switch, even when nested.
    if !PREEMPT_DEPTH.can_preempt() {
        DEFERRED_IRQS.fetch_add(1, Ordering::Relaxed);
        return frame_ptr;
    }
    let current = CURRENT.load(Ordering::Relaxed);
    // Hardware timer-driven wake happens before round-robin selection.
    // Nested preempt-disable sections were checked above and never switch.
    timer_block_wake(current);
    timer_finished_task_observation(current);
    if current >= TASK_COUNT {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        return frame_ptr;
    }
    let next = match rr_policy::next_runnable(
        current, TASK_COUNT, RUNNABLE.load(Ordering::Relaxed)
    ) {
        Ok(id) if id != current => id,
        Ok(_) => return frame_ptr, // no alternative ready; keep running
        Err(_) => {
            REJECTED.fetch_add(1, Ordering::Relaxed);
            return frame_ptr;
        }
    };
    if FINISHED.load(Ordering::Acquire) & (1u64 << next) != 0 {
        FINISH_ERRORS.fetch_add(1, Ordering::Relaxed);
        REJECTED.fetch_add(1, Ordering::Relaxed);
        return frame_ptr;
    }
    let old_rsp = frame_ptr as usize;
    let next_rsp = FRAME_RSP[next].load(Ordering::Relaxed);
    let cs = CODE_SELECTOR.load(Ordering::Relaxed) as u16;
    let old_ok = old_rsp >= stack_bottom(current) + 512
        && old_rsp.checked_add(size_of::<KernelTrapFrame>())
            .is_some_and(|end| end <= stack_top(current));
    let new_ok = next_rsp >= stack_bottom(next) + 512
        && next_rsp.checked_add(size_of::<KernelTrapFrame>())
            .is_some_and(|end| end <= stack_top(next));
    if !old_ok || !new_ok {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        return frame_ptr;
    }
    // SAFETY: both bounded, stable and sufficiently aligned BSP-owned frames;
    // only the currently interrupted task's frame is written by the CPU.
    // Other task is suspended; its frame remains immutable until resumed.
    let valid = unsafe {
        validate_kernel_resume(
            old_rsp as u64, stack_bottom(current) as u64,
            stack_top(current) as u64, cs, &*frame_ptr
        ).is_ok() && validate_kernel_resume(
            next_rsp as u64, stack_bottom(next) as u64,
            stack_top(next) as u64, cs, &*(next_rsp as *const KernelTrapFrame)
        ).is_ok()
    };
    if !valid {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        return frame_ptr;
    }

    // SAFETY: both full frames have been validated. Only BSP enters this
    // IF=0 IRQ dispatcher; FX images are private, aligned and initialized.
    let Some(saved_xmm) = (unsafe { fx_state::switch(current, next) }) else {
        REJECTED.fetch_add(1, Ordering::Relaxed);
        return frame_ptr;
    };
    FX_SWITCHES.fetch_add(1, Ordering::Relaxed);
    if XMM_READY[current].load(Ordering::Relaxed) {
        FX_OBSERVATIONS.fetch_add(1, Ordering::Relaxed);
        if saved_xmm != TASK_XMM0[current] {
            FX_BAD.fetch_add(1, Ordering::Relaxed);
        }
    }
    FRAME_RSP[current].store(old_rsp, Ordering::Relaxed);
    INTERRUPTED[current].fetch_add(1, Ordering::Relaxed);
    CURRENT.store(next, Ordering::Relaxed);
    SWITCHES.fetch_add(1, Ordering::Relaxed);
    if FINISH_PHASE.load(Ordering::Acquire) >= 1 {
        if next < 2 {
            POST_FINISH_VISITS[next].fetch_add(1, Ordering::Relaxed);
        } else {
            FINISH_ERRORS.fetch_add(1, Ordering::Relaxed);
        }
    } else if BLOCK_PHASE.load(Ordering::Acquire) >= 2 {
        POST_WAKE_VISITS[next].fetch_add(1, Ordering::Relaxed);
    }
    next_rsp as *const KernelTrapFrame
}

/// Prove that two nested task-owned critical sections suppress involuntary
/// switching but NOT timer IRQ/EOI delivery. Task 0 alone owns the depth;
/// task 1 cannot start until the outermost enable releases preemption.
fn check_nested_irq_deferral() -> bool {
    if PREEMPT_DEPTH.depth() != 2 || SWITCHES.load(Ordering::Relaxed) != 0 {
        return false;
    }
    for phase in 0..2 {
        let target = (phase as u64 + 1) * 2;
        let mut observed = false;
        for _ in 0..MAX_TASK_SPINS {
            if DEFERRED_IRQS.load(Ordering::Relaxed) >= target {
                observed = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !observed || SWITCHES.load(Ordering::Relaxed) != 0
            || WORK[1].load(Ordering::Relaxed) != 0
            || WORK[2].load(Ordering::Relaxed) != 0
        {
            return false;
        }
        if PREEMPT_DEPTH.enable() != Ok(1 - phase) {
            return false;
        }
    }
    PREEMPT_DEPTH.can_preempt()
        && PREEMPT_DEPTH.depth() == 0
        && DEFERRED_IRQS.load(Ordering::Relaxed) >= 4
        && SWITCHES.load(Ordering::Relaxed) == 0
}

#[inline(never)]
fn busy_task(id: usize) -> ! {
    // Set IF only AFTER entering this private stack. Each task spins doing
    // independent atomic work and NEVER calls yield to the other task.
    x86_64::instructions::interrupts::enable();
    if id == 0 {
        let nested_ok = check_nested_irq_deferral();
        NESTED_GUARD_OK.store(nested_ok, Ordering::Release);
        if !nested_ok {
            // Fail closed; return to the BSP instead of spinning forever in
            // a permanently preempt-disabled state.
            x86_64::instructions::interrupts::disable();
            ACTIVE.store(false, Ordering::Relaxed);
            EXIT_TASK.store(id, Ordering::Release);
            unsafe { context_switch::switch_raw(EXIT_RSP.0.get(), BSP_RSP.0.get()); }
            crate::halt_forever()
        }
    }
    // FXSAVE64 captures XMM0 at each genuine IRQ switch; FXRSTOR64 must
    // return the expected lane even after the other task has run.
    unsafe { fx_state::set_test_xmm0(TASK_XMM0[id]); }
    XMM_READY[id].store(true, Ordering::Release);
    // This local variable is saved in the task's genuine suspended stack
    // and GPR frame. The loop never yields to another task voluntarily.
    let mut blocked_once = false;
    let mut resumed_once = false;
    let mut finished_once = false;
    for _ in 0..MAX_TASK_SPINS {
        if id == 1 && !blocked_once && WORK[1].load(Ordering::Acquire) >= 128 {
            // The task itself requests Blocked; nested preempt-disable
            // prevents an IRQ handoff across the bitmap+phase update.
            // Hardware interrupts still execute and receive EOI.
            if PREEMPT_DEPTH.disable() != Ok(1) {
                BLOCK_ERRORS.fetch_add(1, Ordering::Relaxed);
                break;
            }
            let blocked = RUNNABLE.fetch_update(
                Ordering::AcqRel, Ordering::Acquire,
                |mask| rr_policy::block_runnable(mask, 1, TASK_COUNT).ok()
            ).is_ok();
            if blocked {
                BLOCK_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
                BLOCK_PHASE.store(1, Ordering::Release);
            } else {
                BLOCK_ERRORS.fetch_add(1, Ordering::Relaxed);
            }
            if PREEMPT_DEPTH.enable() != Ok(0) {
                BLOCK_ERRORS.fetch_add(1, Ordering::Relaxed);
                break;
            }
            blocked_once = true;
        }
        if id == 1 && blocked_once && !resumed_once
            && BLOCK_PHASE.load(Ordering::Acquire) == 2
        {
            // We returned from the original interrupted RIP and task stack
            // only after the timer woke us. XMM0 is checked immediately
            // below to verify saved/restored floating-point ownership.
            RESUME_COUNT.fetch_add(1, Ordering::Relaxed);
            BLOCK_PHASE.store(3, Ordering::Release);
            resumed_once = true;
        }
        if id == 2 && !finished_once
            && BLOCK_PHASE.load(Ordering::Acquire) == 3
            && SWITCHES.load(Ordering::Relaxed) >= FINISH_AFTER_SWITCHES
            && POST_WAKE_VISITS.iter().all(|visit|
                visit.load(Ordering::Relaxed) >= MIN_EPOCHS_PER_TASK
            )
        {
            // Task 2 completes on its actual private kernel stack. No
            // task-to-task yield is involved; it runs until the next xAPIC
            // IRQ then remains permanently excluded from runnable masks.
            if PREEMPT_DEPTH.disable() != Ok(1) {
                FINISH_ERRORS.fetch_add(1, Ordering::Relaxed);
                break;
            }
            let finished = RUNNABLE.fetch_update(
                Ordering::AcqRel, Ordering::Acquire,
                |mask| rr_policy::finish_runnable(
                    mask, FINISHED.load(Ordering::Acquire), 2, TASK_COUNT
                ).ok().map(|(ready, _)| ready)
            ).is_ok();
            // SAFETY: the single BSP owns this table. Nestable preemption
            // guard prevents the IRQ dispatcher from switching to another
            // Rust task while this metadata is being updated. The IRQ
            // callback never reads SLOT_OWNERS.
            let ownership_finished = if finished {
                unsafe {
                    let table = &mut *SLOT_OWNERS.0.get();
                    table.handle(2)
                        .ok()
                        .is_some_and(|handle| table.finish(handle).is_ok())
                }
            } else { false };
            if finished && ownership_finished {
                FINISHED.store(1u64 << 2, Ordering::Release);
                FINISH_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
                FINISH_PHASE.store(1, Ordering::Release);
            } else {
                FINISH_ERRORS.fetch_add(1, Ordering::Relaxed);
            }
            if PREEMPT_DEPTH.enable() != Ok(0) {
                FINISH_ERRORS.fetch_add(1, Ordering::Relaxed);
                break;
            }
            finished_once = true;
        }
        let lane = unsafe { fx_state::read_test_xmm0() };
        FX_WORK_CHECKS.fetch_add(1, Ordering::Relaxed);
        if lane != TASK_XMM0[id] {
            FX_BAD.fetch_add(1, Ordering::Relaxed);
            break;
        }
        WORK[id].fetch_add(1, Ordering::Relaxed);
        if SWITCHES.load(Ordering::Relaxed) >= STOP_AFTER
            && BLOCK_PHASE.load(Ordering::Acquire) == 3
            && FINISH_PHASE.load(Ordering::Acquire) == 2
            && FINISH_FROZEN_SAMPLES.load(Ordering::Relaxed) >= FINISH_FREEZE_REQUIRED
            && POST_FINISH_VISITS.iter().all(|count|
                count.load(Ordering::Relaxed) >= MIN_EPOCHS_PER_TASK
            )
            && POST_WAKE_VISITS.iter().all(|count|
                count.load(Ordering::Relaxed) >= MIN_EPOCHS_PER_TASK
            )
            && WORK.iter().all(|work| work.load(Ordering::Relaxed) != 0)
            && INTERRUPTED.iter().all(|count|
                count.load(Ordering::Relaxed) >= MIN_EPOCHS_PER_TASK
            )
        {
            break;
        }
        core::hint::spin_loop();
    }
    // Exactly ONE task exits after enough *involuntary* two-task switches.
    // The other remains suspended on its private stack. No future IRQ can
    // select it after ACTIVE clears and IF=0.
    x86_64::instructions::interrupts::disable();
    ACTIVE.store(false, Ordering::Relaxed);
    EXIT_TASK.store(id, Ordering::Release);
    // SAFETY: only BSP, IF=0, task's current context and saved BSP context
    // are different, live and disjoint; no Rust borrow spans this switch.
    unsafe { context_switch::switch_raw(EXIT_RSP.0.get(), BSP_RSP.0.get()); }
    crate::halt_forever()
}

extern "C" fn task0() -> ! { busy_task(0) }
extern "C" fn task1() -> ! { busy_task(1) }
extern "C" fn task2() -> ! { busy_task(2) }

/// Proof of safe reuse of an INACTIVE slot: the original task 2 was
/// interrupted, marked Finished, and left off the runnable list for >=6
/// genuine timer IRQ observations. Only after all task contexts have exited
/// to the disjoint BSP stack and IF=0 do we scrub its physical stack memory.
/// There is NO actual new task execution in this test.
struct RecycleProof {
    old_generation: u64,
    new_generation: u64,
    scrubbed_stack: bool,
    fx: fx_state::FxRecycleProof,
    valid_new_frame: bool,
    stale_rejected: bool,
    old_handle_refused_while_running: bool,
    grace_refused: bool,
}

fn recycle_quiescent_task2() -> Option<RecycleProof> {
    let interrupts_disabled = !x86_64::instructions::interrupts::are_enabled();
    // SAFETY: read the real BSP RSP register; this does not access any
    // memory, change flags or modify the current execution context.
    let bsp_rsp: usize;
    unsafe {
        core::arch::asm!(
            "mov {}, rsp",
            out(reg) bsp_rsp,
            options(nomem, nostack, preserves_flags)
        );
    }
    let disjoint_bsp = (0..TASK_COUNT).all(|id|
        bsp_rsp < stack_bottom(id) || bsp_rsp >= stack_top(id)
    );
    let scheduler_inactive = !ACTIVE.load(Ordering::Acquire)
        && PREEMPT_DEPTH.depth() == 0;
    let old_task_not_current =
        CURRENT.load(Ordering::Acquire) != 2;
    let ready_mask = RUNNABLE.load(Ordering::Acquire);
    let finished_mask = FINISHED.load(Ordering::Acquire);
    let frozen = FINISH_FROZEN_SAMPLES.load(Ordering::Acquire);
    let saved_rsp = FRAME_RSP[2].load(Ordering::Acquire);
    let bottom = stack_bottom(2);
    let top = stack_top(2);

    // Never touch a live or uncleared task stack. This is BSP-only; all APs
    // remain parked with their maskable interrupts disabled throughout QEMU
    // smoke. No cross-CPU reclamation is possible with this prototype.
    if !interrupts_disabled || !scheduler_inactive || !disjoint_bsp
        || !old_task_not_current || ready_mask != 0b011
        || finished_mask != 0b100
        || FINISH_PHASE.load(Ordering::Acquire) != 2
        || FINISH_ERRORS.load(Ordering::Acquire) != 0
        || frozen < task_slot::MIN_GRACE_IRQS
        || !canary_ok(2) || saved_rsp & 7 != 0
        || saved_rsp < bottom + 512
        || saved_rsp.checked_add(size_of::<KernelTrapFrame>())
            .is_none_or(|end| end > top)
    {
        return None;
    }
    let cs = CODE_SELECTOR.load(Ordering::Acquire) as u16;
    // SAFETY: bounds and alignment were explicitly verified above.
    // This is a suspended kernel task's still-owned IRQ trap frame, and IF=0.
    let old_valid = unsafe {
        validate_kernel_resume(
            saved_rsp as u64, bottom as u64, top as u64, cs,
            &*(saved_rsp as *const KernelTrapFrame)
        ).is_ok()
    };
    if !old_valid { return None; }

    let gate = ReclaimGate {
        interrupts_disabled,
        scheduler_inactive,
        bsp_on_disjoint_stack: disjoint_bsp,
        old_task_not_current,
        ready_mask,
        finished_mask,
        frozen_irq_observations: frozen,
    };
    // SAFETY: IF=0 on BSP and task execution has stopped. Timer IRQ Rust
    // dispatcher never reads the ownership table, and no AP accesses it.
    let table = unsafe { &mut *SLOT_OWNERS.0.get() };
    let old_handle = table.handle(2).ok()?;
    if table.state(old_handle).ok()? != SlotState::Finished {
        return None;
    }
    let running_gate = ReclaimGate {
        interrupts_disabled: false,
        ..gate
    };
    let early_gate = ReclaimGate {
        frozen_irq_observations: task_slot::MIN_GRACE_IRQS - 1,
        ..gate
    };
    let old_handle_refused_while_running =
        table.retire(old_handle, running_gate) == Err(SlotError::NotQuiescent);
    let grace_refused = table.retire(old_handle, early_gate)
        == Err(SlotError::InsufficientObservedGrace);
    if !old_handle_refused_while_running || !grace_refused
        || table.state(old_handle).ok()? != SlotState::Finished
    {
        return None;
    }
    table.retire(old_handle, gate).ok()?;

    // Task2 cannot be selected with its finished runnable mask. Invalidate
    // the saved return-frame pointer BEFORE wiping the dead stack.
    if FRAME_RSP[2].swap(0, Ordering::AcqRel) != saved_rsp {
        return None;
    }
    // SAFETY: IF=0, real CPU RSP is on a different BSP stack and the only
    // APs are parked; task2 is fully retired and cannot resume. The 16 KiB
    // region is private to slot2 and does not overlap other task stacks.
    let scrubbed_stack = unsafe {
        // Volatile writes make the clearing operation observable even in
        // a release/optimized kernel: do not elide dead-stack scrubbing.
        for offset in (0..STACK_BYTES).step_by(size_of::<u64>()) {
            core::ptr::write_volatile((bottom + offset) as *mut u64, 0);
        }
        (0..STACK_BYTES).step_by(size_of::<u64>()).all(|offset|
            core::ptr::read_volatile((bottom + offset) as *const u64) == 0
        )
    };
    if !scrubbed_stack { return None; }

    // SAFETY: image is inactive after the real preemption proof, and the
    // original BSP FX state has already been restored by leave().
    let fx = unsafe { fx_state::recycle_task_image(2) }?;
    if !fx.aligned || !fx.fully_scrubbed || !fx.baseline_reseeded
        || fx.old_xmm0 != TASK_XMM0[2]
    {
        return None;
    }

    let new_handle = table.spawn(2).ok()?;
    let stale_rejected =
        table.state(old_handle) == Err(SlotError::StaleHandle)
        && table.finish(old_handle) == Err(SlotError::StaleHandle)
        && table.state(new_handle).ok()? == SlotState::Allocated
        && new_handle.generation == old_handle.generation.checked_add(1)?;

    // Reinitialize a fresh, unqueued kernel-only IRETQ frame on the same
    // wiped physical stack. It is validated but NEVER dispatched in this
    // test; future work must implement controlled task creation/enqueue.
    let new_rsp = top - 8 - 64 - size_of::<KernelTrapFrame>();
    let next = KernelTrapFrame {
        registers: SavedGprs {
            r12: RECYCLE_R12,
            r15: RECYCLE_R15,
            ..SavedGprs::default()
        },
        hardware: HardwareReturnFrame {
            rip: crate::apic_irq_entry::recycled_entry_address(),
            cs: u64::from(cs),
            rflags: 0x202,
            rsp: (top - 8) as u64,
            ss: u64::from(SS::get_reg().0),
        },
    };
    // SAFETY: this new frame lies inside the now-unowned, cleared stack2;
    // task2 remains NOT RUNNABLE and no IRQ can attempt to restore it.
    let valid_new_frame = unsafe {
        (bottom as *mut u64).write_volatile(CANARY ^ 2);
        (new_rsp as *mut KernelTrapFrame).write(next);
        validate_kernel_resume(
            new_rsp as u64, bottom as u64, top as u64, cs,
            &*(new_rsp as *const KernelTrapFrame)
        ).is_ok()
    } && canary_ok(2)
        && RUNNABLE.load(Ordering::Acquire) & (1u64 << 2) == 0;
    FRAME_RSP[2].store(new_rsp, Ordering::Release);
    if !stale_rejected || !valid_new_frame {
        return None;
    }
    Some(RecycleProof {
        old_generation: old_handle.generation,
        new_generation: new_handle.generation,
        scrubbed_stack,
        fx,
        valid_new_frame,
        stale_rejected,
        old_handle_refused_while_running,
        grace_refused,
    })
}

/// New task generation's entry point. Hand-written assembly captures its
/// initially restored r12/r15 at the very first instruction BEFORE jumping
/// here. This task never uses the first generation task2 control flow.
///
/// Unlike the old task2, this worker runs with only its OWN bit admitted
/// to the test's ready mask. The old task0/1 contexts are retired from the
/// runnable epoch, and ACTIVE remains false: every IRQ returns to this
/// worker, never to a first-generation saved stack or FX image.
#[unsafe(no_mangle)]
pub extern "C" fn wolfos_recycled_task_entry() -> ! {
    let baseline = unsafe { fx_state::read_test_xmm0() };
    RECYCLE_OBSERVED_XMM.store(baseline, Ordering::Release);
    if WOLFOS_RECYCLE_ENTRY_R12.load(Ordering::Acquire) != RECYCLE_R12
        || WOLFOS_RECYCLE_ENTRY_R15.load(Ordering::Acquire) != RECYCLE_R15
        || baseline != RECYCLE_BASELINE_XMM.load(Ordering::Acquire)
        || RECYCLE_GENERATION.load(Ordering::Acquire) < 2
    {
        RECYCLE_BAD.fetch_add(1, Ordering::Relaxed);
    }
    unsafe { fx_state::set_test_xmm0(RECYCLE_XMM0); }
    // Establish nonzero real work before arming the IRQ capture, so an
    // immediately delivered APIC timer IRQ cannot fake worker progress.
    for _ in 0..256 {
        RECYCLE_WORK.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
    RECYCLE_ACTIVE.store(true, Ordering::Release);
    for _ in 0..MAX_TASK_SPINS {
        if unsafe { fx_state::read_test_xmm0() } != RECYCLE_XMM0 {
            RECYCLE_BAD.fetch_add(1, Ordering::Relaxed);
            break;
        }
        let work = RECYCLE_WORK.fetch_add(1, Ordering::Relaxed) + 1;
        let first = RECYCLE_IRQ_FIRST_WORK.load(Ordering::Acquire);
        if RECYCLE_IRQS.load(Ordering::Acquire) >= RECYCLE_MIN_IRQS
            && first > 0 && work > first + 512
        {
            break;
        }
        core::hint::spin_loop();
    }
    x86_64::instructions::interrupts::disable();
    RECYCLE_ACTIVE.store(false, Ordering::Release);
    RECYCLE_RETURNED.store(true, Ordering::Release);
    // SAFETY: BSP only, IF=0. The original caller context is waiting on
    // its own disjoint BSP stack with six SysV callee-saved registers.
    // This worker's stack is not overwritten before the return completes.
    unsafe {
        context_switch::switch_raw(
            RECYCLE_TASK_EXIT_RSP.0.get(), RECYCLE_BSP_RSP.0.get()
        );
    }
    crate::halt_forever()
}

/// Dispatch the initialized second-generation task2's actual GPR+IRETQ
/// frame ONCE, observe >=4 live APIC timer IRQs on its recycled stack and
/// return to the BSP with IF=0. No other task is runnable in this epoch.
fn prove_recycled_task_runs(proof: &RecycleProof) -> bool {
    let fail = |reason| {
        crate::serial::write_fmt(format_args!(
            "WOLFOS_APIC_REUSE_EXEC_ERROR stage={}\n", reason
        ));
        false
    };
    if x86_64::instructions::interrupts::are_enabled()
        || ACTIVE.load(Ordering::Acquire)
        || RECYCLE_ACTIVE.load(Ordering::Acquire)
        || PREEMPT_DEPTH.depth() != 0
        || proof.old_generation.checked_add(1) != Some(proof.new_generation)
        || FINISHED.load(Ordering::Acquire) != 0b100
        || RUNNABLE.load(Ordering::Acquire) != 0b011
    {
        return fail("not_quiescent");
    }
    let frame_rsp = FRAME_RSP[2].load(Ordering::Acquire);
    let bottom = stack_bottom(2);
    let top = stack_top(2);
    let cs = CODE_SELECTOR.load(Ordering::Acquire) as u16;
    let bounded = frame_rsp >= bottom + 512
        && frame_rsp & 7 == 0
        && frame_rsp.checked_add(size_of::<KernelTrapFrame>())
            .is_some_and(|end| end <= top);
    let valid = bounded && unsafe {
        let frame = &*(frame_rsp as *const KernelTrapFrame);
        validate_kernel_resume(
            frame_rsp as u64, bottom as u64, top as u64, cs, frame
        ).is_ok()
            && frame.hardware.rip == crate::apic_irq_entry::recycled_entry_address()
            && frame.registers.r12 == RECYCLE_R12
            && frame.registers.r15 == RECYCLE_R15
    };
    if !valid || !canary_ok(2) {
        return fail("invalid_recycled_frame");
    }
    let handle = task_slot::TaskHandle {
        slot: 2, generation: proof.new_generation
    };
    // SAFETY: BSP alone, IF=0, no ISR borrows the ownership table.
    let owner_valid = unsafe {
        let table = &*SLOT_OWNERS.0.get();
        table.state(handle) == Ok(SlotState::Allocated)
            && table.state(task_slot::TaskHandle {
                slot: 2, generation: proof.old_generation
            }) == Err(SlotError::StaleHandle)
    };
    if !owner_valid { return fail("stale_or_unallocated"); }

    RECYCLE_ACTIVE.store(false, Ordering::Relaxed);
    RECYCLE_RETURNED.store(false, Ordering::Relaxed);
    RECYCLE_WORK.store(0, Ordering::Relaxed);
    RECYCLE_IRQS.store(0, Ordering::Relaxed);
    RECYCLE_BAD.store(0, Ordering::Relaxed);
    RECYCLE_IRQ_FIRST_WORK.store(0, Ordering::Relaxed);
    RECYCLE_OBSERVED_XMM.store(0, Ordering::Relaxed);
    RECYCLE_BASELINE_XMM.store(0, Ordering::Relaxed);
    RECYCLE_GENERATION.store(proof.new_generation, Ordering::Release);
    WOLFOS_RECYCLE_ENTRY_R12.store(0, Ordering::Relaxed);
    WOLFOS_RECYCLE_ENTRY_R15.store(0, Ordering::Relaxed);

    // Re-enable the original BSP's x87/SSE controls for this separate
    // task bootstrap, and load ONLY the prepared new task FX image.
    // The old first-generation task2 XMM0 sentinel cannot reappear.
    let Some(original_fx) = (unsafe {
        fx_state::enter_preserving_prepared_images()
    }) else {
        return fail("fx_unsupported");
    };
    let Some(initial_xmm) = (unsafe { fx_state::activate_prepared_task(2) })
    else {
        unsafe { fx_state::leave(original_fx); }
        return fail("fx_activate");
    };
    RECYCLE_BASELINE_XMM.store(initial_xmm, Ordering::Release);
    if initial_xmm == TASK_XMM0[2] {
        unsafe { fx_state::leave(original_fx); }
        return fail("stale_xmm_exposed");
    }

    // Retire first-generation READY bitmap, keeping all its stack frames
    // unreachable. Admit ONLY this new generation's validated task slot.
    // There is no active generic task scheduler; IRQs simply IRETQ to
    // the new worker, which returns once to its saved BSP caller.
    RUNNABLE.store(1 << 2, Ordering::Release);
    FINISHED.store(0, Ordering::Release);
    // SAFETY: BSP, IF=0 and valid isolated private x86-64 kernel frame.
    // IRETQ enables IF *on the worker's stack*, not on the BSP. The worker
    // returns via the paired context_switch primitive with IF=0.
    unsafe {
        crate::apic_irq_entry::enter_recycled_frame(
            RECYCLE_BSP_RSP.0.get(), frame_rsp
        );
    }
    x86_64::instructions::interrupts::disable();

    let returned = RECYCLE_RETURNED.load(Ordering::Acquire);
    let live_irqs = RECYCLE_IRQS.load(Ordering::Acquire);
    let bad = RECYCLE_BAD.load(Ordering::Acquire);
    let work = RECYCLE_WORK.load(Ordering::Acquire);
    let first_irq_work = RECYCLE_IRQ_FIRST_WORK.load(Ordering::Acquire);
    let entry_r12 = WOLFOS_RECYCLE_ENTRY_R12.load(Ordering::Acquire);
    let entry_r15 = WOLFOS_RECYCLE_ENTRY_R15.load(Ordering::Acquire);
    let observed_baseline = RECYCLE_OBSERVED_XMM.load(Ordering::Acquire);
    let observed_final = unsafe { fx_state::snapshot_active_task(2) };
    // SAFETY: IF=0 on the BSP, second-generation task has returned on
    // another stack, and the timer ISR will no longer restore this FX state.
    unsafe { fx_state::leave(original_fx); }
    RUNNABLE.store(0, Ordering::Release);
    FINISHED.store(1 << 2, Ordering::Release);
    // SAFETY: BSP IF=0, the old handle cannot be mistaken for the new one.
    let state_ok = unsafe {
        let table = &mut *SLOT_OWNERS.0.get();
        table.finish(handle).is_ok()
            && table.state(handle) == Ok(SlotState::Finished)
            && table.state(task_slot::TaskHandle {
                slot: 2, generation: proof.old_generation
            }) == Err(SlotError::StaleHandle)
    };
    let ok = returned && !RECYCLE_ACTIVE.load(Ordering::Acquire)
        && live_irqs >= RECYCLE_MIN_IRQS && bad == 0
        && first_irq_work > 0 && work > first_irq_work + 512
        && entry_r12 == RECYCLE_R12 && entry_r15 == RECYCLE_R15
        && observed_baseline == initial_xmm
        && observed_final == Some(RECYCLE_XMM0)
        && initial_xmm != TASK_XMM0[2]
        && state_ok && canary_ok(2)
        && !x86_64::instructions::interrupts::are_enabled()
        && !ACTIVE.load(Ordering::Acquire)
        && RUNNABLE.load(Ordering::Acquire) == 0
        && FINISHED.load(Ordering::Acquire) == 0b100;
    if ok {
        crate::serial::write_fmt(format_args!(
            "WOLFOS_APIC_REUSE_EXEC_OK task=2 old_gen={} new_gen={} via_iretq=1 entry_r12={:#x} entry_r15={:#x} irq={} work={} first_irq_work={} xmm_initial={:#x} xmm_final={:#x} xmm_old={:#x} corrupt={} stale=1 finished_new=1 ready=0 bsp_only=1\n",
            proof.old_generation, proof.new_generation,
            entry_r12, entry_r15, live_irqs, work, first_irq_work,
            initial_xmm, observed_final.unwrap_or(0), TASK_XMM0[2], bad
        ));
    } else {
        crate::serial::write_fmt(format_args!(
            "WOLFOS_APIC_REUSE_EXEC_ERROR stage=validation returned={} irq={} work={} first_irq_work={} r12={:#x} r15={:#x} xmm_initial={:#x} xmm_observed={:#x} xmm_final={:?} corrupt={} ownership={}\n",
            returned, live_irqs, work, first_irq_work, entry_r12,
            entry_r15, initial_xmm, observed_baseline, observed_final,
            bad, state_ok
        ));
    }
    ok
}

/// BSP only; enter and leave with IRQs disabled. APIC timer hardware remains
/// mapped and programmed by the caller; APs are parked (IF=0).
pub fn verify() -> bool {
    if x86_64::instructions::interrupts::are_enabled()
        || STARTED.swap(true, Ordering::AcqRel) || !prepare()
    {
        return false;
    }
    // SAFETY: BSP IF=0 before any private task runs. This table is never
    // touched by the timer interrupt dispatcher (which uses atomics only).
    let allocated = unsafe {
        let table = &mut *SLOT_OWNERS.0.get();
        (0..TASK_COUNT).all(|id| table.spawn(id).is_ok())
    };
    if !allocated { return false; }
    CURRENT.store(0, Ordering::Relaxed);
    for work in &WORK { work.store(0, Ordering::Relaxed); }
    for interrupted in &INTERRUPTED { interrupted.store(0, Ordering::Relaxed); }
    RUNNABLE.store((1 << TASK_COUNT) - 1, Ordering::Release);
    BLOCK_PHASE.store(0, Ordering::Relaxed);
    BLOCK_ENTRY_CAPTURED.store(false, Ordering::Relaxed);
    BLOCK_SAVED_WORK.store(0, Ordering::Relaxed);
    BLOCK_OTHER_WORK.store(0, Ordering::Relaxed);
    BLOCKED_TIMER_IRQS.store(0, Ordering::Relaxed);
    BLOCK_FROZEN_SAMPLES.store(0, Ordering::Relaxed);
    BLOCK_SKIPPED.store(0, Ordering::Relaxed);
    BLOCK_ATTEMPTS.store(0, Ordering::Relaxed);
    WAKE_COUNT.store(0, Ordering::Relaxed);
    RESUME_COUNT.store(0, Ordering::Relaxed);
    BLOCK_ERRORS.store(0, Ordering::Relaxed);
    for visit in &POST_WAKE_VISITS { visit.store(0, Ordering::Relaxed); }
    FINISH_PHASE.store(0, Ordering::Relaxed);
    FINISHED.store(0, Ordering::Relaxed);
    FINISH_ATTEMPTS.store(0, Ordering::Relaxed);
    FINISH_WORK_SNAPSHOT.store(0, Ordering::Relaxed);
    FINISH_FROZEN_SAMPLES.store(0, Ordering::Relaxed);
    FINISH_SKIPS.store(0, Ordering::Relaxed);
    FINISH_ERRORS.store(0, Ordering::Relaxed);
    for visit in &POST_FINISH_VISITS { visit.store(0, Ordering::Relaxed); }
    SWITCHES.store(0, Ordering::Relaxed);
    REJECTED.store(0, Ordering::Relaxed);
    EXIT_TASK.store(usize::MAX, Ordering::Relaxed);
    DEFERRED_IRQS.store(0, Ordering::Relaxed);
    NESTED_GUARD_OK.store(false, Ordering::Relaxed);
    FX_SWITCHES.store(0, Ordering::Relaxed);
    FX_OBSERVATIONS.store(0, Ordering::Relaxed);
    FX_BAD.store(0, Ordering::Relaxed);
    FX_WORK_CHECKS.store(0, Ordering::Relaxed);
    for ready in &XMM_READY { ready.store(false, Ordering::Relaxed); }
    if PREEMPT_DEPTH.disable() != Ok(1) || PREEMPT_DEPTH.disable() != Ok(2) {
        return false;
    }
    // SAFETY: BSP IF=0, APs parked. Save the original CPU x87/SSE
    // context and CR0/CR4 before any private kernel task runs.
    let Some(original_fx) = (unsafe { fx_state::enter() }) else {
        return false;
    };
    ACTIVE.store(true, Ordering::Release);

    // SAFETY: starts first task at normal ABI boundary, IF=0 on BSP.
    // From now on, ONLY hardware interrupts rotate tasks 0 -> 1 -> 2.
    unsafe { context_switch::switch_raw(BSP_RSP.0.get(), START_RSP.0.get()); }

    let unexpected_interrupt_state = x86_64::instructions::interrupts::are_enabled()
        || ACTIVE.load(Ordering::Acquire);
    // Restore even on failure; no task remains runnable after returning
    // from the one-time BSP exit switch.
    x86_64::instructions::interrupts::disable();
    let switches = SWITCHES.load(Ordering::Acquire);
    let first = INTERRUPTED[0].load(Ordering::Acquire);
    let second = INTERRUPTED[1].load(Ordering::Acquire);
    let third = INTERRUPTED[2].load(Ordering::Acquire);
    let work0 = WORK[0].load(Ordering::Acquire);
    let work1 = WORK[1].load(Ordering::Acquire);
    let work2 = WORK[2].load(Ordering::Acquire);
    let rejected = REJECTED.load(Ordering::Acquire);
    let deferred = DEFERRED_IRQS.load(Ordering::Acquire);
    let depth = PREEMPT_DEPTH.depth();
    let nested_ok = NESTED_GUARD_OK.load(Ordering::Acquire);
    let exit_task = EXIT_TASK.load(Ordering::Acquire);
    let fx_switches = FX_SWITCHES.load(Ordering::Acquire);
    let fx_observations = FX_OBSERVATIONS.load(Ordering::Acquire);
    let fx_bad = FX_BAD.load(Ordering::Acquire);
    let fx_work_checks = FX_WORK_CHECKS.load(Ordering::Acquire);
    let xmm_ready = XMM_READY.iter().all(|x| x.load(Ordering::Acquire));
    let block_phase = BLOCK_PHASE.load(Ordering::Acquire);
    let block_irqs = BLOCKED_TIMER_IRQS.load(Ordering::Acquire);
    let freeze_checks = BLOCK_FROZEN_SAMPLES.load(Ordering::Acquire);
    let block_skips = BLOCK_SKIPPED.load(Ordering::Acquire);
    let block_attempts = BLOCK_ATTEMPTS.load(Ordering::Acquire);
    let wakes = WAKE_COUNT.load(Ordering::Acquire);
    let resumed = RESUME_COUNT.load(Ordering::Acquire);
    let block_errors = BLOCK_ERRORS.load(Ordering::Acquire);
    let frozen_work = BLOCK_SAVED_WORK.load(Ordering::Acquire);
    let post0 = POST_WAKE_VISITS[0].load(Ordering::Acquire);
    let post1 = POST_WAKE_VISITS[1].load(Ordering::Acquire);
    let post2 = POST_WAKE_VISITS[2].load(Ordering::Acquire);
    let finish_phase = FINISH_PHASE.load(Ordering::Acquire);
    let finished_mask = FINISHED.load(Ordering::Acquire);
    let finish_attempts = FINISH_ATTEMPTS.load(Ordering::Acquire);
    let finish_work = FINISH_WORK_SNAPSHOT.load(Ordering::Acquire);
    let finish_freezes = FINISH_FROZEN_SAMPLES.load(Ordering::Acquire);
    let finish_skips = FINISH_SKIPS.load(Ordering::Acquire);
    let finish_errors = FINISH_ERRORS.load(Ordering::Acquire);
    let survivor0 = POST_FINISH_VISITS[0].load(Ordering::Acquire);
    let survivor1 = POST_FINISH_VISITS[1].load(Ordering::Acquire);
    let post_min = post0.min(post1).min(post2);
    let post_max = post0.max(post1).max(post2);
    // SAFETY: no further private task or APIC handler uses FX state,
    // interrupts disabled. Recover the original BSP xstate and CR0/CR4.
    unsafe { fx_state::leave(original_fx); }
    let min_irqs = first.min(second).min(third);
    // Blocking is intentionally unfair during its bounded sleep. Measure
    // round-robin fairness ONLY after task1 is made runnable again.
    let ok = !unexpected_interrupt_state && switches >= STOP_AFTER
        && min_irqs >= MIN_EPOCHS_PER_TASK
        && post_min >= MIN_EPOCHS_PER_TASK && post_max - post_min <= 1
        && first + second + third == switches
        && work0 > 0 && work1 > 0 && work2 > 0
        && rejected == 0 && exit_task < TASK_COUNT
        && deferred >= 4 && nested_ok && depth == 0
        && fx_switches == switches
        && fx_observations >= STOP_AFTER - 1
        && fx_work_checks > 0 && xmm_ready && fx_bad == 0
        && block_phase == 3
        && block_attempts == 1 && wakes == 1 && resumed == 1
        && block_irqs >= WAKE_AFTER_BLOCKED_IRQS
        && freeze_checks == block_irqs && block_skips >= 2
        && frozen_work > 0 && block_errors == 0
        && RUNNABLE.load(Ordering::Acquire) == 0b011
        && finish_phase == 2 && finished_mask == 0b100
        && finish_attempts == 1 && finish_work > 0
        && finish_freezes >= FINISH_FREEZE_REQUIRED
        && finish_skips >= 2 && finish_errors == 0
        && survivor0 >= MIN_EPOCHS_PER_TASK
        && survivor1 >= MIN_EPOCHS_PER_TASK
        && survivor0.abs_diff(survivor1) <= 1
        && (0..TASK_COUNT).all(canary_ok);
    if ok {
        crate::serial::write_fmt(format_args!(
            "WOLFOS_APIC_FINISHED_OK task=2 mask=4 ready=3 finish=1 frozen_irqs={} skipped={} errors={} frozen_work={} survivor0={} survivor1={} never_rescheduled=1 fx_still_owned=1\n",
            finish_freezes, finish_skips, finish_errors, finish_work,
            survivor0, survivor1
        ));
        crate::serial::write_fmt(format_args!(
            "WOLFOS_APIC_BLOCK_WAKE_OK task=1 blocked_irqs={} frozen_samples={} skipped={} attempts={} wakes={} resumed={} errors={} frozen_work={} postwake0={} postwake1={} postwake2={} stack_resumed=1\n",
            block_irqs, freeze_checks, block_skips, block_attempts, wakes,
            resumed, block_errors, frozen_work, post0, post1, post2
        ));
        crate::serial::write_fmt(format_args!(
            "WOLFOS_APIC_FXSTATE_OK format=fxsave64 bytes=512 xmm0=3 fx_switches={} fx_observations={} work_checks={} corrupt={} original_restored=1 avx=0\n",
            fx_switches, fx_observations, fx_work_checks, fx_bad
        ));
        crate::serial::write_fmt(format_args!(
            "WOLFOS_APIC_PREEMPT_OK tasks=3 involuntary_switches={} task0_irqs={} task1_irqs={} task2_irqs={} work0={} work1={} work2={} exit_task={} rejected={} stack_kib=16 bsp_only=1 user_mode=0 deferred={} nested=1 guard_depth={} fairness_max_delta={}\n",
            switches, first, second, third, work0, work1, work2,
            exit_task, rejected, deferred, depth, post_max - post_min
        ));
    } else {
        crate::serial::write_fmt(format_args!(
            "WOLFOS_APIC_PREEMPT_ERROR switches={} task0_irqs={} task1_irqs={} task2_irqs={} work0={} work1={} work2={} exit_task={} rejected={} deferred={} nested_ok={} guard_depth={} fx_switches={} fx_observations={} fx_bad={} fx_work_checks={} xmm_ready={} interrupt_state_ok={} phase={} block_irqs={} frozen={} skipped={} wakes={} resumed={} block_errors={} postwake={}/{}/{} finish_phase={} finish_mask={} finish_freezes={} finish_skips={} finish_errors={} survivors={}/{}\n",
            switches, first, second, third, work0, work1, work2, exit_task, rejected,
            deferred, nested_ok, depth, fx_switches, fx_observations, fx_bad,
            fx_work_checks, xmm_ready, !unexpected_interrupt_state, block_phase,
            block_irqs, freeze_checks, block_skips, wakes, resumed, block_errors,
            post0, post1, post2, finish_phase, finished_mask, finish_freezes,
            finish_skips, finish_errors, survivor0, survivor1
        ));
    }
    // Keep the original finished/IRQ/SSE evidence tied to the *live*
    // pre-reclaim task state above. Only now, back in the disjoint BSP
    // context with IF=0, is it safe to wipe and prepare a reused slot.
    // The new generation is deliberately NOT added to RUNNABLE.
    let recycled = if ok { recycle_quiescent_task2() } else { None };
    if let Some(proof) = &recycled {
        crate::serial::write_fmt(format_args!(
            "WOLFOS_APIC_RECYCLE_OK task=2 old_gen={} new_gen={} scrubbed_kib=16 fx_bytes=512 fx_scrub={} fx_reseed={} prior_xmm0={:#x} stale={} early_denied={} grace_denied={} frame_valid={} runnable=0 bsp_only=1 executed_new_task=0\n",
            proof.old_generation, proof.new_generation,
            u8::from(proof.fx.fully_scrubbed),
            u8::from(proof.fx.baseline_reseeded),
            proof.fx.old_xmm0,
            u8::from(proof.stale_rejected),
            u8::from(proof.old_handle_refused_while_running),
            u8::from(proof.grace_refused),
            u8::from(proof.valid_new_frame)
        ));
    } else if ok {
        crate::serial::write_fmt(format_args!(
            "WOLFOS_APIC_RECYCLE_ERROR quiescence_or_generation_or_stack_invalid\n"
        ));
    }
    // The recycled frame was deliberately kept OFF the run queue while
    // wiping and validating it. Now execute it as a separate BSP-only
    // single-worker epoch and prove actual IRETQ entry, live timer IRQs,
    // SSE isolation, and a new Finished transition.
    let reuse_ok = recycled.as_ref()
        .is_some_and(prove_recycled_task_runs);
    ok && recycled.is_some() && reuse_ok
}
