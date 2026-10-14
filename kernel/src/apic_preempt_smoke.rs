//! QEMU-only BSP proof of *involuntary* kernel-to-kernel task handoff.
//!
//! Two private kernel stacks run CPU-bound tasks that NEVER yield to one
//! another. An actual periodic xAPIC interrupt stores the interrupted
//! 15-GPR + hardware trap-frame RSP and selects the other task's saved RSP.
//! Assembly pops the selected task's GPRs and IRETQs onto its stack.
//!
//! The task finishing the bounded proof voluntarily returns to the original
//! BSP test harness ONCE, with IF=0. This is not a production scheduler:
//! no arbitrary tasks, IRQ-safe locking, XSAVE/FPU state, CR3/TLS, ring 3,
//! migration, guard pages or AP-local interrupts. All work is BSP-owned.

use core::cell::UnsafeCell;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use x86_64::instructions::segmentation::{CS, SS, Segment};

use crate::{context_switch, kernel_trap_frame::{
    HardwareReturnFrame, KernelTrapFrame, SavedGprs, validate_kernel_resume
}, preempt_depth::PreemptDepth, fx_state, rr_policy};

const TASK_COUNT: usize = 3;
const STACK_BYTES: usize = 16 * 1024;
const STOP_AFTER: u64 = MIN_EPOCHS_PER_TASK * TASK_COUNT as u64;
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
struct PrivateStacks(UnsafeCell<[Stack; TASK_COUNT]>);
// SAFETY: only BSP runs; tasks own disjoint stacks. The interrupt handler
// observes saved frame addresses atomically but does not mutate live Rust
// data borrowed across an IRQ or context switch.
unsafe impl Sync for PrivateStacks {}
static STACKS: PrivateStacks =
    PrivateStacks(UnsafeCell::new([
        const { Stack([0; STACK_BYTES]) }; TASK_COUNT
    ]));

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
static FRAME_RSP: [AtomicUsize; TASK_COUNT] =
    [const { AtomicUsize::new(0) }; TASK_COUNT];
static WORK: [AtomicU64; TASK_COUNT] =
    [const { AtomicU64::new(0) }; TASK_COUNT];
static INTERRUPTED: [AtomicU64; TASK_COUNT] =
    [const { AtomicU64::new(0) }; TASK_COUNT];
static SWITCHES: AtomicU64 = AtomicU64::new(0);
static REJECTED: AtomicU64 = AtomicU64::new(0);
static EXIT_TASK: AtomicUsize = AtomicUsize::new(usize::MAX);
static CODE_SELECTOR: AtomicUsize = AtomicUsize::new(0);
static RUNNABLE: AtomicU64 = AtomicU64::new(0);
static PREEMPT_DEPTH: PreemptDepth = PreemptDepth::new();
static DEFERRED_IRQS: AtomicU64 = AtomicU64::new(0);
static NESTED_GUARD_OK: AtomicBool = AtomicBool::new(false);
static XMM_READY: [AtomicBool; TASK_COUNT] =
    [const { AtomicBool::new(false) }; TASK_COUNT];
static FX_SWITCHES: AtomicU64 = AtomicU64::new(0);
static FX_OBSERVATIONS: AtomicU64 = AtomicU64::new(0);
static FX_BAD: AtomicU64 = AtomicU64::new(0);
static FX_WORK_CHECKS: AtomicU64 = AtomicU64::new(0);

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

/// IRQ-time handoff decision. Only the BSP xAPIC timer handler can call it.
/// No allocations, logging, task changes inside Rust frame borrows, or
/// scheduler lock acquisition. The returned pointer is a *different live
/// private stack* only when both frames pass validation.
///
/// The assembly IRQ entry restores all GPRs and IRETQs using this pointer.
pub fn select_frame(frame_ptr: *const KernelTrapFrame) -> *const KernelTrapFrame {
    if !ACTIVE.load(Ordering::Relaxed) { return frame_ptr; }
    // The local APIC IRQ and its EOI still occur, but a held critical
    // section must NOT trigger a kernel stack switch, even when nested.
    if !PREEMPT_DEPTH.can_preempt() {
        DEFERRED_IRQS.fetch_add(1, Ordering::Relaxed);
        return frame_ptr;
    }
    let current = CURRENT.load(Ordering::Relaxed);
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
    for _ in 0..MAX_TASK_SPINS {
        let lane = unsafe { fx_state::read_test_xmm0() };
        FX_WORK_CHECKS.fetch_add(1, Ordering::Relaxed);
        if lane != TASK_XMM0[id] {
            FX_BAD.fetch_add(1, Ordering::Relaxed);
            break;
        }
        WORK[id].fetch_add(1, Ordering::Relaxed);
        if SWITCHES.load(Ordering::Relaxed) >= STOP_AFTER
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

/// BSP only; enter and leave with IRQs disabled. APIC timer hardware remains
/// mapped and programmed by the caller; APs are parked (IF=0).
pub fn verify() -> bool {
    if x86_64::instructions::interrupts::are_enabled()
        || STARTED.swap(true, Ordering::AcqRel) || !prepare()
    {
        return false;
    }
    CURRENT.store(0, Ordering::Relaxed);
    WORK[0].store(0, Ordering::Relaxed);
    WORK[1].store(0, Ordering::Relaxed);
    INTERRUPTED[0].store(0, Ordering::Relaxed);
    INTERRUPTED[1].store(0, Ordering::Relaxed);
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
    // From now on, ONLY APIC hardware interrupts transfer task0<->task1.
    unsafe { context_switch::switch_raw(BSP_RSP.0.get(), START_RSP.0.get()); }

    let unexpected_interrupt_state = x86_64::instructions::interrupts::are_enabled()
        || ACTIVE.load(Ordering::Acquire);
    // Restore even on failure; no task remains runnable after returning
    // from the one-time BSP exit switch.
    x86_64::instructions::interrupts::disable();
    let switches = SWITCHES.load(Ordering::Acquire);
    let first = INTERRUPTED[0].load(Ordering::Acquire);
    let second = INTERRUPTED[1].load(Ordering::Acquire);
    let work0 = WORK[0].load(Ordering::Acquire);
    let work1 = WORK[1].load(Ordering::Acquire);
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
    // SAFETY: no further private task or APIC handler uses FX state,
    // interrupts disabled. Recover the original BSP xstate and CR0/CR4.
    unsafe { fx_state::leave(original_fx); }
    let ok = !unexpected_interrupt_state && switches >= STOP_AFTER
        && first >= MIN_EPOCHS_PER_TASK && second >= MIN_EPOCHS_PER_TASK
        && first + second == switches
        && work0 > 0 && work1 > 0
        && rejected == 0 && exit_task < 2
        && deferred >= 4 && nested_ok && depth == 0
        && fx_switches == switches
        && fx_observations >= MIN_EPOCHS_PER_TASK * 2 - 1
        && fx_work_checks > 0 && xmm_ready && fx_bad == 0
        && canary_ok(0) && canary_ok(1);
    if ok {
        crate::serial::write_fmt(format_args!(
            "WOLFOS_APIC_FXSTATE_OK format=fxsave64 bytes=512 xmm0=2 fx_switches={} fx_observations={} work_checks={} corrupt={} original_restored=1 avx=0\n",
            fx_switches, fx_observations, fx_work_checks, fx_bad
        ));
        crate::serial::write_fmt(format_args!(
            "WOLFOS_APIC_PREEMPT_OK tasks=2 involuntary_switches={} task0_irqs={} task1_irqs={} work0={} work1={} exit_task={} rejected={} stack_kib=16 bsp_only=1 user_mode=0 deferred={} nested=1 guard_depth={}\n",
            switches, first, second, work0, work1, exit_task, rejected,
            deferred, depth
        ));
    } else {
        crate::serial::write_fmt(format_args!(
            "WOLFOS_APIC_PREEMPT_ERROR switches={} task0_irqs={} task1_irqs={} work0={} work1={} exit_task={} rejected={} deferred={} nested_ok={} guard_depth={} fx_switches={} fx_observations={} fx_bad={} fx_work_checks={} xmm_ready={} interrupt_state_ok={}\n",
            switches, first, second, work0, work1, exit_task, rejected,
            deferred, nested_ok, depth, fx_switches, fx_observations, fx_bad,
            fx_work_checks, xmm_ready, !unexpected_interrupt_state
        ));
    }
    ok
}
