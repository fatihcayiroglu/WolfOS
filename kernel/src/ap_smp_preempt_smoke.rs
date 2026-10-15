//! Isolated 4-vCPU QEMU proof: every secondary CPU involuntarily switches
//! between TWO independently stacked kernel tasks on its OWN local xAPIC
//! timer IRQ. No task-to-task yield occurs; the only worker->coordinator
//! transition is once at shutdown, with local IF=0.
//!
//! AP-private stacks, saved trap frames, FX state, timer and counters never
//! cross AP ownership boundaries. The BSP is a read-only verifier. This is
//! NOT a general SMP scheduler: no migration, ring 3, page reclamation,
//! locks, production timekeeping, x2APIC or XSAVE/AVX state support.
//! The legacy x87/SSE baseline is preserved by per-AP FXSAVE64 images.

use core::arch::{asm, x86_64::__cpuid};
use core::cell::UnsafeCell;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use limine::mp::MpInfo;
use x86_64::instructions::segmentation::{CS, SS, Segment};

use crate::{
    ap_ipi_smoke, context_switch, preempt_depth::PreemptDepth, kernel_trap_frame::{
        HardwareReturnFrame, KernelTrapFrame, SavedGprs, validate_kernel_resume,
    }, lapic_irq_layout, lapic_timer_layout, lapic_timer_plan, serial,
};

pub const VECTOR: u8 = 0xe3;
const CPU_SLOTS: usize = 4; // the isolated QEMU test *requires* -smp 4
const TASKS: usize = 2;
const STACK_BYTES: usize = 16 * 1024;
const MIN_SWITCHES: u64 = 10;
const MIN_INTERRUPTS_PER_TASK: u64 = 5;
const MIN_DEFERRED_PER_AP: u64 = 4;
const COUNT: u32 = 262_144;
const DIVISOR: u32 = 16;
const MAX_SPINS: u64 = 50_000_000;
const BSP_WAIT_SPINS: usize = 200_000_000;
const CANARY: u64 = 0x4150_5052_454d_5054;
const FX_BYTES: usize = 512;
const XMM0_OFFSET: usize = 160;
const XMM_TAGS: [u64; TASKS] = [
    0x11ee_3300_aa55_6677, 0x22ff_4400_bb66_7788,
];
const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR0_TS: u64 = 1 << 3;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;

#[repr(align(16))]
#[derive(Clone, Copy)]
struct Stack([u8; STACK_BYTES]);
struct Stacks(UnsafeCell<[[Stack; TASKS]; CPU_SLOTS]>);
// SAFETY: every AP owns a unique MP directory index. Its worker tasks
// execute only on that AP, and their live stacks never overlap another CPU.
unsafe impl Sync for Stacks {}
static STACKS: Stacks = Stacks(UnsafeCell::new(
    [[const { Stack([0; STACK_BYTES]) }; TASKS]; CPU_SLOTS]
));

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct FxImage([u8; FX_BYTES]);
struct FxBanks(UnsafeCell<[[FxImage; TASKS + 1]; CPU_SLOTS]>);
// SAFETY: index 0 (original AP state), 1 and 2 (worker states) are only
// accessed from the owning AP. IRQ gate IF=0 serializes the worker/handler.
unsafe impl Sync for FxBanks {}
static FX: FxBanks = FxBanks(UnsafeCell::new(
    [[const { FxImage([0; FX_BYTES]) }; TASKS + 1]; CPU_SLOTS]
));

#[derive(Clone, Copy)]
struct CpuControls {
    cr0: u64,
    cr4: u64,
    previous_divisor: u32,
}
struct OwnerCells(UnsafeCell<[CpuControls; CPU_SLOTS]>);
unsafe impl Sync for OwnerCells {}
static CONTROLS: OwnerCells = OwnerCells(UnsafeCell::new(
    [CpuControls { cr0: 0, cr4: 0, previous_divisor: 0 }; CPU_SLOTS]
));

/// Three non-aliasing raw RSP slots: coordinator's suspended Rust context,
/// first task's synthetic switch frame, and worker's one-time exit frame.
struct StackSlots(UnsafeCell<[[usize; 3]; CPU_SLOTS]>);
unsafe impl Sync for StackSlots {}
static RSP: StackSlots = StackSlots(UnsafeCell::new([[0; 3]; CPU_SLOTS]));

struct CpuProof {
    active: AtomicBool,
    done: AtomicBool,
    failed: AtomicBool,
    current: AtomicUsize,
    saved: [AtomicUsize; TASKS],
    work: [AtomicU64; TASKS],
    interrupted: [AtomicU64; TASKS],
    ticks: AtomicU64,
    eois: AtomicU64,
    switches: AtomicU64,
    invalid: AtomicU64,
    xmm_bad: AtomicU64,
    deferred: AtomicU64,
    nested_ok: AtomicBool,
    exited_by: AtomicUsize,
}
impl CpuProof {
    const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
            done: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            current: AtomicUsize::new(0),
            saved: [const { AtomicUsize::new(0) }; TASKS],
            work: [const { AtomicU64::new(0) }; TASKS],
            interrupted: [const { AtomicU64::new(0) }; TASKS],
            ticks: AtomicU64::new(0),
            eois: AtomicU64::new(0),
            switches: AtomicU64::new(0),
            invalid: AtomicU64::new(0),
            xmm_bad: AtomicU64::new(0),
            deferred: AtomicU64::new(0),
            nested_ok: AtomicBool::new(false),
            exited_by: AtomicUsize::new(usize::MAX),
        }
    }
}
static CORES: [CpuProof; CPU_SLOTS] = [const { CpuProof::new() }; CPU_SLOTS];
static UNROUTED: AtomicU64 = AtomicU64::new(0);
// Each AP's depth is owned exclusively by that processor and its timer IRQ.
// Other APs and the BSP cannot mutate another core's scheduler guard.
static GATES: [PreemptDepth; CPU_SLOTS] =
    [const { PreemptDepth::new() }; CPU_SLOTS];

fn bottom(cpu: usize, task: usize) -> usize {
    // SAFETY: caller has checked cpu < 4 and task < 2; raw address only.
    let raw = unsafe { core::ptr::addr_of_mut!((*STACKS.0.get())[cpu][task]) };
    raw.cast::<u8>() as usize
}
fn top(cpu: usize, task: usize) -> usize { bottom(cpu, task) + STACK_BYTES }

unsafe fn save_fx(image: *mut FxImage) {
    // SAFETY: caller guarantees CPUID FXSR, CR0/CR4 enabled, valid aligned
    // 512 bytes, same AP and no concurrent owner.
    unsafe { asm!("fxsave64 [{}]", in(reg) image, options(nostack)); }
}
unsafe fn restore_fx(image: *const FxImage) {
    unsafe { asm!("fxrstor64 [{}]", in(reg) image, options(nostack)); }
}
fn saved_xmm0(image: *const FxImage) -> u64 {
    // SAFETY: the FXSAVE image is initialized and aligned, low 64 bits
    // of XMM0 are at offset 160 in the FX64 image.
    unsafe { image.cast::<u8>().add(XMM0_OFFSET).cast::<u64>().read_unaligned() }
}
fn fx_enter(cpu: usize) -> bool {
    let f = __cpuid(1);
    let required = (1 << 24) | (1 << 25) | (1 << 26);
    if f.edx & required != required { return false; }
    let cr0: u64;
    let cr4: u64;
    // SAFETY: this AP alone modifies its own CR0/CR4 with IF=0. Only its
    // private image is touched; all task images are initialized by copying
    // a real, valid architectural save image.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        asm!("mov cr0, {}", in(reg) ((cr0 | CR0_MP) & !(CR0_EM | CR0_TS)), options(nostack));
        asm!("mov cr4, {}", in(reg) (cr4 | CR4_OSFXSR | CR4_OSXMMEXCPT), options(nostack));
        let bank = (*FX.0.get())[cpu].as_mut_ptr();
        save_fx(bank);
        core::ptr::copy_nonoverlapping(bank, bank.add(1), 1);
        core::ptr::copy_nonoverlapping(bank, bank.add(2), 1);
        (*CONTROLS.0.get())[cpu].cr0 = cr0;
        (*CONTROLS.0.get())[cpu].cr4 = cr4;
    }
    true
}
fn fx_leave(cpu: usize) {
    // SAFETY: the per-AP timer is stopped, IF=0; no worker remains active.
    // Restore the exact original AP legacy FX image and control registers.
    unsafe {
        let bank = (*FX.0.get())[cpu].as_ptr();
        restore_fx(bank);
        asm!("mov cr4, {}", in(reg) (*CONTROLS.0.get())[cpu].cr4, options(nostack));
        asm!("mov cr0, {}", in(reg) (*CONTROLS.0.get())[cpu].cr0, options(nostack));
    }
}

fn prepare(cpu: usize) -> bool {
    let cs = CS::get_reg().0;
    let ss = SS::get_reg().0;
    if cs == 0 || cs & 3 != 0 || ss == 0 || ss & 3 != 0 { return false; }
    let proof = &CORES[cpu];
    for task in 0..TASKS {
        let base = bottom(cpu, task);
        let end = top(cpu, task);
        if base & 15 != 0 || end & 15 != 0 { return false; }
        unsafe { (base as *mut u64).write_volatile(CANARY ^ (cpu as u64) ^ task as u64); }
        if task == 0 {
            // Six callee-saved GPRs + entry PC + dummy return address.
            let sp = end - 8 * size_of::<usize>();
            unsafe {
                core::ptr::write_bytes(sp as *mut u8, 0, 64);
                (sp as *mut usize).add(6).write(task0 as usize);
                (*RSP.0.get())[cpu][1] = sp;
            }
        } else {
            let sp = end - 8 - 64 - size_of::<KernelTrapFrame>();
            let frame = KernelTrapFrame {
                registers: SavedGprs::default(),
                hardware: HardwareReturnFrame {
                    rip: task1 as usize as u64,
                    cs: u64::from(cs),
                    rflags: 0x202,
                    rsp: (end - 8) as u64,
                    ss: u64::from(ss),
                },
            };
            let checked = unsafe {
                (sp as *mut KernelTrapFrame).write(frame);
                validate_kernel_resume(
                    sp as u64, base as u64, end as u64, cs,
                    &*(sp as *const KernelTrapFrame),
                ).is_ok()
            };
            if !checked { return false; }
            proof.saved[1].store(sp, Ordering::Relaxed);
        }
    }
    proof.saved[0].store(0, Ordering::Relaxed);
    proof.work[0].store(0, Ordering::Relaxed);
    proof.work[1].store(0, Ordering::Relaxed);
    proof.interrupted[0].store(0, Ordering::Relaxed);
    proof.interrupted[1].store(0, Ordering::Relaxed);
    proof.ticks.store(0, Ordering::Relaxed);
    proof.eois.store(0, Ordering::Relaxed);
    proof.switches.store(0, Ordering::Relaxed);
    proof.invalid.store(0, Ordering::Relaxed);
    proof.xmm_bad.store(0, Ordering::Relaxed);
    proof.deferred.store(0, Ordering::Relaxed);
    proof.nested_ok.store(false, Ordering::Relaxed);
    proof.exited_by.store(usize::MAX, Ordering::Relaxed);
    proof.current.store(0, Ordering::Relaxed);
    proof.active.store(false, Ordering::Relaxed);
    proof.done.store(false, Ordering::Relaxed);
    proof.failed.store(false, Ordering::Relaxed);
    true
}

fn select(cpu: usize, frame_ptr: *const KernelTrapFrame) -> *const KernelTrapFrame {
    let proof = &CORES[cpu];
    if !proof.active.load(Ordering::Relaxed) { return frame_ptr; }
    // An active critical section blocks ONLY stack handoff. This same local
    // IRQ still enters the assembly gate, gets EOI and restores the current
    // frame. Other CPUs' guards do not affect this CPU's preemption.
    if !GATES[cpu].can_preempt() {
        proof.deferred.fetch_add(1, Ordering::Relaxed);
        return frame_ptr;
    }
    let current = proof.current.load(Ordering::Relaxed);
    if current >= TASKS {
        proof.invalid.fetch_add(1, Ordering::Relaxed);
        return frame_ptr;
    }
    let next = 1 - current;
    let old_sp = frame_ptr as usize;
    let next_sp = proof.saved[next].load(Ordering::Relaxed);
    let old_end = old_sp.checked_add(size_of::<KernelTrapFrame>());
    let next_end = next_sp.checked_add(size_of::<KernelTrapFrame>());
    if old_sp < bottom(cpu, current) + 512
        || old_end.is_none_or(|end| end > top(cpu, current))
        || next_sp < bottom(cpu, next) + 512
        || next_end.is_none_or(|end| end > top(cpu, next))
    {
        proof.invalid.fetch_add(1, Ordering::Relaxed);
        return frame_ptr;
    }
    let cs = CS::get_reg().0;
    // SAFETY: both verified private stack ranges belong exclusively to
    // THIS AP and distinct tasks. The next frame is suspended, immutable
    // until its actual IRETQ activation. The old frame is live right now.
    let valid = unsafe {
        validate_kernel_resume(
            old_sp as u64, bottom(cpu,current) as u64,
            top(cpu,current) as u64, cs, &*frame_ptr
        ).is_ok() && validate_kernel_resume(
            next_sp as u64, bottom(cpu,next) as u64,
            top(cpu,next) as u64, cs,
            &*(next_sp as *const KernelTrapFrame)
        ).is_ok()
    };
    if !valid {
        proof.invalid.fetch_add(1, Ordering::Relaxed);
        return frame_ptr;
    }
    // The active worker's legacy FX must be saved BEFORE restoring the
    // destination's FX image and returning its all-GPR trap pointer.
    // Caller is at CPL0 IRQ gate IF=0. This check detects state leakage.
    unsafe {
        let bank = (*FX.0.get())[cpu].as_mut_ptr();
        let source = bank.add(current + 1);
        save_fx(source);
        if saved_xmm0(source) != XMM_TAGS[current] {
            proof.xmm_bad.fetch_add(1, Ordering::Relaxed);
        }
        restore_fx(bank.add(next + 1));
    }
    proof.saved[current].store(old_sp, Ordering::Relaxed);
    proof.interrupted[current].fetch_add(1, Ordering::Relaxed);
    proof.current.store(next, Ordering::Relaxed);
    proof.switches.fetch_add(1, Ordering::Relaxed);
    next_sp as *const KernelTrapFrame
}

/// Called by the independent AP assembly entry after it saved 15 GPRs and
/// aligned its temporary SysV callback stack. A return to a different
/// private AP task frame causes a REAL involuntary kernel task switch.
#[unsafe(no_mangle)]
pub extern "C" fn wolfos_ap_preempt_irq_dispatch(
    frame: *const KernelTrapFrame,
) -> *const KernelTrapFrame {
    let cpu = ap_ipi_smoke::ap_slot(ap_ipi_smoke::local_id());
    let selected = if let Some(i) = cpu {
        if i < CPU_SLOTS {
            let proof = &CORES[i];
            proof.ticks.fetch_add(1, Ordering::Relaxed);
            select(i, frame)
        } else {
            UNROUTED.fetch_add(1, Ordering::Relaxed);
            frame
        }
    } else {
        UNROUTED.fetch_add(1, Ordering::Relaxed);
        frame
    };
    // CPU-local xAPIC EOI exactly once regardless of frame acceptance.
    unsafe { ap_ipi_smoke::write(lapic_irq_layout::EOI_OFFSET, 0); }
    if let Some(i) = cpu {
        if i < CPU_SLOTS {
            CORES[i].eois.fetch_add(1, Ordering::Release);
        }
    }
    selected
}

fn stop_timer() -> bool {
    let lvt = unsafe { ap_ipi_smoke::read(lapic_timer_layout::LVT_TIMER_OFFSET) };
    // SAFETY: only current AP, IF=0; mask first and disable countdown second.
    unsafe {
        ap_ipi_smoke::write(
            lapic_timer_layout::LVT_TIMER_OFFSET, lvt | lapic_timer_layout::LVT_MASKED
        );
        ap_ipi_smoke::write(lapic_timer_layout::INITIAL_COUNT_OFFSET, 0);
    }
    unsafe {
        ap_ipi_smoke::read(lapic_timer_layout::INITIAL_COUNT_OFFSET) == 0
            && ap_ipi_smoke::read(lapic_timer_layout::LVT_TIMER_OFFSET)
                & lapic_timer_layout::LVT_MASKED != 0
    }
}

/// Task0 owns two nested preemption-disabled critical sections. Real
/// local timer interrupts and local EOIs must keep flowing, but task1 must
/// not execute until BOTH nested sections have exited. The inner release
/// must NOT re-enable preemption. No CLI or voluntary task switch here.
fn prove_nested_irq_deferral(cpu: usize) -> bool {
    let proof = &CORES[cpu];
    if GATES[cpu].depth() != 2
        || proof.switches.load(Ordering::Acquire) != 0
        || proof.work[1].load(Ordering::Acquire) != 0 { return false; }

    for phase in 0..2 {
        let target = (phase as u64 + 1) * 2;
        let mut arrived = false;
        for _ in 0..MAX_SPINS {
            proof.work[0].fetch_add(1, Ordering::Relaxed);
            if proof.deferred.load(Ordering::Acquire) >= target {
                arrived = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !arrived || proof.switches.load(Ordering::Acquire) != 0
            || proof.work[1].load(Ordering::Acquire) != 0
            || GATES[cpu].depth() != (2 - phase)
        { return false; }
        if GATES[cpu].enable() != Ok(1 - phase) { return false; }
        // After the first release, the outermost guard must still prevent
        // any task switch despite additional hardware IRQs.
    }
    GATES[cpu].can_preempt() && GATES[cpu].depth() == 0
        && proof.deferred.load(Ordering::Acquire) >= MIN_DEFERRED_PER_AP
        && proof.switches.load(Ordering::Acquire) == 0
        && proof.work[1].load(Ordering::Acquire) == 0
}

#[inline(never)]
fn run_task(task: usize) -> ! {
    let Some(cpu) = ap_ipi_smoke::ap_slot(ap_ipi_smoke::local_id())
    else { crate::halt_forever(); };
    if cpu >= CPU_SLOTS { crate::halt_forever(); }
    // The task owns this AP's current x87/SSE state and installs a
    // distinctive XMM0 low lane. Every hardware context switch checks
    // its FXSAVE image and restores the other task's independent image.
    unsafe {
        asm!("movq xmm0, {}", in(reg) XMM_TAGS[task], options(nostack, preserves_flags));
    }
    x86_64::instructions::interrupts::enable();
    let proof = &CORES[cpu];
    // Task1 must not enter until task0 has observed two truly nested
    // critical sections with four real timer interrupts but zero switches.
    let nested = task != 0 || prove_nested_irq_deferral(cpu);
    if task == 0 {
        proof.nested_ok.store(nested, Ordering::Release);
    }
    let mut success = false;
    if nested {
    for _ in 0..MAX_SPINS {
        proof.work[task].fetch_add(1, Ordering::Relaxed);
        if proof.switches.load(Ordering::Relaxed) >= MIN_SWITCHES
            && proof.interrupted[0].load(Ordering::Relaxed) >= MIN_INTERRUPTS_PER_TASK
            && proof.interrupted[1].load(Ordering::Relaxed) >= MIN_INTERRUPTS_PER_TASK
            && proof.work[0].load(Ordering::Relaxed) != 0
            && proof.work[1].load(Ordering::Relaxed) != 0
        {
            success = true;
            break;
        }
        core::hint::spin_loop();
    }
    }
    x86_64::instructions::interrupts::disable();
    proof.active.store(false, Ordering::Relaxed);
    let stopped = stop_timer();
    proof.failed.store(!success || !stopped, Ordering::Release);
    proof.exited_by.store(task, Ordering::Release);
    // One-time WORKER->original AP coordinator return with IF=0. The
    // other task remains suspended on its private stack and no timer IRQ
    // can select it once active=false and the hardware LVT is masked.
    unsafe {
        let cells = (*RSP.0.get())[cpu].as_mut_ptr();
        context_switch::switch_raw(cells.add(2), cells);
    }
    crate::halt_forever()
}
extern "C" fn task0() -> ! { run_task(0) }
extern "C" fn task1() -> ! { run_task(1) }

/// Called by one AP after its original per-CPU GDT/TSS, IDT and all the
/// earlier cooperative SMP tasks have been verified. Enters with IF=0.
pub fn secondary_run(cpu: usize) -> bool {
    if cpu >= CPU_SLOTS
        || x86_64::instructions::interrupts::are_enabled()
        || ap_ipi_smoke::ap_slot(ap_ipi_smoke::local_id()) != Some(cpu)
        || !prepare(cpu)
    {
        return false;
    }
    let Ok(plan) = lapic_timer_plan::periodic_timer_plan(VECTOR, DIVISOR, COUNT)
    else { return false; };
    if !fx_enter(cpu) { return false; }
    // Two AP-owned nested guards start before the first worker is entered.
    // IF remains off here; task0 turns IF on and proves deferred IRQs.
    if GATES[cpu].disable() != Ok(1) || GATES[cpu].disable() != Ok(2) {
        fx_leave(cpu);
        return false;
    }
    // The caller has masked the original AP local timer and enabled its
    // SVR. Timer programming remains THIS AP's responsibility.
    unsafe {
        (*CONTROLS.0.get())[cpu].previous_divisor =
            ap_ipi_smoke::read(lapic_timer_layout::DIVIDE_CONFIG_OFFSET);
    }
    for reg in plan.preparation {
        unsafe { ap_ipi_smoke::write(reg.offset, reg.value); }
    }
    unsafe { ap_ipi_smoke::write(plan.activation.offset, plan.activation.value); }
    CORES[cpu].active.store(true, Ordering::Release);
    // The coordinator's C/Rust call frame is suspended here, not
    // selected by any hardware timer interrupt. Only the two worker task
    // stacks alternate on real local APIC hardware IRQs.
    unsafe {
        let cells = (*RSP.0.get())[cpu].as_mut_ptr();
        context_switch::switch_raw(cells, cells.add(1));
    }
    x86_64::instructions::interrupts::disable();
    let proof = &CORES[cpu];
    let stopped = stop_timer();
    unsafe {
        ap_ipi_smoke::write(
            lapic_timer_layout::DIVIDE_CONFIG_OFFSET,
            (*CONTROLS.0.get())[cpu].previous_divisor,
        );
    }
    fx_leave(cpu);
    let switches = proof.switches.load(Ordering::Acquire);
    let a = proof.interrupted[0].load(Ordering::Acquire);
    let b = proof.interrupted[1].load(Ordering::Acquire);
    let ticks = proof.ticks.load(Ordering::Acquire);
    let eois = proof.eois.load(Ordering::Acquire);
    let ok = stopped && !proof.active.load(Ordering::Acquire)
        && !proof.failed.load(Ordering::Acquire)
        && proof.exited_by.load(Ordering::Acquire) < TASKS
        && switches >= MIN_SWITCHES
        && a >= MIN_INTERRUPTS_PER_TASK && b >= MIN_INTERRUPTS_PER_TASK
        && a + b == switches
        && ticks == eois && ticks >= switches
        && proof.invalid.load(Ordering::Acquire) == 0
        && proof.xmm_bad.load(Ordering::Acquire) == 0
        && proof.nested_ok.load(Ordering::Acquire)
        && proof.deferred.load(Ordering::Acquire) >= MIN_DEFERRED_PER_AP
        && GATES[cpu].depth() == 0
        && ticks >= switches + proof.deferred.load(Ordering::Acquire)
        && (0..TASKS).all(|task| {
            proof.work[task].load(Ordering::Acquire) > 0
                && unsafe {
                    (bottom(cpu,task) as *const u64).read_volatile()
                        == CANARY ^ (cpu as u64) ^ task as u64
                }
        });
    proof.failed.store(!ok, Ordering::Release);
    proof.done.store(true, Ordering::Release);
    ok
}

fn wait_all(cpus: &[&MpInfo], bsp: u32) -> bool {
    for _ in 0..BSP_WAIT_SPINS {
        if cpus.iter().enumerate().all(|(i,c)| c.lapic_id == bsp
            || (i < CPU_SLOTS && CORES[i].done.load(Ordering::Acquire)
                && ap_ipi_smoke::is_offline(i)))
        { return true; }
        core::hint::spin_loop();
    }
    false
}

/// BSP stays IF=0 and never modifies AP task stacks, registers or APIC.
/// Its only role is to verify all three independently completed AP proofs.
pub fn verify_bsp(bsp: u32, cpus: &[&MpInfo]) -> bool {
    if x86_64::instructions::interrupts::are_enabled()
        || cpus.len() != CPU_SLOTS
        || cpus.iter().filter(|c| c.lapic_id == bsp).count() != 1
        || !wait_all(cpus, bsp)
    {
        serial::write_line("WOLFOS_AP_SMP_PREEMPT_ERROR ap_not_finished");
        return false;
    }
    let (mut irq, mut eoi, mut switched, mut a, mut b, mut work, mut offline,
         mut deferred, mut nested_aps) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64, 0usize, 0u64, 0usize);
    let mut good = true;
    for (cpu, info) in cpus.iter().enumerate() {
        if info.lapic_id == bsp { continue; }
        let p = &CORES[cpu];
        let xa = p.interrupted[0].load(Ordering::Acquire);
        let xb = p.interrupted[1].load(Ordering::Acquire);
        let sw = p.switches.load(Ordering::Acquire);
        let it = p.ticks.load(Ordering::Acquire);
        let et = p.eois.load(Ordering::Acquire);
        if p.failed.load(Ordering::Acquire)
            || p.active.load(Ordering::Acquire)
            || !p.done.load(Ordering::Acquire)
            || !ap_ipi_smoke::is_offline(cpu)
            || sw < MIN_SWITCHES
            || xa < MIN_INTERRUPTS_PER_TASK
            || xb < MIN_INTERRUPTS_PER_TASK
            || xa + xb != sw || et != it
            || p.invalid.load(Ordering::Acquire) != 0
            || p.xmm_bad.load(Ordering::Acquire) != 0
            || !p.nested_ok.load(Ordering::Acquire)
            || p.deferred.load(Ordering::Acquire) < MIN_DEFERRED_PER_AP
            || GATES[cpu].depth() != 0
            || it < sw + p.deferred.load(Ordering::Acquire)
        { good = false; }
        irq += it;
        eoi += et;
        switched += sw;
        a += xa;
        b += xb;
        work += p.work[0].load(Ordering::Acquire)
            + p.work[1].load(Ordering::Acquire);
        offline += usize::from(ap_ipi_smoke::is_offline(cpu));
        deferred += p.deferred.load(Ordering::Acquire);
        nested_aps += usize::from(p.nested_ok.load(Ordering::Acquire));
    }
    let spurious = ap_ipi_smoke::spurious_count();
    let wrong_ipi = ap_ipi_smoke::ipi_count();
    let misrouted = UNROUTED.load(Ordering::Acquire);
    if good && switched >= 30 && a >= 15 && b >= 15
        && irq == eoi && irq >= switched
        && work > 0 && offline == 3
        && deferred >= 12 && nested_aps == 3
        && irq >= switched + deferred
        && spurious == 0 && wrong_ipi == 0 && misrouted == 0
    {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_SMP_PREEMPT_OK cpus=4 aps=3 tasks_per_ap=2 switches={} task0_irqs={} task1_irqs={} ticks={} eois={} work={} invalid=0 xmm_bad=0 spurious=0 wrong_ipi=0 offline={} bsp_if=0 migrated=0 deferred={} nested_aps={} guard_depth=0\n",
            switched, a, b, irq, eoi, work, offline, deferred, nested_aps
        ));
        true
    } else {
        // Fail-closed hardware diagnostics: no conditions are relaxed.
        // Every AP is parked before BSP reads these counters.
        for (cpu, info) in cpus.iter().enumerate() {
            if info.lapic_id == bsp { continue; }
            let p = &CORES[cpu];
            serial::write_fmt(format_args!(
                "WOLFOS_AP_SMP_PREEMPT_DIAG cpu={} failed={} active={} done={} offline={} current={} exit={} switches={} task0_irqs={} task1_irqs={} ticks={} eois={} deferred={} nested={} guard_depth={} invalid={} xmm_bad={} work0={} work1={} canary0={} canary1={}\n",
                cpu, p.failed.load(Ordering::Acquire),
                p.active.load(Ordering::Acquire), p.done.load(Ordering::Acquire),
                ap_ipi_smoke::is_offline(cpu), p.current.load(Ordering::Acquire),
                p.exited_by.load(Ordering::Acquire),
                p.switches.load(Ordering::Acquire),
                p.interrupted[0].load(Ordering::Acquire),
                p.interrupted[1].load(Ordering::Acquire),
                p.ticks.load(Ordering::Acquire),
                p.eois.load(Ordering::Acquire),
                p.deferred.load(Ordering::Acquire),
                p.nested_ok.load(Ordering::Acquire), GATES[cpu].depth(),
                p.invalid.load(Ordering::Acquire), p.xmm_bad.load(Ordering::Acquire),
                p.work[0].load(Ordering::Acquire), p.work[1].load(Ordering::Acquire),
                unsafe { (bottom(cpu, 0) as *const u64).read_volatile() == CANARY ^ cpu as u64 },
                unsafe { (bottom(cpu, 1) as *const u64).read_volatile() == CANARY ^ cpu as u64 ^ 1 },
            ));
        }
        serial::write_fmt(format_args!(
            "WOLFOS_AP_SMP_PREEMPT_ERROR switches={} task0_irqs={} task1_irqs={} ticks={} eois={} work={} offline={} good={} spurious={} wrong_ipi={} unrouted={} deferred={} nested_aps={}\n",
            switched, a, b, irq, eoi, work, offline, good,
            spurious, wrong_ipi, misrouted, deferred, nested_aps
        ));
        false
    }
}
