//! QEMU-only hardware-timer PREEMPTED kernel frame migrated between APs.
//!
//! One original 16 KiB kernel stack and its actual interrupt-saved 15-GPR
//! frame resume on three separate CPUs. The task never yields. Each AP's
//! LOCAL xAPIC timer involuntarily captures its frame, saves its x87/SSE,
//! stops its own timer, locally EOIs, and IRETQs to a separate per-AP escape
//! stack. The escape trampoline returns the SOURCE AP to its coordinator
//! RSP. Only after that coordinator publishes Completed can BSP transfer
//! the paused ownership lease and send a directed IPI to the destination.
//! Destination restores FXSAVE64 and IRETQs into the captured live frame.
//!
//! Proof boundary: CPL0, common static kernel CR3 and code/data selectors,
//! no other IRQs while task runs; fixed task and escape stacks live forever.
//! No XSAVE/AVX upper lanes, usermode, FS/GS/TLS, dynamic scheduler queues,
//! true production stop-the-world or real physical hardware validation.

use core::arch::{asm, x86_64::__cpuid};
use core::cell::UnsafeCell;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use limine::mp::MpInfo;
use x86_64::instructions::segmentation::{CS, SS, Segment};

use crate::{
    ap_ipi_smoke, ap_irq_migrate_entry, context_switch,
    kernel_trap_frame::{HardwareReturnFrame, KernelTrapFrame, SavedGprs, validate_kernel_resume},
    lapic_irq_layout, lapic_timer_layout, lapic_timer_plan,
    migrating_stack_contract::{self, STACK_BYTES}, remote_runqueue::RemoteMailbox,
    serial, task_handoff::{advance_digest, HandoffError, TaskLease, INITIAL_DIGEST},
};

pub const TIMER_VECTOR: u8 = 0xe4;
const CORES: usize = 4;
const QUANTA: u64 = 12;
const PER_AP: u64 = 4;
const COUNT: u32 = 262_144;
const DIVISOR: u32 = 16;
const WAIT_SPINS: usize = 200_000_000;
const CANARY: u64 = 0x4952_515f_4d49_4752;
const LOCAL_COOKIE: u64 = 0x4350_555f_4c4f_434b;
const XMM_TAG: u64 = 0xabcd_4455_66ef_7788;
const XMM0_OFFSET: usize = 160;
const ESCAPE_BYTES: usize = 8192;
const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR0_TS: u64 = 1 << 3;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;

#[repr(align(16))]
struct Stack<const N: usize>([u8; N]);
struct TaskStack(UnsafeCell<Stack<STACK_BYTES>>);
// SAFETY: shared task stack has exactly one executing CPU at a time,
// serialized by the checked TaskLease and mailbox completion protocol.
// It is NEVER deallocated and is mapped at the same VA on every AP.
unsafe impl Sync for TaskStack {}
static TASK_STACK: TaskStack =
    TaskStack(UnsafeCell::new(Stack([0; STACK_BYTES])));
struct EscapeStacks(UnsafeCell<[Stack<ESCAPE_BYTES>; CORES]>);
// SAFETY: per-CPU escape stacks have disjoint unique MP directory indices.
unsafe impl Sync for EscapeStacks {}
static ESCAPE: EscapeStacks =
    EscapeStacks(UnsafeCell::new([const { Stack([0; ESCAPE_BYTES]) }; CORES]));
struct OwnedSlots(UnsafeCell<([usize; CORES], [usize; CORES], usize)>);
// SAFETY: coordinator and escape RSP indexed slots are only written by their
// AP; initial task RSP is BSP initialized before dispatch. Trapped task
// frame is published separately via AtomicUsize after a completed IRQ.
unsafe impl Sync for OwnedSlots {}
static RSP: OwnedSlots = OwnedSlots(UnsafeCell::new(([0; CORES], [0; CORES], 0)));
static CAPTURED: AtomicUsize = AtomicUsize::new(0);

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct FxImage([u8; 512]);
struct FxBank(UnsafeCell<(FxImage, [FxImage; CORES])>);
// SAFETY: the task bank is used only by the current owner, prior owner
// returns to its own coordinator before the next AP may restore task FX.
unsafe impl Sync for FxBank {}
static FX: FxBank = FxBank(UnsafeCell::new((
    FxImage([0; 512]), [const { FxImage([0; 512]) }; CORES],
)));
static FX_READY: AtomicBool = AtomicBool::new(false);
struct ControlBank(UnsafeCell<[(u64, u64, u32); CORES]>);
unsafe impl Sync for ControlBank {}
static CONTROLS: ControlBank =
    ControlBank(UnsafeCell::new([(0, 0, 0); CORES]));

static LEASE: TaskLease = TaskLease::new();
static MAIL: [RemoteMailbox; CORES] = [
    RemoteMailbox::new(0), RemoteMailbox::new(1),
    RemoteMailbox::new(2), RemoteMailbox::new(3),
];
static READY: [AtomicBool; CORES] = [const { AtomicBool::new(false) }; CORES];
static CLAIMS: [AtomicU64; CORES] = [const { AtomicU64::new(0) }; CORES];
static DONE: [AtomicU64; CORES] = [const { AtomicU64::new(0) }; CORES];
static ACTIVE: [AtomicBool; CORES] = [const { AtomicBool::new(false) }; CORES];
static EPOCH: [AtomicU64; CORES] = [const { AtomicU64::new(0) }; CORES];
static WORK: [AtomicU64; CORES] = [const { AtomicU64::new(0) }; CORES];
static LAST_WORK: [AtomicU64; CORES] = [const { AtomicU64::new(0) }; CORES];
static TIMER_IRQS: [AtomicU64; CORES] = [const { AtomicU64::new(0) }; CORES];
static TIMER_EOIS: [AtomicU64; CORES] = [const { AtomicU64::new(0) }; CORES];
static STOP: AtomicBool = AtomicBool::new(false);
static ERROR: AtomicU64 = AtomicU64::new(0);
static STARTS: AtomicU64 = AtomicU64::new(0);
static RESUMES: AtomicU64 = AtomicU64::new(0);
static CROSS_AP: AtomicU64 = AtomicU64::new(0);
static FX_SAVES: AtomicU64 = AtomicU64::new(0);
static FX_RESTORES: AtomicU64 = AtomicU64::new(0);

fn bottom() -> usize { TASK_STACK.0.get().cast::<u8>() as usize }
fn top() -> usize { bottom() + STACK_BYTES }
fn escape_bottom(cpu: usize) -> usize {
    let raw = unsafe { core::ptr::addr_of_mut!((*ESCAPE.0.get())[cpu]) };
    raw.cast::<u8>() as usize
}
fn escape_top(cpu: usize) -> usize { escape_bottom(cpu) + ESCAPE_BYTES }

unsafe fn fxsave(image: *mut FxImage) {
    unsafe { asm!("fxsave64 [{}]", in(reg) image, options(nostack)); }
}
unsafe fn fxrstor(image: *const FxImage) {
    unsafe { asm!("fxrstor64 [{}]", in(reg) image, options(nostack)); }
}
fn xmm_low(image: *const FxImage) -> u64 {
    unsafe { image.cast::<u8>().add(XMM0_OFFSET).cast::<u64>().read_unaligned() }
}

/// AP owns its original FX/control state, but the single task FX image is
/// transferable only after a fully completed hardware-timer checkpoint.
fn fx_enter(cpu: usize) -> bool {
    let f = __cpuid(1);
    if f.edx & ((1 << 24) | (1 << 25) | (1 << 26))
        != ((1 << 24) | (1 << 25) | (1 << 26))
    { return false; }
    let cr0: u64;
    let cr4: u64;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        asm!("mov cr0, {}", in(reg) ((cr0 | CR0_MP) & !(CR0_EM | CR0_TS)), options(nostack));
        asm!("mov cr4, {}", in(reg) (cr4 | CR4_OSFXSR | CR4_OSXMMEXCPT), options(nostack));
        (*CONTROLS.0.get())[cpu].0 = cr0;
        (*CONTROLS.0.get())[cpu].1 = cr4;
        let bank = FX.0.get();
        let original = core::ptr::addr_of_mut!((*bank).1[cpu]);
        fxsave(original);
        if !FX_READY.load(Ordering::Acquire) {
            core::ptr::copy_nonoverlapping(
                original, core::ptr::addr_of_mut!((*bank).0), 1,
            );
            FX_READY.store(true, Ordering::Release);
        }
        fxrstor(core::ptr::addr_of!((*bank).0));
    }
    FX_RESTORES.fetch_add(1, Ordering::Relaxed);
    true
}
fn fx_leave(cpu: usize) {
    unsafe {
        let bank = FX.0.get();
        fxrstor(core::ptr::addr_of!((*bank).1[cpu]));
        let (cr0, cr4, _) = (*CONTROLS.0.get())[cpu];
        asm!("mov cr4, {}", in(reg) cr4, options(nostack));
        asm!("mov cr0, {}", in(reg) cr0, options(nostack));
    }
}
fn stop_local_timer() -> bool {
    let lvt = unsafe { ap_ipi_smoke::read(lapic_timer_layout::LVT_TIMER_OFFSET) };
    unsafe {
        ap_ipi_smoke::write(
            lapic_timer_layout::LVT_TIMER_OFFSET, lvt | lapic_timer_layout::LVT_MASKED,
        );
        ap_ipi_smoke::write(lapic_timer_layout::INITIAL_COUNT_OFFSET, 0);
    }
    unsafe {
        ap_ipi_smoke::read(lapic_timer_layout::INITIAL_COUNT_OFFSET) == 0
            && ap_ipi_smoke::read(lapic_timer_layout::LVT_TIMER_OFFSET)
                & lapic_timer_layout::LVT_MASKED != 0
    }
}

/// This runs after hardware IRETQ onto a CPU-private ESCAPE stack, with
/// IF=0. The task's actual interrupted frame is still saved unmodified
/// on the globally mapped shared 16KiB kernel stack. Switching back
/// reactivates this AP's suspended coordinator, NOT the interrupted task.
extern "C" fn escape() -> ! {
    let Some(cpu) = ap_ipi_smoke::ap_slot(ap_ipi_smoke::local_id())
    else { crate::halt_forever(); };
    if cpu >= CORES || x86_64::instructions::interrupts::are_enabled() {
        ERROR.fetch_add(1, Ordering::Relaxed);
        crate::halt_forever();
    }
    unsafe {
        let storage = RSP.0.get();
        context_switch::switch_raw(
            core::ptr::addr_of_mut!((*storage).1[cpu]),
            core::ptr::addr_of!((*storage).0[cpu]),
        );
    }
    crate::halt_forever()
}

fn make_escape_frame(cpu: usize) -> Option<usize> {
    let low = escape_bottom(cpu);
    let high = escape_top(cpu);
    let cs = CS::get_reg().0;
    let ss = SS::get_reg().0;
    if low & 15 != 0 || high & 15 != 0
        || cs == 0 || cs & 3 != 0 || ss == 0 || ss & 3 != 0
    { return None; }
    let addr = high - 8 - size_of::<KernelTrapFrame>();
    let fake = KernelTrapFrame {
        registers: SavedGprs::default(),
        hardware: HardwareReturnFrame {
            rip: escape as usize as u64,
            cs: cs as u64,
            // CPU returns to escape with IF=0 (no nested timer there).
            rflags: 0x2,
            rsp: (high - 8) as u64,
            ss: ss as u64,
        },
    };
    unsafe {
        (addr as *mut KernelTrapFrame).write(fake);
        ((high - 8) as *mut u64).write(0);
    }
    Some(addr)
}

/// Executes as uninterrupted CPU-bound Rust code. No 'yield', no
/// cooperative task switch and no access to the coordinator RSP.
/// The ONLY way out of this stack is through a real timer IRQ.
#[repr(C)]
struct Local {
    cookie: u64,
    visits: u64,
    last_cpu: usize,
}
extern "C" fn worker() -> ! {
    STARTS.fetch_add(1, Ordering::Relaxed);
    let mut local = Local {
        cookie: LOCAL_COOKIE,
        visits: 0,
        last_cpu: usize::MAX,
    };
    let ptr = core::ptr::addr_of_mut!(local);
    // The initial task enters by ABI-only stack switch with IF=0.
    // Later migrations resume via a captured IRETQ with saved IF=1.
    x86_64::instructions::interrupts::enable();
    loop {
        let Some(cpu) = ap_ipi_smoke::ap_slot(ap_ipi_smoke::local_id())
        else { crate::halt_forever(); };
        if cpu >= CORES { crate::halt_forever(); }
        let epoch = EPOCH[cpu].load(Ordering::Acquire);
        let previous = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!((*ptr).last_cpu))
        };
        if cpu != previous {
            let count = unsafe {
                core::ptr::read_volatile(core::ptr::addr_of!((*ptr).visits))
            };
            if count != epoch || epoch >= QUANTA
                || unsafe {
                    core::ptr::read_volatile(core::ptr::addr_of!((*ptr).cookie))
                } != LOCAL_COOKIE
            {
                ERROR.fetch_add(1, Ordering::Relaxed);
            }
            if count == 0 {
                unsafe { asm!("movq xmm0, {}", in(reg) XMM_TAG, options(nostack, preserves_flags)); }
            } else {
                let live: u64;
                unsafe { asm!("movq {}, xmm0", out(reg) live, options(nostack, preserves_flags)); }
                if live != XMM_TAG { ERROR.fetch_add(1, Ordering::Relaxed); }
                CROSS_AP.fetch_add(1, Ordering::Relaxed);
            }
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).last_cpu), cpu);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*ptr).visits), count + 1);
            }
            RESUMES.fetch_add(1, Ordering::Relaxed);
        }
        // The tick can preempt *anywhere* in this busy loop. A live stack
        // local + uncooperative work prove true involuntary suspension.
        WORK[cpu].fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

/// Called by the real AP-local timer IRQ assembly after saving all 15 GPRs.
/// All task FX and stack state are captured on SOURCE CPU with IF=0.
/// Normal completion IRETQs to this AP's private escape stack, never to
/// the interrupted worker; DESTINATION will later IRETQ to the stored frame.
#[unsafe(no_mangle)]
pub extern "C" fn wolfos_ap_migrate_timer_irq_dispatch(
    frame: *const KernelTrapFrame,
) -> *const KernelTrapFrame {
    let Some(cpu) = ap_ipi_smoke::ap_slot(ap_ipi_smoke::local_id())
    else {
        ERROR.fetch_add(1, Ordering::Relaxed);
        unsafe { ap_ipi_smoke::write(lapic_irq_layout::EOI_OFFSET, 0); }
        return frame;
    };
    TIMER_IRQS[cpu].fetch_add(1, Ordering::Relaxed);
    let original = frame;
    let mut next_frame = frame;
    if cpu >= CORES || !ACTIVE[cpu].swap(false, Ordering::AcqRel) {
        ERROR.fetch_add(1, Ordering::Relaxed);
    } else {
        let cs = CS::get_reg().0;
        let valid = frame as usize >= bottom() + 512
            && (frame as usize).checked_add(size_of::<KernelTrapFrame>())
                .is_some_and(|end| end <= top())
            && unsafe { validate_kernel_resume(
                frame as u64, bottom() as u64, top() as u64, cs, &*frame
            ).is_ok() };
        let progress = WORK[cpu].load(Ordering::Relaxed);
        let previous = LAST_WORK[cpu].swap(progress, Ordering::Relaxed);
        if !valid || progress <= previous {
            ERROR.fetch_add(1, Ordering::Relaxed);
        } else {
            // The task is the only running owner; save the entire legacy
            // 512-byte x87/SSE image BEFORE restoring source AP original FX.
            unsafe {
                let bank = FX.0.get();
                let task = core::ptr::addr_of_mut!((*bank).0);
                fxsave(task);
                if xmm_low(task) != XMM_TAG { ERROR.fetch_add(1, Ordering::Relaxed); }
                fxrstor(core::ptr::addr_of!((*bank).1[cpu]));
            }
            FX_SAVES.fetch_add(1, Ordering::Relaxed);
            let epoch = EPOCH[cpu].load(Ordering::Acquire);
            let snap = LEASE.execute_quantum(cpu, epoch);
            if snap.ok().is_none_or(|s| s.steps != epoch + 1)
                || !stop_local_timer()
            {
                ERROR.fetch_add(1, Ordering::Relaxed);
            } else {
                CAPTURED.store(frame as usize, Ordering::Release);
                let fake = unsafe { (*RSP.0.get()).1[cpu] };
                if fake == 0 {
                    ERROR.fetch_add(1, Ordering::Relaxed);
                } else {
                    next_frame = fake as *const KernelTrapFrame;
                }
            }
        }
    }
    // Exactly one EOI on the receiving local APIC, never the BSP's.
    unsafe { ap_ipi_smoke::write(lapic_irq_layout::EOI_OFFSET, 0); }
    TIMER_EOIS[cpu].fetch_add(1, Ordering::Release);
    if next_frame == original {
        // Failure case cannot safely publish a result; leave test to
        // fail-closed QEMU timeout instead of executing unvalidated frame.
    }
    next_frame
}

fn prepare_bsp() -> bool {
    let low = bottom();
    let high = top();
    let Ok(sp) = migrating_stack_contract::initial_rsp(low, high)
    else { return false; };
    unsafe {
        (low as *mut u64).write_volatile(CANARY);
        core::ptr::write_bytes(sp as *mut u8, 0, 64);
        (sp as *mut usize).add(6).write(worker as usize);
        (*RSP.0.get()).2 = sp;
    }
    CAPTURED.store(0, Ordering::Release);
    FX_READY.store(false, Ordering::Release);
    true
}

/// AP-private directed IPI (vector 0xe1) only claims its one work mailbox.
/// The preempted shared kernel task is resumed OUTSIDE the IRQ.
pub fn on_ipi(cpu: usize) {
    if cpu >= CORES || MAIL[cpu].claim_from_irq(cpu).is_err() {
        ERROR.fetch_add(1, Ordering::Relaxed);
    } else {
        CLAIMS[cpu].fetch_add(1, Ordering::Release);
    }
}

/// AP worker loop retains its own original MP stack when task is running.
/// When its local timer preempts the busy task, escape()->coordinator
/// returns HERE, after the saved-RSP call or full IRQ-frame IRETQ resume.
pub fn secondary_run(cpu: usize) -> bool {
    if cpu >= CORES || ap_ipi_smoke::ap_slot(ap_ipi_smoke::local_id()) != Some(cpu)
        || x86_64::instructions::interrupts::are_enabled()
    { return false; }
    x86_64::instructions::interrupts::enable();
    READY[cpu].store(true, Ordering::Release);
    let mut generation = 0u64;
    let mut good = true;
    while !STOP.load(Ordering::Acquire) {
        match MAIL[cpu].claimed_work(cpu) {
            Ok(Some(job)) => {
                if job.sequence != generation + 1 || job.token == 0 {
                    good = false; break;
                }
                x86_64::instructions::interrupts::disable();
                if !fx_enter(cpu) {
                    good = false; break;
                }
                EPOCH[cpu].store(job.token - 1, Ordering::Release);
                if LEASE.resume(cpu, job.token - 1).is_err() {
                    fx_leave(cpu);
                    good = false; break;
                }
                let Some(fake) = make_escape_frame(cpu)
                else { fx_leave(cpu); good = false; break; };
                // Same AP-specific slot serves as the 'escape frame'
                // only UNTIL escape() begins. It then stores its own
                // suspended coordinator-stack RSP in a different slot.
                unsafe { (*RSP.0.get()).1[cpu] = fake; }
                let Ok(plan) = lapic_timer_plan::periodic_timer_plan(
                    TIMER_VECTOR, DIVISOR, COUNT
                ) else { fx_leave(cpu); good = false; break; };
                unsafe {
                    (*CONTROLS.0.get())[cpu].2 =
                        ap_ipi_smoke::read(lapic_timer_layout::DIVIDE_CONFIG_OFFSET);
                }
                for op in plan.preparation {
                    unsafe { ap_ipi_smoke::write(op.offset, op.value); }
                }
                unsafe { ap_ipi_smoke::write(plan.activation.offset, plan.activation.value); }
                ACTIVE[cpu].store(true, Ordering::Release);
                if job.token == 1 {
                    // Initial kernel task entry is an ABI switch, but
                    // the worker NEVER voluntarily yields afterwards.
                    unsafe {
                        let slot = RSP.0.get();
                        context_switch::switch_raw(
                            core::ptr::addr_of_mut!((*slot).0[cpu]),
                            core::ptr::addr_of!((*slot).2),
                        );
                    }
                } else {
                    let saved = CAPTURED.load(Ordering::Acquire);
                    let cs = CS::get_reg().0;
                    let checked = saved >= bottom() + 512
                        && saved.checked_add(size_of::<KernelTrapFrame>())
                            .is_some_and(|end| end <= top())
                        && unsafe {
                            validate_kernel_resume(
                                saved as u64, bottom() as u64,
                                top() as u64, cs,
                                &*(saved as *const KernelTrapFrame),
                            ).is_ok()
                        };
                    if !checked {
                        ERROR.fetch_add(1, Ordering::Relaxed);
                        good = false;
                    } else {
                        // This assembly primitive saves the CURRENT AP's
                        // coordinator ABI frame before returning by IRETQ
                        // into a FULL hardware-preempted 15-GPR frame.
                        unsafe {
                            let slot = RSP.0.get();
                            ap_irq_migrate_entry::resume_saved_irq(
                                core::ptr::addr_of_mut!((*slot).0[cpu]),
                                saved as *const KernelTrapFrame,
                            );
                        }
                    }
                }
                // Timer IRQ has returned to escape(), which performed an
                // ABI switch onto this AP's original saved coordinator RSP.
                x86_64::instructions::interrupts::disable();
                let stopped = stop_local_timer();
                unsafe {
                    ap_ipi_smoke::write(
                        lapic_timer_layout::DIVIDE_CONFIG_OFFSET,
                        (*CONTROLS.0.get())[cpu].2,
                    );
                }
                fx_leave(cpu);
                let captured = CAPTURED.load(Ordering::Acquire);
                let snap = LEASE.snapshot();
                if !good || !stopped || ACTIVE[cpu].load(Ordering::Acquire)
                    || TIMER_IRQS[cpu].load(Ordering::Acquire) != generation
                    || TIMER_EOIS[cpu].load(Ordering::Acquire) != generation
                    || captured < bottom() + 512
                    || captured.checked_add(size_of::<KernelTrapFrame>())
                        .is_none_or(|end| end > top())
                    || snap.ok().is_none_or(|s| s.owner != cpu
                        || s.epoch != job.token - 1 || s.steps != job.token)
                {
                    good = false; break;
                }
                let Some(snap) = LEASE.snapshot().ok()
                else { good = false; break; };
                if MAIL[cpu].finish(cpu, job.sequence, snap.digest).is_err() {
                    good = false; break;
                }
                DONE[cpu].fetch_add(1, Ordering::Release);
                generation = job.sequence;
                x86_64::instructions::interrupts::enable();
            }
            Ok(None) => core::hint::spin_loop(),
            Err(_) => { good = false; break; }
        }
    }
    x86_64::instructions::interrupts::disable();
    let final_ok = good && generation == PER_AP
        && DONE[cpu].load(Ordering::Acquire) == PER_AP
        && CLAIMS[cpu].load(Ordering::Acquire) == PER_AP
        && MAIL[cpu].is_idle_generation(PER_AP)
        && TIMER_IRQS[cpu].load(Ordering::Acquire) == PER_AP
        && TIMER_EOIS[cpu].load(Ordering::Acquire) == PER_AP;
    if !final_ok { ERROR.fetch_add(1, Ordering::Relaxed); }
    final_ok
}

fn wait(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..WAIT_SPINS {
        if f() { return true; }
        core::hint::spin_loop();
    }
    f()
}

/// BSP IF=0, 4-vCPU QEMU only. The previous AP must have returned to its
/// own coordinator and published an Acquire-visible mailbox completion
/// BEFORE the owner+epoch transfer and directed IPI to the new AP.
pub fn verify_bsp(bsp: u32, cpus: &[&MpInfo]) -> bool {
    if cpus.len() != CORES || cpus[0].lapic_id != bsp
        || cpus.iter().filter(|c| c.lapic_id == bsp).count() != 1
        || x86_64::instructions::interrupts::are_enabled()
        || !wait(|| (1..CORES).all(|i| READY[i].load(Ordering::Acquire)))
        || !prepare_bsp() || LEASE.initialize(1).is_err()
    {
        serial::write_line("WOLFOS_AP_IRQ_MIGRATE_ERROR setup");
        return false;
    }
    let mut owner = 1usize;
    let mut epoch = 0u64;
    let mut digest = INITIAL_DIGEST;
    let mut generations = [0u64; CORES];
    let mut sends = 0u64;
    let mut migrations = 0u64;
    let mut stale = 0u64;
    let mut valid = true;
    'steps: for step in 1..=QUANTA {
        let next_cpu = ((step - 1) % 3 + 1) as usize;
        if step > 1 {
            let previous = epoch;
            let Ok(new_epoch) = LEASE.transfer(owner, next_cpu, epoch)
            else { valid = false; break 'steps; };
            epoch = new_epoch;
            migrations += 1;
            if LEASE.transfer(owner, next_cpu, previous)
                == Err(HandoffError::WrongOwner)
            { stale += 1; } else { valid = false; break 'steps; }
        }
        generations[next_cpu] += 1;
        let generation = generations[next_cpu];
        if MAIL[next_cpu].publish(next_cpu, generation, epoch + 1).is_err()
            || !ap_ipi_smoke::send(bsp, cpus[next_cpu].lapic_id)
        { valid = false; break 'steps; }
        sends += 1;
        if !wait(|| MAIL[next_cpu].completed(next_cpu, generation)
            .ok().flatten().is_some())
        { valid = false; break 'steps; }
        digest = advance_digest(digest, step);
        let snap = LEASE.snapshot();
        if snap.ok().is_none_or(|s| s.epoch != epoch
            || s.owner != next_cpu || s.steps != step || s.digest != digest)
            || MAIL[next_cpu].completed(next_cpu, generation).ok().flatten() != Some(digest)
            || ap_ipi_smoke::ipi_received(next_cpu) != generation
            || ap_ipi_smoke::ipi_eois(next_cpu) != generation
            || CLAIMS[next_cpu].load(Ordering::Acquire) != generation
            || DONE[next_cpu].load(Ordering::Acquire) != generation
            || TIMER_IRQS[next_cpu].load(Ordering::Acquire) != generation
            || TIMER_EOIS[next_cpu].load(Ordering::Acquire) != generation
            || MAIL[next_cpu].retire(next_cpu, generation).is_err()
        { valid = false; break 'steps; }
        owner = next_cpu;
    }
    if valid && LEASE.retire(owner, epoch).is_err() { valid = false; }
    STOP.store(true, Ordering::Release);
    let offline = wait(|| (1..CORES).all(|cpu| ap_ipi_smoke::is_offline(cpu)));
    let (mut ipis, mut ipi_eois, mut timers, mut timer_eois,
         mut claims, mut completed, mut work, mut idle) =
        (0u64,0u64,0u64,0u64,0u64,0u64,0u64,0usize);
    for cpu in 1..CORES {
        let i = ap_ipi_smoke::ipi_received(cpu);
        let e = ap_ipi_smoke::ipi_eois(cpu);
        let t = TIMER_IRQS[cpu].load(Ordering::Acquire);
        let te = TIMER_EOIS[cpu].load(Ordering::Acquire);
        let c = CLAIMS[cpu].load(Ordering::Acquire);
        let d = DONE[cpu].load(Ordering::Acquire);
        let w = WORK[cpu].load(Ordering::Acquire);
        ipis += i; ipi_eois += e; timers += t; timer_eois += te;
        claims += c; completed += d; work += w;
        idle += usize::from(MAIL[cpu].is_idle_generation(PER_AP));
        if i != PER_AP || e != PER_AP || t != PER_AP || te != PER_AP
            || c != PER_AP || d != PER_AP || w == 0
            || !ap_ipi_smoke::is_offline(cpu) { valid = false; }
    }
    let errors = ERROR.load(Ordering::Acquire) + ap_ipi_smoke::bad_count();
    let spurious = ap_ipi_smoke::spurious_count();
    let canary = unsafe { (bottom() as *const u64).read_volatile() == CANARY };
    let first = STARTS.load(Ordering::Acquire);
    let resumes = RESUMES.load(Ordering::Acquire);
    let hops = CROSS_AP.load(Ordering::Acquire);
    let saves = FX_SAVES.load(Ordering::Acquire);
    let restores = FX_RESTORES.load(Ordering::Acquire);
    if valid && offline && sends == QUANTA && migrations == QUANTA - 1
        && stale == migrations && ipis == QUANTA && ipi_eois == QUANTA
        && timers == QUANTA && timer_eois == QUANTA
        && claims == QUANTA && completed == QUANTA && idle == 3
        && first == 1 && resumes == QUANTA && hops == migrations
        && saves == QUANTA && restores == QUANTA && canary
        && work > 0 && errors == 0 && spurious == 0
        && LEASE.is_retired(owner, epoch)
    {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_IRQ_MIGRATE_OK cpus=4 aps=3 starts={} resumes={} hops={} transfers={} quanta={} ipis={} ipi_eois={} timer_irqs={} timer_eois={} claims={} finished={} stale_denied={} fx_saves={} fx_restores={} work={} canary=1 invalid=0 spurious=0 offline=3 irq_preempted=1 stack_copied=0 bsp_if=0\n",
            first, resumes, hops, migrations, QUANTA, ipis, ipi_eois,
            timers, timer_eois, claims, completed, stale,
            saves, restores, work,
        ));
        true
    } else {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_IRQ_MIGRATE_ERROR valid={} starts={} resumes={} hops={} transfers={} quanta={} ipis={} ipi_eois={} timer_irqs={} timer_eois={} claims={} finished={} stale_denied={} fx_saves={} fx_restores={} work={} canary={} invalid={} spurious={} offline={}\n",
            valid, first, resumes, hops, migrations, QUANTA, ipis, ipi_eois,
            timers, timer_eois, claims, completed, stale,
            saves, restores, work, canary, errors, spurious, offline,
        ));
        false
    }
}
