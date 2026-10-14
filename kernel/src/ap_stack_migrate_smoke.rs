//! QEMU-only suspended kernel context migration across three APs.
//!
//! ONE real Rust function, ONE fixed 16 KiB stack and ONE saved ABI RSP
//! are resumed, across AP1->AP2->AP3->AP1 (12 quanta). A task runs on
//! an AP's own local hardware CPU only while its TaskLease is RUNNING.
//! Before changing owners it saves its legacy x87/SSE image, commits a
//! Paused snapshot, then returns to that AP's *coordinator stack* via
//! an actual ABI context switch. BSP transfers the lease only AFTER
//! the coordinator publishes verified completion. A directed IPI wakes
//! the next AP, which restores the SAME task FX image and saved RSP,
//! resuming the SAME Rust function and the SAME stack-local variables.
//!
//! This is NOT IRQ-time/live preemption migration. All yields happen at
//! controlled ABI-safe boundaries with IF=0, identical kernel CR3,
//! no FS/GS/TLS, XSAVE/AVX, user mode, guard pages or stack reclamation.
//! A static shared kernel stack is retained throughout QEMU exit.

use core::arch::{asm, x86_64::__cpuid};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use limine::mp::MpInfo;
use crate::{
    ap_ipi_smoke, context_switch, migrating_stack_contract::{
        self, STACK_BYTES, validate_suspended_rsp,
    }, remote_runqueue::RemoteMailbox, serial,
    task_handoff::{TaskLease, HandoffError, advance_digest, INITIAL_DIGEST},
};

const CORES: usize = 4;
const QUANTA: u64 = 12;
const PER_AP: u64 = 4;
const WAIT_SPINS: usize = 200_000_000;
const CANARY: u64 = 0x574f_4c46_4d49_4752;
const XMM_TAG: u64 = 0x7777_55aa_ddcc_3311;
const XMM_OFFSET: usize = 160;
const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR0_TS: u64 = 1 << 3;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;

#[repr(align(16))]
struct Stack([u8; STACK_BYTES]);
struct SingleStack(UnsafeCell<Stack>);
// SAFETY: one TaskLease RUNNING owner at a time. BSP only initializes this
// stack before first dispatch and reads canary after all APs stopped.
unsafe impl Sync for SingleStack {}
static STACK: SingleStack = SingleStack(UnsafeCell::new(Stack([0; STACK_BYTES])));

struct SuspendedSlots(UnsafeCell<(usize, [usize; CORES])>);
// SAFETY: the saved task RSP is only written by the ONE current task when
// switching off its stack; next AP reads only AFTER the original AP
// publishes Completion with Release and BSP publishes the next mailbox.
// Each coordinator RSP cell is touched only by its owning processor.
unsafe impl Sync for SuspendedSlots {}
static RSP: SuspendedSlots = SuspendedSlots(UnsafeCell::new((0, [0; CORES])));

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct FxImage([u8; 512]);
struct FxSlots(UnsafeCell<(FxImage, [FxImage; CORES])>);
// SAFETY: shared task FX saved by exclusive owner before it yields;
// original FX images indexed per CPU, never accessed by another AP.
unsafe impl Sync for FxSlots {}
static FX: FxSlots = FxSlots(UnsafeCell::new((
    FxImage([0; 512]), [const { FxImage([0; 512]) }; CORES],
)));
static FX_INITIALIZED: AtomicBool = AtomicBool::new(false);

struct ControlSlots(UnsafeCell<[(u64, u64); CORES]>);
unsafe impl Sync for ControlSlots {}
static CTRL: ControlSlots = ControlSlots(UnsafeCell::new([(0, 0); CORES]));

static LEASE: TaskLease = TaskLease::new();
static MAIL: [RemoteMailbox; CORES] = [
    RemoteMailbox::new(0), RemoteMailbox::new(1),
    RemoteMailbox::new(2), RemoteMailbox::new(3),
];
static EPOCH: [AtomicU64; CORES] = [const { AtomicU64::new(0) }; CORES];
static READY: [AtomicBool; CORES] = [const { AtomicBool::new(false) }; CORES];
static CLAIMS: [AtomicU64; CORES] = [const { AtomicU64::new(0) }; CORES];
static FINISHED: [AtomicU64; CORES] = [const { AtomicU64::new(0) }; CORES];
static STOP: AtomicBool = AtomicBool::new(false);
static ERROR: AtomicU64 = AtomicU64::new(0);
static STARTS: AtomicU64 = AtomicU64::new(0);
static RESUMES: AtomicU64 = AtomicU64::new(0);
static STACK_CROSS_AP: AtomicU64 = AtomicU64::new(0);
static FX_CHECKS: AtomicU64 = AtomicU64::new(0);

fn bottom() -> usize {
    // SAFETY: stable permanent single stack allocation; raw address only.
    STACK.0.get().cast::<u8>() as usize
}
fn top() -> usize { bottom() + STACK_BYTES }
fn slots() -> *mut (usize, [usize; CORES]) { RSP.0.get() }

unsafe fn fxsave(image: *mut FxImage) {
    // SAFETY: CPU has FXSR/SSE2, CR0.EM=TS=0 and CR4.OSFXSR=1.
    // Image points to writable, 16-byte-aligned, owned FX bank.
    unsafe { asm!("fxsave64 [{}]", in(reg) image, options(nostack)); }
}
unsafe fn fxrstor(image: *const FxImage) {
    unsafe { asm!("fxrstor64 [{}]", in(reg) image, options(nostack)); }
}
fn fx_lane(image: *const FxImage) -> u64 {
    unsafe { image.cast::<u8>().add(XMM_OFFSET).cast::<u64>().read_unaligned() }
}
fn fx_setup(cpu: usize) -> bool {
    let feature = __cpuid(1);
    if feature.edx & ((1 << 24) | (1 << 25) | (1 << 26))
        != ((1 << 24) | (1 << 25) | (1 << 26)) { return false; }
    let cr0: u64;
    let cr4: u64;
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        asm!("mov cr0, {}", in(reg) ((cr0 | CR0_MP) & !(CR0_EM | CR0_TS)), options(nostack));
        asm!("mov cr4, {}", in(reg) (cr4 | CR4_OSFXSR | CR4_OSXMMEXCPT), options(nostack));
        (*CTRL.0.get())[cpu] = (cr0, cr4);
        let all = FX.0.get();
        let original = core::ptr::addr_of_mut!((*all).1[cpu]);
        fxsave(original);
        if !FX_INITIALIZED.load(Ordering::Acquire) {
            // The first actual owner is AP index 1, and this is called
            // AFTER the BSP has serialized the first mailbox generation.
            core::ptr::copy_nonoverlapping(
                original, core::ptr::addr_of_mut!((*all).0), 1
            );
            FX_INITIALIZED.store(true, Ordering::Release);
        }
        fxrstor(core::ptr::addr_of!((*all).0));
    }
    true
}
fn fx_leave(cpu: usize) {
    // Task has yielded and saved its FX image; current CPU owns its own
    // coordinator stack with IF=0. Restore original AP FX and CR0/CR4.
    unsafe {
        let all = FX.0.get();
        fxrstor(core::ptr::addr_of!((*all).1[cpu]));
        let (cr0, cr4) = (*CTRL.0.get())[cpu];
        asm!("mov cr4, {}", in(reg) cr4, options(nostack));
        asm!("mov cr0, {}", in(reg) cr0, options(nostack));
    }
}

#[repr(C)]
struct StackLocals {
    cookie: u64,
    steps: u64,
    digest: u64,
    last_cpu: usize,
}

/// Entered via a synthetic ABI return frame only ONCE. Subsequent APs
/// return to the very same Rust invocation through its saved stack RSP.
/// Volatile stack-local fields must survive all 11 CPU changes.
extern "C" fn shared_task() -> ! {
    STARTS.fetch_add(1, Ordering::Relaxed);
    let mut local = StackLocals {
        cookie: CANARY ^ 0x5555_aaaa_1234_9876,
        steps: 0,
        digest: INITIAL_DIGEST,
        last_cpu: usize::MAX,
    };
    let local_ptr = core::ptr::addr_of_mut!(local);
    for step in 1..=QUANTA {
        // No AP timer is armed. Each task slice runs with IF=0, so this
        // function can never be interrupted by an unrelated scheduler.
        if x86_64::instructions::interrupts::are_enabled() {
            ERROR.fetch_add(1, Ordering::Relaxed);
        }
        let Some(cpu) = ap_ipi_smoke::ap_slot(ap_ipi_smoke::local_id())
        else { crate::halt_forever(); };
        let expected_cpu = ((step - 1) % 3 + 1) as usize;
        let epoch = EPOCH[cpu].load(Ordering::Acquire);
        let rsp: usize;
        unsafe { asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)); }
        if cpu != expected_cpu || epoch != step - 1
            || rsp < bottom() + 1024 || rsp >= top()
            || unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*local_ptr).cookie)) }
                != CANARY ^ 0x5555_aaaa_1234_9876
            || unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*local_ptr).steps)) }
                != step - 1
            || (step > 1 && unsafe {
                core::ptr::read_volatile(core::ptr::addr_of!((*local_ptr).last_cpu))
            } == cpu)
        {
            ERROR.fetch_add(1, Ordering::Relaxed);
        }
        if step == 1 {
            unsafe { asm!("movq xmm0, {}", in(reg) XMM_TAG, options(nostack, preserves_flags)); }
        } else {
            let live: u64;
            unsafe { asm!("movq {}, xmm0", out(reg) live, options(nostack, preserves_flags)); }
            if live != XMM_TAG { ERROR.fetch_add(1, Ordering::Relaxed); }
            STACK_CROSS_AP.fetch_add(1, Ordering::Relaxed);
        }
        if LEASE.resume(cpu, epoch).is_err() {
            ERROR.fetch_add(1, Ordering::Relaxed);
        }
        let snap = LEASE.execute_quantum(cpu, epoch);
        if let Ok(s) = snap {
            if s.steps != step
                || s.digest != advance_digest(unsafe {
                    core::ptr::read_volatile(core::ptr::addr_of!((*local_ptr).digest))
                }, step)
            { ERROR.fetch_add(1, Ordering::Relaxed); }
            unsafe {
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*local_ptr).steps), step);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*local_ptr).digest), s.digest);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*local_ptr).last_cpu), cpu);
            }
        } else {
            ERROR.fetch_add(1, Ordering::Relaxed);
        }
        RESUMES.fetch_add(1, Ordering::Relaxed);
        // Save task FX before the ABI-only stack switch; the coordinator
        // does not touch the task's FX image until a NEW owner restores it.
        unsafe {
            let all = FX.0.get();
            let image = core::ptr::addr_of_mut!((*all).0);
            fxsave(image);
            if fx_lane(image) != XMM_TAG { ERROR.fetch_add(1, Ordering::Relaxed); }
            FX_CHECKS.fetch_add(1, Ordering::Relaxed);
            let rsp_slots = slots();
            context_switch::switch_raw(
                core::ptr::addr_of_mut!((*rsp_slots).0),
                core::ptr::addr_of!((*rsp_slots).1[cpu]),
            );
        }
        // When next resumed by a DIFFERENT AP, execution returns here,
        // continuing to the next iteration using SAME Rust stack locals.
    }
    crate::halt_forever() // never schedule the completed stack again
}

/// BSP only. Initializes the one shared stack before any AP may resume it.
fn prepare() -> bool {
    let lo = bottom();
    let hi = top();
    let Ok(sp) = migrating_stack_contract::initial_rsp(lo, hi) else { return false; };
    unsafe {
        (lo as *mut u64).write_volatile(CANARY);
        core::ptr::write_bytes(sp as *mut u8, 0, 8 * 8);
        ((sp as *mut usize).add(6)).write(shared_task as usize);
        (*slots()).0 = sp;
    }
    FX_INITIALIZED.store(false, Ordering::Relaxed);
    true
}

/// AP private external IPI handler: claim ONLY, no context switch inside
/// interrupt, no FX use. The shared APIC handler issues its own local EOI.
pub fn on_ipi(cpu: usize) {
    if cpu >= CORES || MAIL[cpu].claim_from_irq(cpu).is_err() {
        ERROR.fetch_add(1, Ordering::Relaxed);
    } else {
        CLAIMS[cpu].fetch_add(1, Ordering::Release);
    }
}

/// AP worker waits on its OWN permanent MP stack and executes the one
/// quiesced task when its directed IPI mailbox transitions to Claimed.
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
                // One exclusive saved RSP across ALL APs. The old AP has
                // already yielded and published completion before BSP
                // issues this IPI. No other CPU may enter this branch.
                x86_64::instructions::interrupts::disable();
                if !fx_setup(cpu) {
                    good = false;
                    break;
                }
                EPOCH[cpu].store(job.token - 1, Ordering::Release);
                let sp = unsafe { (*slots()).0 };
                if validate_suspended_rsp(bottom(), top(), sp).is_err() {
                    ERROR.fetch_add(1, Ordering::Relaxed);
                    fx_leave(cpu);
                    good = false;
                    break;
                }
                unsafe {
                    let p = slots();
                    context_switch::switch_raw(
                        core::ptr::addr_of_mut!((*p).1[cpu]),
                        core::ptr::addr_of!((*p).0),
                    );
                }
                // This is the SAME AP's coordinator again, IF=0: task
                // has saved its FX image and suspended its real RSP.
                let saved = unsafe { (*slots()).0 };
                let ok = validate_suspended_rsp(bottom(), top(), saved).is_ok();
                fx_leave(cpu);
                if !ok || LEASE.snapshot().ok().is_none_or(|s|
                    s.owner != cpu || s.epoch != job.token - 1 || s.steps != job.token
                ) {
                    good = false; break;
                }
                let Ok(snap) = LEASE.snapshot() else { good = false; break; };
                if MAIL[cpu].finish(cpu, job.sequence, snap.digest).is_err() {
                    good = false; break;
                }
                FINISHED[cpu].fetch_add(1, Ordering::Release);
                generation = job.sequence;
                x86_64::instructions::interrupts::enable();
            }
            Ok(None) => core::hint::spin_loop(),
            Err(_) => { good = false; break; }
        }
    }
    x86_64::instructions::interrupts::disable();
    let good = good && generation == PER_AP
        && FINISHED[cpu].load(Ordering::Acquire) == PER_AP
        && CLAIMS[cpu].load(Ordering::Acquire) == PER_AP
        && MAIL[cpu].is_idle_generation(PER_AP);
    if !good { ERROR.fetch_add(1, Ordering::Relaxed); }
    good
}

fn wait(mut check: impl FnMut() -> bool) -> bool {
    for _ in 0..WAIT_SPINS {
        if check() { return true; }
        core::hint::spin_loop();
    }
    check()
}

/// BSP stays IF=0 throughout. It checks that a real stack+FX context
/// suspends BEFORE transferring lease to another AP. Destination IPI
/// resumes from the saved ABI return frame on the SAME stack, no copy.
pub fn verify_bsp(bsp: u32, cpus: &[&MpInfo]) -> bool {
    if cpus.len() != CORES
        || cpus.iter().filter(|c| c.lapic_id == bsp).count() != 1
        || cpus[0].lapic_id != bsp
        || x86_64::instructions::interrupts::are_enabled()
        || !wait(|| (1..CORES).all(|cpu| READY[cpu].load(Ordering::Acquire)))
        || !prepare() || LEASE.initialize(1).is_err()
    {
        serial::write_line("WOLFOS_AP_STACK_MIGRATE_ERROR setup");
        return false;
    }
    let mut epoch = 0u64;
    let mut owner = 1usize;
    let mut digest = INITIAL_DIGEST;
    let mut sent = 0u64;
    let mut transfers = 0u64;
    let mut stale_denied = 0u64;
    let mut generations = [0u64; CORES];
    let mut valid = true;
    'steps: for step in 1..=QUANTA {
        let cpu = ((step - 1) % 3 + 1) as usize;
        if step > 1 {
            let before = epoch;
            let Ok(next) = LEASE.transfer(owner, cpu, epoch)
            else { valid = false; break 'steps; };
            epoch = next;
            transfers += 1;
            if LEASE.transfer(owner, cpu, before) == Err(HandoffError::WrongOwner) {
                stale_denied += 1;
            } else { valid = false; break 'steps; }
        }
        generations[cpu] += 1;
        let generation = generations[cpu];
        if MAIL[cpu].publish(cpu, generation, epoch + 1).is_err()
            || !ap_ipi_smoke::send(bsp, cpus[cpu].lapic_id)
        { valid = false; break 'steps; }
        sent += 1;
        if !wait(|| MAIL[cpu].completed(cpu, generation).ok().flatten().is_some()) {
            valid = false; break 'steps;
        }
        digest = advance_digest(digest, step);
        let snap = LEASE.snapshot();
        if snap.ok().is_none_or(|s| s.epoch != epoch
            || s.owner != cpu || s.steps != step || s.digest != digest)
            || MAIL[cpu].completed(cpu, generation).ok().flatten() != Some(digest)
            || ap_ipi_smoke::ipi_received(cpu) != generation
            || ap_ipi_smoke::ipi_eois(cpu) != generation
            || CLAIMS[cpu].load(Ordering::Acquire) != generation
            || FINISHED[cpu].load(Ordering::Acquire) != generation
            || validate_suspended_rsp(bottom(), top(), unsafe { (*slots()).0 }).is_err()
            || MAIL[cpu].retire(cpu, generation).is_err()
        { valid = false; break 'steps; }
        owner = cpu;
    }
    if valid && LEASE.retire(owner, epoch).is_err() { valid = false; }
    STOP.store(true, Ordering::Release);
    let offline = wait(|| (1..CORES).all(|i| ap_ipi_smoke::is_offline(i)));
    let mut irq = 0u64;
    let mut eoi = 0u64;
    let mut claim = 0u64;
    let mut finished = 0u64;
    let mut idle = 0usize;
    for cpu in 1..CORES {
        let seen = ap_ipi_smoke::ipi_received(cpu);
        let ack = ap_ipi_smoke::ipi_eois(cpu);
        irq += seen; eoi += ack;
        claim += CLAIMS[cpu].load(Ordering::Acquire);
        finished += FINISHED[cpu].load(Ordering::Acquire);
        idle += usize::from(MAIL[cpu].is_idle_generation(PER_AP));
        if seen != PER_AP || ack != PER_AP
            || CLAIMS[cpu].load(Ordering::Acquire) != PER_AP
            || FINISHED[cpu].load(Ordering::Acquire) != PER_AP
            || !ap_ipi_smoke::is_offline(cpu)
        { valid = false; }
    }
    let errors = ERROR.load(Ordering::Acquire) + ap_ipi_smoke::bad_count();
    let spurious = ap_ipi_smoke::spurious_count();
    let canary_ok = unsafe { (bottom() as *const u64).read_volatile() == CANARY };
    if valid && offline && sent == QUANTA && transfers == QUANTA - 1
        && stale_denied == transfers && irq == QUANTA && eoi == QUANTA
        && claim == QUANTA && finished == QUANTA && idle == 3
        && errors == 0 && spurious == 0 && canary_ok
        && STARTS.load(Ordering::Acquire) == 1
        && RESUMES.load(Ordering::Acquire) == QUANTA
        && STACK_CROSS_AP.load(Ordering::Acquire) == transfers
        && FX_CHECKS.load(Ordering::Acquire) == QUANTA
        && LEASE.is_retired(owner, epoch)
    {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_STACK_MIGRATE_OK cpus=4 aps=3 starts=1 resumes={} cross_ap_resumes={} transfers={} quanta={} sent={} received={} eois={} claims={} finished={} stale_denied={} fx_checked={} canary=1 irq_preempted=0 stack_copied=0 invalid={} spurious={} offline=3 bsp_if=0\n",
            QUANTA, transfers, transfers, QUANTA, sent, irq, eoi,
            claim, finished, stale_denied, FX_CHECKS.load(Ordering::Acquire),
            errors, spurious
        ));
        true
    } else {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_STACK_MIGRATE_ERROR valid={} starts={} resumes={} cross_ap={} sent={} received={} eois={} claim={} finished={} transfers={} stale={} fx={} canary={} offline={} invalid={} spurious={}\n",
            valid, STARTS.load(Ordering::Acquire), RESUMES.load(Ordering::Acquire),
            STACK_CROSS_AP.load(Ordering::Acquire), sent, irq, eoi,
            claim, finished, transfers, stale_denied, FX_CHECKS.load(Ordering::Acquire),
            canary_ok, offline, errors, spurious
        ));
        false
    }
}
