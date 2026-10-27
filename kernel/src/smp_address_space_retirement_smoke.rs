//! Isolated four-CPU CPL0 quiescence proof. All CPUs borrow one cloned
//! kernel PML4, restore the registered supervisor root, then acknowledge
//! their own observation. Explicit active ownership pins the root throughout.
//! No Ring3, PCID, private globals or IPI shootdown. After genuine
//! CR3 departures, each CPU reloads its own supervisor CR3 and acknowledges
//! a generation-tagged retirement TLB round before PMM reclaim.
use crate::{
    active_address_space::ActiveAddressSpace,
    address_space_retirement::{Error, Phase},
    ring3_context_retirement::{Error as BindError, Ring3SavedBinding},
    ring3_runqueue::{Error as QueueError, Ring3RunQueue},
    process_table::ProcessTable,
    user_context_bank::{ContextError as FrameError, UserContextBank},
    saved_context_retirement::Error as ContextError,
    tlb_shootdown::{Error as TlbError, Round, ShootdownBarrier},
    pmm,
    pmm_frame_batch::{FrameBatch, FrameSource, ReleaseReport},
    serial,
};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use limine::mp::MpInfo;
use x86_64::{
    PhysAddr, VirtAddr,
    registers::control::{Cr3, Cr4, Cr4Flags},
    structures::paging::PhysFrame,
};

const CPUS: usize = 4;
const ALL: u64 = 15;
const SPINS: usize = 200_000_000;
static PREPARED: AtomicBool = AtomicBool::new(false);
static STARTED: AtomicBool = AtomicBool::new(false);
static ROOT: AtomicU64 = AtomicU64::new(0);
static SUPERVISOR: AtomicU64 = AtomicU64::new(0);
static BSP: AtomicUsize = AtomicUsize::new(CPUS);
static ACTIVE: AtomicU64 = AtomicU64::new(0);
static RELEASE: AtomicU64 = AtomicU64::new(0);
static ACKS: AtomicU64 = AtomicU64::new(0);
static FLUSH_RELEASE: AtomicU64 = AtomicU64::new(0);
static FLUSH_ACKS: AtomicU64 = AtomicU64::new(0);
static BAD: AtomicBool = AtomicBool::new(false);
static ENTERED: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static LEFT: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];

struct PmmFrames;
impl FrameSource for PmmFrames {
    fn allocate(&mut self) -> Option<u64> {
        let first = pmm::allocate_frame()?;
        if first != 0 {
            return Some(first);
        }
        // UEFI may expose physical frame zero as usable RAM. The ledger
        // deliberately reserves zero as an invalid CR3 identity. Hold that
        // frame until the next allocation, then return it before publication;
        // immediately freeing and retrying would select zero again forever.
        let next = pmm::allocate_frame();
        if pmm::free_frame(first).is_err() {
            serial::write_line("WOLFOS_SMP_RETIRE_ERROR frame_zero_release");
            if let Some(frame) = next {
                if pmm::free_frame(frame).is_err() {
                    serial::write_line("WOLFOS_SMP_RETIRE_ERROR nonzero_root_rollback");
                }
            }
            return None;
        }
        next
    }
    fn release(&mut self, frame: u64) -> bool {
        pmm::free_frame(frame).is_ok()
    }
}
type Owner = ActiveAddressSpace<'static, PmmFrames, 1, CPUS>;
// A single mutable borrow is created by the BSP after STARTED's one-shot CAS,
// before AP startup. Thereafter only the locked Owner can use this provider.
static mut FRAME_SOURCE: PmmFrames = PmmFrames;

struct RoundState {
    barrier: ShootdownBarrier<CPUS>,
    round: Round,
}
struct Ledger {
    held: AtomicBool,
    value: UnsafeCell<Option<Owner>>,
    round: UnsafeCell<Option<RoundState>>,
}
// SAFETY: initialization and every access hold held exclusively. No borrowed
// ledger reference escapes with(); the guard unlocks on every ordinary exit.
unsafe impl Sync for Ledger {}
static LEDGER: Ledger = Ledger {
    held: AtomicBool::new(false),
    value: UnsafeCell::new(None),
    round: UnsafeCell::new(None),
};
struct Unlock<'a>(&'a AtomicBool);
impl Drop for Unlock<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Ledger {
    fn with<R>(&self, operation: impl FnOnce(&mut Option<Owner>) -> R) -> Option<R> {
        self.with_both(|owner, _round| operation(owner))
    }
    fn with_both<R>(
        &self,
        operation: impl FnOnce(&mut Option<Owner>, &mut Option<RoundState>) -> R,
    ) -> Option<R> {
        for _ in 0..SPINS {
            if self
                .held
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                let _unlock = Unlock(&self.held);
                // SAFETY: the ONE shared lock guards both ledgers; neither
                // mutable reference escapes the closure.
                return Some(unsafe {
                    operation(&mut *self.value.get(), &mut *self.round.get())
                });
            }
            core::hint::spin_loop();
        }
        None
    }
}
fn with_gate<R>(operation: impl FnOnce(&mut Owner) -> R) -> Option<R> {
    LEDGER.with(|slot| slot.as_mut().map(operation)).flatten()
}
fn actual_root() -> u64 {
    Cr3::read().0.start_address().as_u64()
}

/// Called by the authenticated local CPU only after its actual supervisor
/// CR3 reload. PCID is disabled and no private global mappings are allowed.
fn acknowledge_local_flush(cpu: usize, supervisor: u64) -> bool {
    if cpu >= CPUS || !supported() || actual_root() != supervisor { return false; }
    LEDGER.with_both(|owner, slot| {
        if !matches!(owner.as_ref().map(|o| o.snapshot().phase), Some(Phase::Retiring)) {
            return false;
        }
        let Some(state) = slot.as_mut() else { return false; };
        // SAFETY: this CPU actually reloaded the authenticated supervisor
        // CR3 after publication, and the same lock guards the exact round.
        unsafe { state.barrier.acknowledge_after_local_flush(state.round, cpu) }.is_ok()
    }) == Some(true)
}
fn supported() -> bool {
    !x86_64::instructions::interrupts::are_enabled() && !Cr4::read().contains(Cr4Flags::PCID)
}
fn wait_for(value: &AtomicU64, mask: u64) -> bool {
    for _ in 0..SPINS {
        if BAD.load(Ordering::Acquire) {
            return false;
        }
        if value.load(Ordering::Acquire) & mask == mask {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn copy_root(hhdm: u64, supervisor: u64, root: u64) -> bool {
    let pointers = hhdm
        .checked_add(supervisor)
        .and_then(|old| hhdm.checked_add(root).map(|new| (old, new)))
        .and_then(|(old, new)| {
            Some((
                VirtAddr::try_new(old).ok()?.as_ptr::<u64>(),
                VirtAddr::try_new(new).ok()?.as_mut_ptr::<u64>(),
            ))
        });
    let Some((old, new)) = pointers else {
        return false;
    };
    // SAFETY: distinct aligned resident PML4 frames via trusted HHDM, before
    // AP startup. Shared children, kernel mappings and stack mappings do not
    // change during the proof. Hardware may update its own accessed bits.
    unsafe {
        for i in 0..512 {
            new.add(i).write_volatile(old.add(i).read_volatile());
        }
    }
    true
}

/// Before AP release, deliberately lose an owner while its real CR3 is active.
/// The test alone can recover this intentional leak after independently
/// restoring the sole CPU; general lost-owner recovery is not implemented.
fn verify_active_drop(hhdm: u64) -> bool {
    let before = pmm::statistics().allocated_frames;
    let supervisor = actual_root();
    let mut source = PmmFrames;
    let Ok(batch) = FrameBatch::<_, 1>::acquire(&mut source) else {
        return false;
    };
    let root = batch.frames()[0];
    if root == supervisor {
        core::mem::forget(batch); // A corrupt PMM must never free the live root.
        return false;
    }
    if !copy_root(hhdm, supervisor, root) {
        return false;
    }
    let Ok(mut owner) = ActiveAddressSpace::<_, 1, 1>::publish(batch, 4, root, supervisor) else {
        return false;
    };
    let Ok(ticket) = owner.reserve_cpu(0) else {
        return false;
    };
    let (original, flags) = Cr3::read();
    // SAFETY: IF=0, PCID=0, before AP release; cloned immutable kernel
    // mappings and their borrowed children remain resident throughout.
    unsafe {
        Cr3::write(PhysFrame::containing_address(PhysAddr::new(root)), flags);
    }
    let confirmed = owner.confirm_active(ticket, actual_root()).is_ok();
    drop(owner);
    let retained = pmm::statistics().allocated_frames == before + 1 && actual_root() == root;
    // SAFETY: unconditional restore before any return after private load.
    unsafe {
        Cr3::write(original, flags);
    }
    if !confirmed || !retained || actual_root() != supervisor || !supported() {
        return false;
    }
    // Sole BSP, no saved context/queue/device/walker or future root load.
    // Shared child tables stay pinned. This is isolated test-leak recovery.
    pmm::free_frame(root).is_ok() && pmm::statistics().allocated_frames == before
}

/// BSP only, after its MMIO probe and before any AP is released. Only the
/// newly allocated PML4 is owned; all child tables remain borrowed/pinned.
pub fn prepare_bsp(bsp_id: u32, cpus: &[&MpInfo], hhdm: u64) -> bool {
    if !supported()
        || cpus.len() != CPUS
        || hhdm & 4095 != 0
        || STARTED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return false;
    }
    let Some(bsp) = cpus.iter().position(|cpu| cpu.lapic_id == bsp_id) else {
        return false;
    };
    if !verify_active_drop(hhdm) {
        return false;
    }
    let supervisor = actual_root();
    // SAFETY: STARTED admits exactly one BSP borrower before any AP starts.
    // This static provider is used only through the locked active owner later.
    let source = unsafe { &mut *core::ptr::addr_of_mut!(FRAME_SOURCE) };
    let Ok(batch) = FrameBatch::<_, 1>::acquire(source) else {
        return false;
    };
    let root = batch.frames()[0];
    if root == supervisor {
        core::mem::forget(batch);
        return false;
    }
    if !copy_root(hhdm, supervisor, root) {
        return false;
    }
    let Ok(gate) = ActiveAddressSpace::publish(batch, 3, root, supervisor) else {
        return false;
    };
    if LEDGER.with(|slot| {
        if slot.is_some() {
            return false;
        }
        *slot = Some(gate);
        true
    }) != Some(true)
    {
        return false; // Active Drop retains the root on publication failure.
    }
    ROOT.store(root, Ordering::Relaxed);
    SUPERVISOR.store(supervisor, Ordering::Relaxed);
    BSP.store(bsp, Ordering::Relaxed);
    PREPARED.store(true, Ordering::Release);
    true
}

/// Runs on each authenticated AP index after its normal boot context work.
/// A failed path restores its CR3 and never permits the BSP to free the root.
pub fn secondary(index: usize) -> bool {
    if !PREPARED.load(Ordering::Acquire)
        || index >= CPUS
        || index == BSP.load(Ordering::Relaxed)
        || !supported()
    {
        BAD.store(true, Ordering::Release);
        return false;
    }
    let (original, flags) = Cr3::read();
    let supervisor = SUPERVISOR.load(Ordering::Relaxed);
    let root = ROOT.load(Ordering::Relaxed);
    if original.start_address().as_u64() != supervisor {
        BAD.store(true, Ordering::Release);
        return false;
    }
    let Some(Ok(ticket)) = with_gate(|gate| gate.reserve_cpu(index)) else {
        BAD.store(true, Ordering::Release);
        return false;
    };
    let Ok(frame) = PhysFrame::from_start_address(PhysAddr::new(root)) else {
        BAD.store(true, Ordering::Release);
        return false;
    };
    // SAFETY: reservation is pinned before the load; BSP retains the cloned
    // PML4 and its unchanged shared children until every AP has restored CR3.
    unsafe {
        Cr3::write(frame, flags);
    }
    let active = actual_root();
    let confirmed = with_gate(|gate| gate.confirm_active(ticket, active)) == Some(Ok(()));
    ENTERED[index].store(active, Ordering::Relaxed);
    if confirmed {
        ACTIVE.fetch_or(1 << index, Ordering::Release);
    }
    let released = confirmed && wait_for(&RELEASE, 1 << index);
    let active_refused = released
        && with_gate(|gate| gate.acknowledge_quiescent(ticket, actual_root()))
            == Some(Err(Error::WrongCr3));
    // SAFETY: both roots are still pinned. Restore unconditionally even when
    // confirmation or a barrier failed; PCID was checked off on this CPU.
    unsafe {
        Cr3::write(original, flags);
    }
    let restored = actual_root();
    LEFT[index].store(restored, Ordering::Relaxed);
    let acknowledged = active_refused
        && restored == supervisor
        && with_gate(|gate| gate.acknowledge_quiescent(ticket, restored)) == Some(Ok(()));
    if !acknowledged {
        BAD.store(true, Ordering::Release);
        return false;
    }
    // Release publishes the actual post-switch observation. This AP performs
    // no later private CR3 load and returns directly to its permanent halt.
    ACKS.fetch_or(1 << index, Ordering::Release);
    // The real private CR3 has already departed; no new private activation
    // is permitted after retirement. Await a post-publication flush round.
    if !wait_for(&FLUSH_RELEASE, 1u64 << index) {
        BAD.store(true, Ordering::Release);
        return false;
    }
    // SAFETY: authenticated AP still owns its permanent supervisor stack;
    // a local supervisor CR3 reload flushes non-global translations with
    // PCID disabled, without touching any physical frame owner.
    unsafe { Cr3::write(original, flags); }
    if !acknowledge_local_flush(index, supervisor) {
        BAD.store(true, Ordering::Release);
        return false;
    }
    FLUSH_ACKS.fetch_or(1u64 << index, Ordering::Release);
    true
}

fn bsp_roundtrip(index: usize, root: u64, supervisor: u64) -> bool {
    let (original, flags) = Cr3::read();
    let Some(Ok(ticket)) = with_gate(|gate| gate.reserve_cpu(index)) else {
        return false;
    };
    let Ok(frame) = PhysFrame::from_start_address(PhysAddr::new(root)) else {
        return false;
    };
    // SAFETY: same immutable shared mappings; APs and BSP keep their own
    // stacks. The reservation precedes the load and no frame can be freed.
    unsafe {
        Cr3::write(frame, flags);
    }
    let entered = actual_root();
    ENTERED[index].store(entered, Ordering::Relaxed);
    let mut ok =
        entered == root && with_gate(|gate| gate.confirm_active(ticket, entered)) == Some(Ok(()));
    ok &= with_gate(|gate| gate.begin_retirement()) == Some(Ok(()));
    ok &= with_gate(|gate| gate.finish_retirement()) == Some(Err(Error::OutstandingCpus));
    ok &= with_gate(|gate| gate.reserve_cpu(index)) == Some(Err(Error::WrongPhase));
    // SAFETY: restore before any return, while all original tables remain
    // pinned. This only deactivates BSP; APs are deliberately still active.
    unsafe {
        Cr3::write(original, flags);
    }
    let restored = actual_root();
    LEFT[index].store(restored, Ordering::Relaxed);
    ok &= restored == supervisor;
    ok &= with_gate(|gate| gate.acknowledge_quiescent(ticket, restored)) == Some(Ok(()));
    if ok {
        ACKS.fetch_or(1 << index, Ordering::Release);
    }
    ok
}

pub fn verify_bsp() -> bool {
    if !PREPARED.load(Ordering::Acquire) || !supported() {
        return false;
    }
    let bsp = BSP.load(Ordering::Relaxed);
    let aps = ALL ^ (1 << bsp);
    let root = ROOT.load(Ordering::Relaxed);
    let supervisor = SUPERVISOR.load(Ordering::Relaxed);
    let resident = pmm::statistics().allocated_frames;
    if actual_root() != supervisor || !wait_for(&ACTIVE, aps) {
        return false;
    }
    // Exercise the actual Ring3RunQueue policy with a synthetic BLOCKED
    // wait. It never owns a real user frame/CR3, but its queue handle and
    // one-use wait ticket are bound to the same ledger as all real CPU loads.
    let mut queue = Ring3RunQueue::<1>::new();
    let Ok(handle) = queue.admit(73) else { return false };
    if queue.start_next() != Ok(handle) {
        return false;
    }
    let Ok((None, wait)) = queue.block_current_for_event(handle, 0xa11) else {
        return false;
    };
    // An empty real process registry/context bank cannot authorize any
    // saved-frame binding. This is still CPL0-only QEMU smoke: no actual
    // CPL3 trap or UserContextBank frame is fabricated for the test.
    let registry = ProcessTable::<1, 1>::new();
    let bank = UserContextBank::<1>::new();
    if with_gate(|gate| Ring3SavedBinding::attach_from_context_bank(
        gate, &registry, &bank, &queue, handle, 0,
    )) != Some(Err(BindError::FrameEvidence(FrameError::NotResident)))
        || with_gate(|gate| gate.context_snapshot().pending) != Some(0)
    {
        return false;
    }
    // Synthetic-only escape hatch retained to exercise quiescence ledger;
    // production admission must use attach_from_context_bank above.
    let Some(Ok(binding)) = with_gate(|gate| Ring3SavedBinding::attach_synthetic_for_smoke(
        gate, &queue, handle, 0,
    )) else {
        return false;
    };
    if with_gate(|gate| gate.context_snapshot().pending) != Some(1)
        || !bsp_roundtrip(bsp, root, supervisor)
        || with_gate(|gate| gate.finish_retirement()) != Some(Err(Error::OutstandingCpus))
        || with_gate(|gate| gate.snapshot().active) != Some(aps)
    {
        return false;
    }
    let Some(last) = (0..CPUS).rev().find(|index| aps & (1 << index) != 0) else {
        return false;
    };
    let last_bit = 1u64 << last;
    RELEASE.store(aps ^ last_bit, Ordering::Release);
    if !wait_for(&ACKS, ALL ^ last_bit)
        || with_gate(|gate| gate.snapshot().active) != Some(last_bit)
        || with_gate(|gate| gate.finish_retirement()) != Some(Err(Error::OutstandingCpus))
        || pmm::statistics().allocated_frames != resident
    {
        return false;
    }
    RELEASE.fetch_or(last_bit, Ordering::Release);
    let before_late_wake = queue;
    if !wait_for(&ACKS, ALL)
        || BAD.load(Ordering::Acquire)
        || ENTERED
            .iter()
            .any(|value| value.load(Ordering::Relaxed) != root)
        || LEFT
            .iter()
            .any(|value| value.load(Ordering::Relaxed) != supervisor)
        || with_gate(|gate| gate.snapshot().active) != Some(0)
        || with_gate(|gate| gate.context_snapshot().pending) != Some(1)
        || with_gate(|gate| gate.finish_retirement()) != Some(Err(Error::OutstandingContexts))
        || with_gate(|gate| binding.wake_for_event(&mut queue, gate, wait, 0xa11))
            != Some(Err(BindError::Context(ContextError::WrongPhase)))
        || queue != before_late_wake
        || actual_root() != supervisor
        || pmm::statistics().allocated_frames != resident
    {
        return false;
    }
    // SAFETY: this synthetic runqueue entry never referenced an actual
    // Ring3 trap frame, hardware timer, event backend or future CR3 handoff.
    // Real CPUs have all independently restored supervisor roots above.
    if with_gate(|gate| unsafe { binding.cancel(&mut queue, gate) }) != Some(Ok(()))
        || queue.wake_for_event(wait, 0xa11) != Err(QueueError::WrongState)
        || with_gate(|gate| gate.context_snapshot().pending) != Some(0)
        || pmm::statistics().allocated_frames != resident
    {
        return false;
    }
    // The actual owner recorded all four CPUs BEFORE their real private
    // CR3 loads. Only the owner can arm its own retired-generation round.
    let armed = LEDGER.with_both(|owner, slot| {
        if slot.is_some() { return false; }
        let Ok(mut barrier) = ShootdownBarrier::<CPUS>::new(3) else { return false; };
        let Some(owner) = owner.as_mut() else { return false; };
        let Ok(round) = owner.begin_retirement_shootdown(&mut barrier, ALL)
        else { return false; };
        *slot = Some(RoundState { barrier, round });
        true
    });
    if armed != Some(true) { return false; }

    // Release two APs while withholding the last. The BSP also performs
    // and acknowledges a real *post-publication* local CR3 reload.
    FLUSH_RELEASE.store(ALL ^ last_bit, Ordering::Release);
    let (original, flags) = Cr3::read();
    if original.start_address().as_u64() != supervisor { return false; }
    // SAFETY: original supervisor CR3 is resident and PCID disabled.
    unsafe { Cr3::write(original, flags); }
    if !acknowledge_local_flush(bsp, supervisor) { return false; }
    FLUSH_ACKS.fetch_or(1u64 << bsp, Ordering::Release);

    if !wait_for(&FLUSH_ACKS, ALL ^ last_bit)
        || BAD.load(Ordering::Acquire)
        || pmm::statistics().allocated_frames != resident
    {
        return false;
    }
    let blocked = LEDGER.with_both(|owner, slot| {
        let Some(state) = slot.as_mut() else { return false; };
        let before = state.barrier.snapshot();
        owner.as_mut().is_some_and(|o|
                o.snapshot().phase == Phase::Retiring
                    && o.finish_retirement() == Err(Error::OutstandingShootdown))
            && before.pending == last_bit && !state.barrier.completed(state.round)
            && state.barrier.begin_covering(ALL, ALL) == Err(TlbError::Busy)
            && state.barrier.snapshot() == before
    });
    if blocked != Some(true) { return false; }

    FLUSH_RELEASE.fetch_or(last_bit, Ordering::Release);
    if !wait_for(&FLUSH_ACKS, ALL)
        || BAD.load(Ordering::Acquire)
        || pmm::statistics().allocated_frames != resident
        || LEDGER.with_both(|owner, slot| {
            let Some(state) = slot.as_ref() else { return false; };
            state.barrier.completed(state.round)
                && state.barrier.snapshot().pending == 0
                && owner.as_ref().is_some_and(|o|
                    o.snapshot().phase == Phase::Retiring
                        && o.context_snapshot().pending == 0)
        }) != Some(true)
        || LEDGER.with_both(|owner, slot| {
            let Some(state) = slot.as_ref() else { return Err(Error::OutstandingShootdown); };
            let Some(owner) = owner.as_mut() else { return Err(Error::WrongPhase); };
            owner.finish_retirement_after_shootdown(&state.barrier, state.round)
        }) != Some(Ok(()))
        || with_gate(|gate| gate.snapshot().phase) != Some(Phase::Retired)
    {
        return false;
    }
    // Independently established on all four CPUs: original root restored,
    // PCID off, no private/global mappings or pending future loads. Only the
    // PML4 is owned; none of its borrowed child tables are released.
    let released = LEDGER
        .with(|slot| {
            let owner = slot.take()?;
            // SAFETY: all four authenticated CPUs have restored their original
            // root with PCID off, invalidating non-global private translations.
            // The synthetic BLOCKED queue entry and its saved-context token
            // were atomically canceled after all actual CPU departures. No
            // real Ring3 saved frame, future queued load, walker or device
            // reference exists in this isolated flavor.
            // Borrowed child tables stay resident.
            match unsafe { owner.reclaim() } {
                Ok(report) => Some(report),
                Err((owner, _)) => {
                    *slot = Some(owner);
                    None
                }
            }
        })
        .flatten();
    if released
        != Some(ReleaseReport {
            released: 1,
            failed: 0,
        })
        || pmm::statistics().allocated_frames.checked_add(1) != Some(resident)
    {
        return false;
    }
    serial::write_line(
        "WOLFOS_ACTIVE_SPACE_OWNERSHIP_OK staged_transfer=1 active_drop_retained=1 cpus=4 last_ap_pinned=1 drop_probe_freed=1 retired_owner_freed=1 pmm_no_leak=1 saved_context_pinned=1 runqueue_cancel=1 late_wake_rejected=1 ring3=0 ipi_shootdown=0 local_cr3_flush_acks=4 withheld_last_flush=1",
    );
    serial::write_line(
        "WOLFOS_SMP_RETIRE_OK cpus=4 real_cr3_loads=4 per_cpu_restored=4 bsp_alone_rejected=1 last_ap_rejected=1 frames_freed=1 pmm_no_leak=1 saved_context_pinned=1 runqueue_cancel=1 late_wake_rejected=1 ring3=0 ipi_shootdown=0 local_cr3_flush_acks=4 withheld_last_flush=1",
    );
    true
}
