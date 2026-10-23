//! Isolated four-CPU CPL0 quiescence proof. All CPUs borrow one cloned
//! kernel PML4, restore the registered supervisor root, then acknowledge
//! their own observation. No Ring3, PCID, private globals or IPI shootdown.
use crate::{
    address_space_retirement::{Error, Phase, RetirementGate},
    pmm, serial,
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
static ROOT: AtomicU64 = AtomicU64::new(0);
static SUPERVISOR: AtomicU64 = AtomicU64::new(0);
static BSP: AtomicUsize = AtomicUsize::new(CPUS);
static ACTIVE: AtomicU64 = AtomicU64::new(0);
static RELEASE: AtomicU64 = AtomicU64::new(0);
static ACKS: AtomicU64 = AtomicU64::new(0);
static BAD: AtomicBool = AtomicBool::new(false);
static ENTERED: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static LEFT: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];

struct Ledger {
    held: AtomicBool,
    value: UnsafeCell<Option<RetirementGate<CPUS>>>,
}
// SAFETY: initialization and every access hold held exclusively. No borrowed
// ledger reference escapes with(); the guard unlocks on every ordinary exit.
unsafe impl Sync for Ledger {}
static LEDGER: Ledger = Ledger {
    held: AtomicBool::new(false),
    value: UnsafeCell::new(None),
};
struct Unlock<'a>(&'a AtomicBool);
impl Drop for Unlock<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl Ledger {
    fn with<R>(&self, operation: impl FnOnce(&mut Option<RetirementGate<CPUS>>) -> R) -> Option<R> {
        for _ in 0..SPINS {
            if self
                .held
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                let _unlock = Unlock(&self.held);
                // SAFETY: exclusive guard held for this entire closure.
                return Some(operation(unsafe { &mut *self.value.get() }));
            }
            core::hint::spin_loop();
        }
        None
    }
}
fn with_gate<R>(operation: impl FnOnce(&mut RetirementGate<CPUS>) -> R) -> Option<R> {
    LEDGER.with(|slot| slot.as_mut().map(operation)).flatten()
}
fn actual_root() -> u64 {
    Cr3::read().0.start_address().as_u64()
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

// Only before publication/bootstrap: no CPU can have loaded this root.
fn reject_unpublished_root(root: u64) -> bool {
    if pmm::free_frame(root).is_err() {
        serial::write_line("WOLFOS_SMP_RETIRE_ERROR staged_root_release");
    }
    false
}

/// BSP only, after its MMIO probe and before any AP is released. Only the
/// newly allocated PML4 is owned; all child tables remain borrowed/pinned.
pub fn prepare_bsp(bsp_id: u32, cpus: &[&MpInfo], hhdm: u64) -> bool {
    if !supported() || cpus.len() != CPUS || PREPARED.load(Ordering::Acquire) || hhdm & 4095 != 0 {
        return false;
    }
    let Some(bsp) = cpus.iter().position(|cpu| cpu.lapic_id == bsp_id) else {
        return false;
    };
    let supervisor = actual_root();
    let Some(root) = pmm::allocate_frame() else {
        return false;
    };
    if root == supervisor {
        return false;
    }
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
        return reject_unpublished_root(root);
    };
    // SAFETY: distinct aligned resident PML4 frames via trusted HHDM, before
    // AP startup. Shared children, kernel mappings and stack mappings do not
    // change during the proof. Hardware may update its own accessed bits.
    unsafe {
        for i in 0..512 {
            new.add(i).write_volatile(old.add(i).read_volatile());
        }
    }
    let Ok(mut gate) = RetirementGate::new(3, root, supervisor) else {
        return reject_unpublished_root(root);
    };
    if gate.publish().is_err() {
        return reject_unpublished_root(root);
    }
    if LEDGER.with(|slot| {
        if slot.is_some() {
            return false;
        }
        *slot = Some(gate);
        true
    }) != Some(true)
    {
        return reject_unpublished_root(root);
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
    if actual_root() != supervisor
        || !wait_for(&ACTIVE, aps)
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
    if !wait_for(&ACKS, ALL)
        || BAD.load(Ordering::Acquire)
        || ENTERED
            .iter()
            .any(|value| value.load(Ordering::Relaxed) != root)
        || LEFT
            .iter()
            .any(|value| value.load(Ordering::Relaxed) != supervisor)
        || with_gate(|gate| gate.finish_retirement()) != Some(Ok(()))
        || with_gate(|gate| gate.snapshot().phase) != Some(Phase::Retired)
        || actual_root() != supervisor
        || pmm::statistics().allocated_frames != resident
    {
        return false;
    }
    // Independently established on all four CPUs: original root restored,
    // PCID off, no private/global mappings or pending future loads. Only the
    // PML4 is owned; none of its borrowed child tables are released.
    if pmm::free_frame(root).is_err()
        || pmm::statistics().allocated_frames.checked_add(1) != Some(resident)
    {
        return false;
    }
    serial::write_line(
        "WOLFOS_SMP_RETIRE_OK cpus=4 real_cr3_loads=4 per_cpu_restored=4 bsp_alone_rejected=1 last_ap_rejected=1 frames_freed=1 pmm_no_leak=1 ring3=0 ipi_shootdown=0",
    );
    true
}
