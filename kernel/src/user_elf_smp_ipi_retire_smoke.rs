//! Isolated 4-vCPU real Ring3 BSP owner + authenticated CPL0 AP borrowers.
//! APs load the *real* ELF-owned user PML4 while still in CPL0, on their
//! permanent kernel stacks; only BSP executes the ELF in genuine CPL3.
//! On terminal EXIT the owner stops admission, reclaims each borrowed AP
//! after a genuine local supervisor CR3 switch, then sends one APIC IPI per
//! historical AP. Each IRQ reloads local CR3 and acknowledges the exact
//! owner-borrowed retirement round. A withheld AP prevents frame reclaim.
//! No AP Ring3 dispatch, PCID, global user mappings, DMA or real-hardware test.
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use limine::mp::MpInfo;
use x86_64::{PhysAddr, registers::control::{Cr3, Cr4, Cr4Flags}, structures::paging::PhysFrame};
use crate::{active_address_space::ActiveAddressSpace,
            address_space_retirement::Error as OwnerError,
            pmm_frame_batch::FrameSource,
            tlb_shootdown::{Round, ShootdownBarrier, Error as TlbError}};

const CPUS: usize = 4;
const ALL: u64 = 15;
const SPINS: usize = 400_000_000;
static INITIALIZED: AtomicBool = AtomicBool::new(false);
static BSP: AtomicUsize = AtomicUsize::new(CPUS);
static SUPERVISOR: AtomicU64 = AtomicU64::new(0);
static ROOT: AtomicU64 = AtomicU64::new(0);
static ENTERED: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static LEFT: [AtomicU64; CPUS] = [const { AtomicU64::new(0) }; CPUS];
static EXIT_RELEASE: AtomicU64 = AtomicU64::new(0);
static FLUSHED: AtomicU64 = AtomicU64::new(0);
static BAD: AtomicBool = AtomicBool::new(false);

struct Armed {
    barrier: ShootdownBarrier<CPUS>,
    round: Round,
}
struct Shared {
    locked: AtomicBool,
    inner: UnsafeCell<Option<Armed>>,
}
// SAFETY: all access is serialized by locked; AP IRQs run IF=0, as does
// the terminal BSP. Nothing waits for remote work while holding this lock.
unsafe impl Sync for Shared {}
static SHARED: Shared = Shared {
    locked: AtomicBool::new(false), inner: UnsafeCell::new(None),
};
struct Unlock;
impl Drop for Unlock {
    fn drop(&mut self) { SHARED.locked.store(false, Ordering::Release); }
}
fn with_state<R>(f: impl FnOnce(&mut Option<Armed>) -> R) -> Option<R> {
    for _ in 0..SPINS {
        if SHARED.locked.compare_exchange(false, true, Ordering::Acquire,
                                          Ordering::Relaxed).is_ok() {
            let _unlock = Unlock;
            return Some(unsafe { f(&mut *SHARED.inner.get()) });
        }
        core::hint::spin_loop();
    }
    None
}
fn root_now() -> u64 { Cr3::read().0.start_address().as_u64() }
fn local_ok() -> bool {
    !x86_64::instructions::interrupts::are_enabled()
        && !Cr4::read().contains(Cr4Flags::PCID)
}
fn wait_mask(bits: &AtomicU64, mask: u64) -> bool {
    for _ in 0..SPINS {
        if BAD.load(Ordering::Acquire) { return false; }
        if bits.load(Ordering::Acquire) & mask == mask { return true; }
        core::hint::spin_loop();
    }
    false
}
pub(crate) fn bsp_index() -> usize { BSP.load(Ordering::Acquire) }
pub(crate) fn ap_mask() -> u64 { ALL ^ (1u64 << bsp_index()) }

pub(crate) fn prepare_bsp(bsp_id: u32, cpus: &[&MpInfo]) -> bool {
    if cpus.len() != CPUS || !local_ok()
        || INITIALIZED.swap(true, Ordering::AcqRel) { return false; }
    let Some(bsp) = cpus.iter().position(|c| c.lapic_id == bsp_id) else {
        return false;
    };
    let supervisor = root_now();
    if supervisor == 0 { return false; }
    BSP.store(bsp, Ordering::Relaxed);
    SUPERVISOR.store(supervisor, Ordering::Relaxed);
    true
}
/// AP only, after all boot work has finished, IF disabled and no PMM use.
pub(crate) fn secondary(index: usize) -> bool {
    let bsp = bsp_index();
    let supervisor = SUPERVISOR.load(Ordering::Relaxed);
    if !INITIALIZED.load(Ordering::Acquire) || index >= CPUS
        || index == bsp || !local_ok() || root_now() != supervisor
    { BAD.store(true, Ordering::Release); return false; }
    let (original, flags) = Cr3::read();
    for _ in 0..SPINS {
        if ROOT.load(Ordering::Acquire) != 0 { break; }
        core::hint::spin_loop();
    }
    let root = ROOT.load(Ordering::Acquire);
    let Ok(frame) = PhysFrame::from_start_address(PhysAddr::new(root)) else {
        BAD.store(true, Ordering::Release);
        return false;
    };
    // SAFETY: BSP reserved this AP in the owner BEFORE publishing ROOT.
    // The ELF root's high kernel half and this permanent stack/IDT are
    // audited and pinned. AP performs no allocations or serial operations.
    unsafe { Cr3::write(frame, flags); }
    let now = root_now();
    ENTERED[index].store(now, Ordering::Release);
    if now != root || !wait_mask(&EXIT_RELEASE, 1u64 << index) {
        // Even a failed observation must restore the boot root, never
        // permit the owner to release the live root.
        unsafe { Cr3::write(original, flags); }
        BAD.store(true, Ordering::Release);
        return false;
    }
    // SAFETY: BSP published retirement before releasing this AP, and no
    // future private load is possible on this isolated terminal worker.
    unsafe { Cr3::write(original, flags); }
    let returned = root_now();
    if returned != supervisor {
        BAD.store(true, Ordering::Release);
        return false;
    }
    LEFT[index].store(returned, Ordering::Release);
    true
}
/// BSP only, after reserving every AP through the exact ELF owner.
/// Every AP independently reads the actual CR3 after its first private load.
pub(crate) fn publish_real_user_root(root: u64, supervisor: u64) -> bool {
    if !INITIALIZED.load(Ordering::Acquire) || !local_ok()
        || root == 0 || root == supervisor || root & 4095 != 0
        || supervisor != SUPERVISOR.load(Ordering::Acquire)
        || ROOT.compare_exchange(0, root, Ordering::Release,
                                 Ordering::Relaxed).is_err() { return false; }
    let aps = ap_mask();
    for _ in 0..SPINS {
        if BAD.load(Ordering::Acquire) { return false; }
        if (0..CPUS).all(|i| aps & (1u64 << i) == 0
            || ENTERED[i].load(Ordering::Acquire) == root) { return true; }
        core::hint::spin_loop();
    }
    false
}
/// Caller alone owns the tickets; it may acknowledge an AP only when its
/// authenticated terminal worker publishes its local post-CR3 observation.
pub(crate) fn release_real_user_root() -> bool {
    if !local_ok() || root_now() != SUPERVISOR.load(Ordering::Acquire)
        || ROOT.load(Ordering::Acquire) == 0 { return false; }
    let aps = ap_mask();
    EXIT_RELEASE.store(aps, Ordering::Release);
    for _ in 0..SPINS {
        if BAD.load(Ordering::Acquire) { return false; }
        if (0..CPUS).all(|i| aps & (1u64 << i) == 0
            || LEFT[i].load(Ordering::Acquire) == SUPERVISOR.load(Ordering::Relaxed)) {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}
fn ack_after_reload(cpu: usize, supervisor: u64) -> bool {
    if cpu >= CPUS || !local_ok() || root_now() != supervisor { return false; }
    with_state(|slot| {
        let Some(state) = slot.as_mut() else { return false; };
        // SAFETY: authenticated CPU physically reloaded supervisor CR3
        // after its exact owner-bound round was published, with PCID off.
        unsafe { state.barrier.acknowledge_after_local_flush(state.round, cpu) }.is_ok()
    }) == Some(true)
}
/// Recipient AP local ID is authenticated by the existing APIC IRQ mapper.
/// IRQ itself always emits the EOI after this callback.
pub(crate) fn on_ipi(cpu: usize) {
    let supervisor = SUPERVISOR.load(Ordering::Relaxed);
    if cpu == bsp_index() || cpu >= CPUS
        || LEFT[cpu].load(Ordering::Acquire) != supervisor
        || !local_ok() || root_now() != supervisor
    {
        BAD.store(true, Ordering::Release);
        return;
    }
    let (original, flags) = Cr3::read();
    // SAFETY: this AP already permanently switched from the live ELF root
    // to the shared pinned supervisor root before enabling local APIC IRQs.
    unsafe { Cr3::write(original, flags); }
    if !ack_after_reload(cpu, supervisor) {
        BAD.store(true, Ordering::Release);
        return;
    }
    FLUSHED.fetch_or(1u64 << cpu, Ordering::Release);
}
/// Real terminal CPL3 EXIT and PID revocation happened before this call.
/// Every AP has restored supervisor CR3 and its owned ticket was drained.
pub(crate) fn finish_owner_round<S: FrameSource, const N: usize>(
    owner: &mut ActiveAddressSpace<'_, S, N, CPUS>,
    pid: u64,
) -> bool {
    let bsp = bsp_index();
    let aps = ap_mask();
    let supervisor = SUPERVISOR.load(Ordering::Acquire);
    let mut barrier = match ShootdownBarrier::<CPUS>::new(pid) {
        Ok(barrier) => barrier, Err(_) => return false,
    };
    let round = match owner.begin_retirement_shootdown(&mut barrier, ALL) {
        Ok(round) => round, Err(_) => return false,
    };
    if with_state(|slot| {
        if slot.is_some() { return false; }
        *slot = Some(Armed { barrier, round });
        true
    }) != Some(true) { return false; }
    let mut ready = false;
    for _ in 0..SPINS {
        if BAD.load(Ordering::Acquire) { return false; }
        if crate::ap_ipi_smoke::retirement_aps_ready(aps) {
            ready = true; break;
        }
        core::hint::spin_loop();
    }
    if !ready { return false; }
    // BSP authenticates its own post-publication CR3 reload.
    if root_now() != supervisor || !local_ok() { return false; }
    let (original, flags) = Cr3::read();
    unsafe { Cr3::write(original, flags); }
    if !ack_after_reload(bsp, supervisor) { return false; }
    FLUSHED.fetch_or(1u64 << bsp, Ordering::Release);

    let Some(last) = (0..CPUS).rev().find(|i| aps & (1u64 << i) != 0) else {
        return false;
    };
    let last_bit = 1u64 << last;
    for cpu in 0..CPUS {
        if aps & !last_bit & (1u64 << cpu) != 0
            && !crate::ap_ipi_smoke::send_retirement_ipi(cpu) { return false; }
    }
    if !wait_mask(&FLUSHED, ALL ^ last_bit)
        || owner.finish_retirement() != Err(OwnerError::OutstandingShootdown)
        || with_state(|state| state.as_mut().is_some_and(|active| {
            active.barrier.snapshot().pending == last_bit
                && !active.barrier.completed(active.round)
                && active.barrier.begin_covering(ALL, ALL) == Err(TlbError::Busy)
        })) != Some(true)
    { return false; }
    if !crate::ap_ipi_smoke::send_retirement_ipi(last)
        || !wait_mask(&FLUSHED, ALL)
        || !crate::ap_ipi_smoke::stop_retirement_aps(aps) { return false; }
    with_state(|slot| {
        let Some(state) = slot.as_ref() else { return false; };
        state.barrier.completed(state.round)
            && state.barrier.snapshot().pending == 0
            && owner.finish_retirement_after_shootdown(&state.barrier, state.round).is_ok()
    }) == Some(true)
}
