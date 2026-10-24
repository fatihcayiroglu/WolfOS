//! Feature-isolated QEMU proof of real per-AP INVLPG before a TLB barrier ack.
//!
//! The BSP publishes a generation/epoch-tagged round and sends hardware fixed
//! IPIs. The *receiving* AP, identified by local xAPIC ID in the IRQ handler,
//! checks its CR3, invalidates a still-present shared supervisor MMIO alias,
//! and only then acknowledges its own bit under one non-allocating lock.
//! This tests an instruction/ack ordering boundary, NOT Ring3 unmap, PCID,
//! global invalidation, retired-context exclusion, or permission to free frames.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::registers::control::{Cr3, Cr4, Cr4Flags};
use crate::tlb_shootdown::{Round, ShootdownBarrier};

const CPUS: usize = 4;
const GENERATION: u64 = 51;
const MMIO_ALIAS_VA: u64 = crate::ap_ipi_smoke::VA;

struct ActiveRound {
    barrier: ShootdownBarrier<CPUS>,
    round: Round,
    root: u64,
    targets: u64,
    acks: u64,
    invlpg: u64,
    per_cpu: [u64; CPUS],
    bad: bool,
}

struct Shared {
    held: AtomicBool,
    inner: UnsafeCell<Option<ActiveRound>>,
}
// SAFETY: every access to inner is serialized by held (Acquire/Release).
// BSP runs with IF=0; recipient IRQ runs with IF=0 and is non-reentrant on
// its own AP. The lock is never held while BSP waits for remote work.
unsafe impl Sync for Shared {}

static STATE: Shared = Shared {
    held: AtomicBool::new(false),
    inner: UnsafeCell::new(None),
};

struct Unlock;
impl Drop for Unlock {
    fn drop(&mut self) {
        STATE.held.store(false, Ordering::Release);
    }
}

fn with_state<T>(f: impl FnOnce(&mut Option<ActiveRound>) -> T) -> T {
    while STATE.held.compare_exchange_weak(
        false, true, Ordering::Acquire, Ordering::Relaxed,
    ).is_err() {
        core::hint::spin_loop();
    }
    let _unlock = Unlock;
    // SAFETY: Acquire successfully took sole ownership of this cell until
    // _unlock publishes Release; neither CPU waits for IPI while locked.
    unsafe { f(&mut *STATE.inner.get()) }
}

fn pcid_disabled() -> bool {
    !Cr4::read().contains(Cr4Flags::PCID)
}

pub(crate) fn arm(targets: u64, root: u64) -> bool {
    if x86_64::instructions::interrupts::are_enabled()
        || !pcid_disabled() || root == 0 || targets.count_ones() != 3
        || targets & !0b1111 != 0
    {
        return false;
    }
    with_state(|slot| {
        if slot.is_some() { return false; }
        let Ok(mut barrier) = ShootdownBarrier::<CPUS>::new(GENERATION)
        else { return false; };
        let Ok(round) = barrier.begin(targets) else { return false; };
        *slot = Some(ActiveRound {
            barrier, round, root, targets, acks: 0, invlpg: 0,
            per_cpu: [0; CPUS], bad: false,
        });
        true
    })
}

/// Only called in the AP's real fixed-vector interrupt after xAPIC ID lookup.
pub(crate) fn on_ipi(cpu: usize) {
    with_state(|slot| {
        let Some(run) = slot.as_mut() else { return; };
        if cpu >= CPUS || (run.targets & (1u64 << cpu)) == 0
            || !pcid_disabled()
            || Cr3::read().0.start_address().as_u64() != run.root
            || (run.barrier.snapshot().pending & (1u64 << cpu)) == 0
        {
            run.bad = true;
            return;
        }
        // SAFETY: This code runs on the authenticated recipient AP with
        // interrupts disabled. The fixed UC supervisor APIC MMIO alias is
        // mapped before AP launch and remains mapped through QEMU exit.
        // INVLPG invalidates the recipient's local translation for this
        // particular 4-KiB page; it cannot flush arbitrary PCID/global data.
        unsafe {
            core::arch::asm!(
                "invlpg [{address}]",
                address = in(reg) MMIO_ALIAS_VA,
                options(nostack, preserves_flags),
            );
        }
        // SAFETY: This exact AP executed the architectural local INVLPG,
        // with PCID off and its expected CR3 loaded. The same lock exposes
        // the current published generation/epoch and serializes each ack.
        if unsafe { run.barrier.acknowledge_after_local_flush(run.round, cpu) }.is_err() {
            run.bad = true;
            return;
        }
        run.invlpg += 1;
        run.acks += 1;
        run.per_cpu[cpu] += 1;
    });
}

pub(crate) fn completed() -> bool {
    with_state(|slot| slot.as_ref().is_some_and(|run|
        !run.bad && run.barrier.completed(run.round)
    ))
}

/// The BSP starts a second generation-tagged epoch only after the first
/// round is complete. Re-entry cannot be inferred from IPI delivery alone.
pub(crate) fn begin_next() -> bool {
    with_state(|slot| {
        let Some(run) = slot.as_mut() else { return false; };
        if run.bad || !run.barrier.completed(run.round) { return false; }
        let Ok(round) = run.barrier.begin(run.targets) else { return false; };
        run.round = round;
        true
    })
}

#[derive(Clone, Copy)]
pub(crate) struct Evidence {
    pub(crate) epoch: u64,
    pub(crate) targets: u64,
    pub(crate) pending: u64,
    pub(crate) acks: u64,
    pub(crate) invlpg: u64,
    pub(crate) per_cpu: [u64; CPUS],
    pub(crate) bad: bool,
    pub(crate) completed: bool,
}

pub(crate) fn evidence() -> Option<Evidence> {
    with_state(|slot| slot.as_ref().map(|run| {
        let snapshot = run.barrier.snapshot();
        Evidence {
            epoch: snapshot.epoch,
            targets: run.targets,
            pending: snapshot.pending,
            acks: run.acks,
            invlpg: run.invlpg,
            per_cpu: run.per_cpu,
            bad: run.bad,
            completed: run.barrier.completed(run.round),
        }
    }))
}
