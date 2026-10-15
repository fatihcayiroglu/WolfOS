//! P2 QEMU proof: TWO real, independent, PMM-owned 4-level shadow roots.
//!
//! Builds a single executable user leaf and an independent RW+NX leaf using
//! ten physical 4-KiB frames, reached through HHDM. Verifies every ancestor
//! U/S permission, leaf flags, empty kernel half, distinct ownership and
//! full resource release. The ACTIVE CR3 is NEVER changed.

use crate::{pmm, serial, user_vm_layout::{self, ENTRY_COUNT, FRAME_COUNT}};
use x86_64::{registers::control::Cr3, VirtAddr};

const ROOTS: usize = 2;
const TOTAL: usize = ROOTS * FRAME_COUNT;
const TEXT_VA: u64 = 0x401000;
const DATA_VA: u64 = 0x601000;
const TEXT_TAG: u64 = 0x574f_4c46_4f53_5258;
const DATA_TAG: u64 = 0x574f_4c46_4f53_5257;

fn mapped_frame(hhdm: u64, physical: u64) -> Option<*mut u8> {
    let virtual_address = hhdm.checked_add(physical)?;
    Some(VirtAddr::try_new(virtual_address).ok()?.as_mut_ptr::<u8>())
}

fn prove_single(hhdm: u64, frames: [u64; FRAME_COUNT], va: u64,
    write: bool, exec: bool, tag: u64,
) -> bool {
    // The PMM already supplies individually owned 4-KiB aligned frames,
    // but independently prohibit any forged reuse before making references.
    for (i, physical) in frames.iter().copied().enumerate() {
        if physical == 0 || physical % 4096 != 0
            || frames[..i].contains(&physical)
        { return false; }
    }
    let mut pointers = [core::ptr::null_mut::<u8>(); FRAME_COUNT];
    for i in 0..FRAME_COUNT {
        let Some(pointer) = mapped_frame(hhdm, frames[i]) else { return false; };
        pointers[i] = pointer;
    }
    // SAFETY: every pointer is an HHDM address for a different exclusively
    // PMM-allocated physical page. Exactly four table pages and one data
    // page are owned by this BSP until they are freed after prove_single.
    unsafe {
        for page in pointers {
            core::ptr::write_bytes(page, 0, 4096);
        }
        let root = &mut *pointers[0].cast::<[u64; ENTRY_COUNT]>();
        let pdpt = &mut *pointers[1].cast::<[u64; ENTRY_COUNT]>();
        let pd = &mut *pointers[2].cast::<[u64; ENTRY_COUNT]>();
        let pt = &mut *pointers[3].cast::<[u64; ENTRY_COUNT]>();
        if user_vm_layout::populate_one(root, pdpt, pd, pt, frames, va, write, exec).is_err()
            || user_vm_layout::audit_one(root, pdpt, pd, pt, frames, va, write, exec).is_err()
            || root[256..].iter().any(|entry| *entry != 0)
        { return false; }
        // Exercise actual physical memory, but DO NOT execute or grant access.
        pointers[4].cast::<u64>().write_volatile(tag);
        pointers[4].cast::<u64>().read_volatile() == tag
    }
}

pub fn verify(hhdm: u64) -> bool {
    // Caller invokes before SMP startup, with BSP IF=0, no PMM reentry.
    let before = pmm::statistics().allocated_frames;
    let previous_cr3 = Cr3::read().0.start_address().as_u64();
    let mut frames = [0u64; TOTAL];
    let mut acquired = 0usize;
    for slot in &mut frames {
        let Some(physical) = pmm::allocate_frame() else { break; };
        *slot = physical;
        acquired += 1;
    }
    let roots_disjoint = acquired == TOTAL
        && frames.iter().enumerate().all(|(i, frame)|
            *frame != 0 && !frames[..i].contains(frame)
        );
    let mut verified = false;
    if roots_disjoint {
        let first = [frames[0], frames[1], frames[2], frames[3], frames[4]];
        let second = [frames[5], frames[6], frames[7], frames[8], frames[9]];
        verified = prove_single(hhdm, first, TEXT_VA, false, true, TEXT_TAG)
            && prove_single(hhdm, second, DATA_VA, true, false, DATA_TAG);
    }
    let mut released = 0usize;
    let mut release_ok = true;
    for physical in frames[..acquired].iter().rev().copied() {
        if pmm::free_frame(physical).is_ok() {
            released += 1;
        } else {
            release_ok = false;
        }
    }
    let cr3_unchanged = Cr3::read().0.start_address().as_u64() == previous_cr3;
    let accounting = pmm::statistics().allocated_frames == before;
    if !roots_disjoint || !verified || !release_ok || released != TOTAL
        || !cr3_unchanged || !accounting
    {
        serial::write_fmt(format_args!(
            "WOLFOS_USER_ROOT_ERROR owned={} verified={} released={} cr3_unchanged={} accounting={}\n",
            acquired, verified, released, cr3_unchanged, accounting,
        ));
        return false;
    }
    serial::write_line(
        "WOLFOS_USER_ROOT_OK roots=2 pages=2 user=1 rx=1 rw_nx=1 high_half_empty=1 frames_freed=10 cr3_unchanged=1 ring3=0"
    );
    true
}
