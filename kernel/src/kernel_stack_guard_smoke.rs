//! Isolated BSP QEMU: real four-level mapping with TWO absent virtual
//! guard pages bracketing four independently PMM-owned stack leaf frames.
//! The boot HHDM remains; the address is a reserved *lower-half* test slot,
//! not a production upper-half kernel stack or a multi-user task switch.
use core::{arch::asm, sync::atomic::{AtomicBool, Ordering}};
use x86_64::{instructions::{interrupts, tlb}, registers::control::Cr3, VirtAddr};
use crate::{kernel_stack_guard::{
    GuardPlan, OWNED, ENTRIES, PAGE, BASE, LOWER_GUARD, UPPER_GUARD,
    STACK_BOTTOM, STACK_TOP, STACK_PAGES, ROOT_INDEX,
}, pmm, serial};

const LOW_CANARY: u64 = 0x574f_4c46_4752_4431;
const HIGH_CANARY: u64 = 0x574f_4c46_4752_4432;
static ARMED: AtomicBool = AtomicBool::new(false);

fn fail(why: &str) -> ! {
    serial::write_fmt(format_args!("WOLFOS_STACK_GUARD_ERROR {why}\n"));
    crate::halt_forever()
}

fn hhdm_ptr(hhdm: u64, physical: u64) -> *mut [u64; ENTRIES] {
    let va = hhdm.checked_add(physical)
        .and_then(|x| VirtAddr::try_new(x).ok())
        .unwrap_or_else(|| fail("invalid_hhdm_address"));
    va.as_mut_ptr::<[u64; ENTRIES]>()
}

fn target() -> u64 {
    if cfg!(feature = "kernel-stack-guard-upper-fault-smoke") {
        UPPER_GUARD
    } else {
        LOWER_GUARD
    }
}

/// BSP only after full boot, while IF=0 and no AP accesses the reserved
/// virtual slot. Caller has checked the Limine HHDM and PMM are initialized.
/// For the fault flavors, hardware never returns: the dedicated IDT handler
/// asserts CR2 + supervisor/non-present error code and exits QEMU.
pub fn verify(hhdm: u64) {
    interrupts::disable();
    if ARMED.load(Ordering::Acquire) { fail("duplicate_invocation") }
    let (cr3,_) = Cr3::read();
    let boot_root = cr3.start_address().as_u64();
    let before = pmm::statistics().allocated_frames;
    if boot_root == 0 || ROOT_INDEX >= 256 || BASE & (PAGE-1) != 0 {
        fail("invalid_root_or_reserved_slot")
    }
    // SAFETY: the active boot PML4 belongs to the BSP; this feature is
    // isolated, maskable IRQs are off and no AP can mutate this reserved
    // lower-half slot. We only *read* the root before admission.
    let root_addr = hhdm_ptr(hhdm,boot_root);
    if unsafe { (*root_addr)[ROOT_INDEX] } != 0 { fail("slot_already_mapped") }

    let mut owned = [0u64; OWNED];
    for p in owned.iter_mut() {
        *p = pmm::allocate_frame().unwrap_or_else(|| fail("physical_frame"));
    }
    let plan = GuardPlan::new(owned,boot_root)
        .unwrap_or_else(|_| fail("pmm_alias_or_alignment"));
    if pmm::statistics().allocated_frames != before+OWNED {
        fail("untracked_allocations")
    }

    // SAFETY: PMM granted exclusive, distinct 4KiB physical frames and
    // HHDM provides their direct map. They are not published as page
    // tables until the final PML4 store inside populate().
    unsafe {
        for &p in &owned[..3] {
            core::ptr::write_bytes(hhdm_ptr(hhdm,p).cast::<u8>(),0,PAGE as usize);
        }
        let root=&mut *root_addr;
        let pdpt=&mut *hhdm_ptr(hhdm,owned[0]);
        let pd=&mut *hhdm_ptr(hhdm,owned[1]);
        let pt=&mut *hhdm_ptr(hhdm,owned[2]);
        plan.populate(root,pdpt,pd,pt)
            .unwrap_or_else(|_| fail("populate"));
        plan.audit(root,pdpt,pd,pt)
            .unwrap_or_else(|_| fail("independent_pte_audit"));
    }
    // TLB invalidations force hardware to re-walk rather than use any
    // former negative-translation cache entry at the reserved slot.
    for i in 0..=5 {
        tlb::flush(VirtAddr::new(BASE + i as u64*PAGE));
    }
    // SAFETY: the four stack VAs were freshly mapped to separate PMM
    // pages as supervisor RW leaves, with an independently audited PTE.
    unsafe {
        (STACK_BOTTOM as *mut u64).write_volatile(LOW_CANARY);
        ((STACK_TOP-8) as *mut u64).write_volatile(HIGH_CANARY);
        if (STACK_BOTTOM as *const u64).read_volatile() != LOW_CANARY
            || ((STACK_TOP-8) as *const u64).read_volatile() != HIGH_CANARY {
            fail("mapped_stack_write_read")
        }
        let first=hhdm_ptr(hhdm,owned[3]).cast::<u64>();
        let last=hhdm_ptr(hhdm,owned[6]).cast::<u64>();
        if first.read_volatile()!=LOW_CANARY
            || last.add(PAGE as usize/8-1).read_volatile()!=HIGH_CANARY {
            fail("leaf_to_hhdm_phys_alias")
        }
    }
    serial::write_line(
        "WOLFOS_STACK_GUARD_MAP_OK mapped_pages=4 physical_leaf_pages=4 table_pages=3 guard_pages=2 supervisor=1 user=0"
    );

    #[cfg(any(feature = "kernel-stack-guard-fault-smoke",
              feature = "kernel-stack-guard-upper-fault-smoke"))]
    {
        ARMED.store(true,Ordering::Release);
        serial::write_fmt(format_args!(
            "WOLFOS_STACK_GUARD_PROBE_BEGIN side={} address={:#x} expected_pf=nonpresent_supervisor_read\n",
            if cfg!(feature="kernel-stack-guard-upper-fault-smoke") {"upper"} else {"lower"},
            target()
        ));
        // SAFETY: this is an EXPECTED #PF against an intentionally absent
        // PTE, executed exclusively in disposable QEMU. Never a Rust
        // pointer dereference, never touches the active supervisor RSP.
        unsafe {
            asm!("mov rax, qword ptr [rax]",
                inout("rax") target() => _,
                options(nostack,readonly,preserves_flags));
        }
        fail("guard_read_did_not_fault")
    }

    #[cfg(feature = "kernel-stack-guard-smoke")]
    {
        // No CPU still uses these as a stack or trap landing site.
        // Drop the PML4 mapping, invalidate every previously mapped VA,
        // then return ALL owned page-table and leaf frames to PMM.
        unsafe {
            let root=&mut *root_addr;
            let pdpt=&mut *hhdm_ptr(hhdm,owned[0]);
            let pd=&mut *hhdm_ptr(hhdm,owned[1]);
            let pt=&mut *hhdm_ptr(hhdm,owned[2]);
            plan.unpublish(root,pdpt,pd,pt)
                .unwrap_or_else(|_| fail("unpublish"));
        }
        for i in 0..=5 {
            tlb::flush(VirtAddr::new(BASE+i as u64*PAGE));
        }
        // SAFETY: after the PML4 removal and TLB invalidation, these
        // physical pages have no live mappings in the new subtree; their
        // boot HHDM aliases are not used for anything else.
        for physical in owned {
            if pmm::free_frame(physical).is_err() { fail("pmm_frame_free") }
        }
        if pmm::statistics().allocated_frames != before
            || Cr3::read().0.start_address().as_u64()!=boot_root
            || unsafe{(*root_addr)[ROOT_INDEX]}!=0 {
            fail("nonzero_leak_or_stale_root")
        }
        serial::write_line(
            "WOLFOS_STACK_GUARD_REAP_OK physical_frames_freed=7 pmm_no_leak=1 boot_cr3_intact=1 tlb_flushed=1"
        );
    }
}

/// Read-only CPU fault-evidence verification. Nothing outside an armed
/// disposable-QEMU negative flavor can turn a #PF into a success.
#[cfg(any(feature = "kernel-stack-guard-fault-smoke",
          feature = "kernel-stack-guard-upper-fault-smoke"))]
pub fn expected_fault(cr2: u64, error: u64, rip: u64) -> bool {
    ARMED.load(Ordering::Acquire)
        && cr2 == target()
        && error == 0 // P=0 W/R=0 U/S=0 RSVD=0 I/D=0
        && rip >= 0xffff_8000_0000_0000
}
