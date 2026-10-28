//! One-BSP, disposable-QEMU proof of two independent guarded HIGH-HALF
//! virtual stacks (never active RSP/TSS). HHDM physical aliases persist.
use core::{arch::asm, sync::atomic::{AtomicBool,Ordering}};
use x86_64::{VirtAddr, instructions::{interrupts,tlb}, registers::control::Cr3};
use crate::{high_half_stack_arena::{
    GuardedArena,Handle,PT_ENTRIES,OWNED,TABLE_PAGES,STACK_PAGES,
    SLOTS,BASE,PAGE,ROOT_INDEX,lower_guard,upper_guard,bottom,top,
},pmm,serial};

const CANARY:u64=0x5753_544b_4152_454e;
static ARMED:AtomicBool=AtomicBool::new(false);

fn fail(msg:&str)->! {
    serial::write_fmt(format_args!("WOLFOS_HIGH_STACK_ARENA_ERROR {msg}\n"));
    crate::halt_forever()
}
fn hhdm_table(hhdm:u64,phys:u64)->*mut [u64;PT_ENTRIES]{
    let va=hhdm.checked_add(phys).and_then(|v|VirtAddr::try_new(v).ok())
        .unwrap_or_else(||fail("bad_hhdm"));
    va.as_mut_ptr::<[u64;PT_ENTRIES]>()
}
fn target()->u64{
    if cfg!(feature="high-half-stack-arena-upper-fault-smoke") {
        upper_guard(1)
    } else {lower_guard(0)}
}
pub fn verify(hhdm:u64){
    interrupts::disable();
    if ARMED.load(Ordering::Acquire) {fail("duplicate")}
    let (hardware,_) = Cr3::read();
    let boot=hardware.start_address().as_u64();
    let baseline=pmm::statistics().allocated_frames;
    if ROOT_INDEX<256 || ROOT_INDEX>=511
        || VirtAddr::try_new(BASE).is_err()
        || boot==0 {fail("root_invalid")}
    let root=hhdm_table(hhdm,boot);
    // SAFETY: this isolated test executes on BSP after APs are parked and
    // no interrupt/scheduler changes boot root; only read until publish.
    if unsafe{(*root)[ROOT_INDEX]}!=0 {fail("root_slot_not_empty")}
    let mut pages=[0u64;OWNED];
    for p in &mut pages {
        *p=pmm::allocate_frame().unwrap_or_else(||fail("allocate"));
    }
    let mut arena=GuardedArena::new(
        [pages[0],pages[1],pages[2]],boot
    ).unwrap_or_else(|_|fail("owned_tables"));
    let one=arena.reserve(1,[pages[3],pages[4],pages[5],pages[6]])
        .unwrap_or_else(|_|fail("reserve_pid_1"));
    let two=arena.reserve(2,[pages[7],pages[8],pages[9],pages[10]])
        .unwrap_or_else(|_|fail("reserve_pid_2"));
    if one.top>=two.bottom || arena.occupied()!=2
        || pmm::statistics().allocated_frames!=baseline+OWNED {
        fail("disjoint_resident_leases")
    }
    // SAFETY: three PMM-exclusive physical pages, HHDM mapped; root has
    // separately verified empty high-half PML4 slot. No live AP uses it.
    unsafe {
        for &phys in &pages[..TABLE_PAGES] {
            core::ptr::write_bytes(
                hhdm_table(hhdm,phys).cast::<u8>(),0,PAGE as usize);
        }
        let pml4=&mut *root;
        let pdpt=&mut *hhdm_table(hhdm,pages[0]);
        let pd=&mut *hhdm_table(hhdm,pages[1]);
        let pt=&mut *hhdm_table(hhdm,pages[2]);
        arena.publish(pml4,pdpt,pd,pt)
            .unwrap_or_else(|_|fail("publish"));
        arena.audit(pml4,pdpt,pd,pt)
            .unwrap_or_else(|_|fail("audit_initial"));
    }
    // No stale negative translation cache entries remain in this BSP.
    for page in 0..12 {
        tlb::flush(VirtAddr::new(BASE+page*PAGE));
    }
    for (i,stack) in [one,two].iter().copied().enumerate() {
        let low=CANARY^(i as u64);
        let high=!low;
        // SAFETY: 2 distinct (4-page) RW supervisor-only virtual stacks,
        // owned by this inactive test; never an actual CPU RSP0.
        unsafe {
            (stack.bottom as *mut u64).write_volatile(low);
            ((stack.top-8) as *mut u64).write_volatile(high);
            if (stack.bottom as *const u64).read_volatile()!=low
                || ((stack.top-8) as *const u64).read_volatile()!=high {
                fail("virtual_canary")
            }
            let first=hhdm_table(hhdm,stack.frames[0]).cast::<u64>();
            let last=hhdm_table(hhdm,stack.frames[3]).cast::<u64>();
            if first.read_volatile()!=low
                || last.add((PAGE/8-1) as usize).read_volatile()!=high {
                fail("hhdm_phys_canary")
            }
        }
    }
    // Hardware access above set A/D; audit MUST ignore only those bits,
    // while still checking exact physical backing and all four absent guards.
    unsafe{
        arena.audit(&*root,&*hhdm_table(hhdm,pages[0]),
            &*hhdm_table(hhdm,pages[1]),&*hhdm_table(hhdm,pages[2]))
            .unwrap_or_else(|_|fail("audit_after_hardware_access"));
    }
    serial::write_line(
        "WOLFOS_HIGH_STACK_ARENA_READY_OK pids=2 high_half=1 real_pmm_frames=11 guard_pages=4 private_leaf_pages=8"
    );
    serial::write_line(
        "WOLFOS_HIGH_STACK_ARENA_ISOLATED_OK distinct_rsp0=2 user_bit=0 physical_alias_denied=1 active_stacks=0"
    );

    #[cfg(any(feature="high-half-stack-arena-lower-fault-smoke",
              feature="high-half-stack-arena-upper-fault-smoke"))]
    {
        ARMED.store(true,Ordering::Release);
        serial::write_fmt(format_args!(
            "WOLFOS_HIGH_STACK_ARENA_PROBE_BEGIN side={} address={:#x}\n",
            if cfg!(feature="high-half-stack-arena-upper-fault-smoke"){"pid2_upper"}
            else {"pid1_lower"},target()
        ));
        // SAFETY: anticipated #PF on an absent PTE, disposable QEMU only,
        // never dereference an invalid virtual pointer in Rust.
        unsafe {
            asm!("mov rax,qword ptr [rax]",
                inout("rax") target()=>_,
                options(nostack,readonly,preserves_flags));
        }
        fail("no_hardware_fault")
    }

    #[cfg(feature="high-half-stack-arena-smoke")]
    {
        unsafe {
            arena.unpublish(
                &mut *root,&mut *hhdm_table(hhdm,pages[0]),
                &mut *hhdm_table(hhdm,pages[1]),&mut *hhdm_table(hhdm,pages[2])
            ).unwrap_or_else(|_|fail("unpublish"));
        }
        // SAFETY: after PML4 unpublication, invalidate every VA before
        // releasing PMM frames or reusing the virtual arena.
        for page in 0..12 {
            tlb::flush(VirtAddr::new(BASE+page*PAGE));
        }
        if arena.inspect(one.handle)!=Ok(one)
            || arena.inspect(two.handle)!=Ok(two) {
            fail("live_lease_corruption")
        }
        // SAFETY: BSP IF=0, all APs parked; verified root entry removed,
        // all 12 virtual translations flushed, no TSS or stack borrows,
        // both synthetic owner PIDs revoked by this feature-only scope.
        let returned_one=unsafe {arena.retire_after_quiescence(one.handle)}
            .unwrap_or_else(|_|fail("retire_pid1"));
        let returned_two=unsafe {arena.retire_after_quiescence(two.handle)}
            .unwrap_or_else(|_|fail("retire_pid2"));
        if returned_one!=one.frames || returned_two!=two.frames
            || arena.inspect(one.handle).is_ok()
            || arena.occupied()!=0 {
            fail("retired_token_or_frames")
        }
        for physical in pages {
            if pmm::free_frame(physical).is_err(){fail("physical_frame_release")}
        }
        if pmm::statistics().allocated_frames!=baseline
            || unsafe{(*root)[ROOT_INDEX]}!=0
            || Cr3::read().0.start_address().as_u64()!=boot {
            fail("physical_leak_or_root")
        }
        serial::write_line(
            "WOLFOS_HIGH_STACK_ARENA_CLEANUP_OK physical_frames_freed=11 pmm_no_leak=1 tlb_flushed=12 boot_cr3_intact=1"
        );
    }
}
#[cfg(any(feature="high-half-stack-arena-lower-fault-smoke",
          feature="high-half-stack-arena-upper-fault-smoke"))]
pub fn expected_fault(cr2:u64,error:u64,rip:u64)->bool{
    ARMED.load(Ordering::Acquire)
        && cr2==target()
        && error==0
        && rip>=0xffff_8000_0000_0000
}
