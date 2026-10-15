//! BSP-only hardware acceptance for the FIRST synchronized CR3,
//! TSS.RSP0 and legacy FXSAVE64 per-PID handoff checkpoint.
//! NO CPL3 instruction executes; IRET frames are bootstrap metadata, not
//! runnable until all ELF/PTE and actual trap lifecycle checks are complete.
use core::arch::asm;
use x86_64::{VirtAddr, instructions::{interrupts,tlb}, registers::control::Cr3};
use crate::{
    high_half_stack_arena::{
        GuardedArena,Handle,PT_ENTRIES,OWNED as ARENA_FRAMES,
        PAGE,BASE,ROOT_INDEX,SLOTS as ARENA_SLOTS,
    },
    process_table::ProcessTable,process_lifecycle::ProcessState,
    user_context_bank::{UserContextBank,KernelStack},
    user_syscall_abi::UserSyscallFrame,
    user_fx_bank::{FxImage,UserFxBank},fx_state,
    interrupts,kernel_half_shadow,pmm,serial,
};
const PIDS:usize=2;
const PROCESS_PAGES:usize=7;
const ALL_PAGES:usize=ARENA_FRAMES+PIDS*PROCESS_PAGES;
const XMM:[u64;PIDS]=[0x4743_5233_0000_1001,0x4743_5233_0000_2002];
fn fail(msg:&str)->!{
    serial::write_fmt(format_args!("WOLFOS_HANDOFF_ERROR {msg}\n"));
    crate::halt_forever()
}
fn table(hhdm:u64,pa:u64)->*mut [u64;PT_ENTRIES]{
    let va=hhdm.checked_add(pa).and_then(|v|VirtAddr::try_new(v).ok())
        .unwrap_or_else(||fail("bad_hhdm"));
    va.as_mut_ptr::<[u64;PT_ENTRIES]>()
}
fn frame(entry:u64,rsp:u64,cs:u16,ss:u16,tag:u64)->UserSyscallFrame{
    let mut f=UserSyscallFrame::default();
    f.hardware.rip=entry;
    f.hardware.rsp=rsp;
    f.hardware.cs=cs as u64;
    f.hardware.ss=ss as u64;
    f.hardware.rflags=2;
    f.registers.r12=tag;
    f
}
pub fn verify(hhdm:u64){
    interrupts::disable();
    if !interrupts::verify_ring3_preconditions() {
        fail("boot_tss_or_selectors")
    }
    if !fx_state::supported(){fail("no_cpuid_fxsr")}
    let boot=Cr3::read().0.start_address().as_u64();
    let original_rsp0=interrupts::test_actual_rsp0();
    if boot==0||original_rsp0==0 {fail("invalid_boot_context")}
    let initial=pmm::statistics().allocated_frames;
    let boot_table=table(hhdm,boot);
    if ROOT_INDEX<256||ROOT_INDEX>=511
        ||unsafe{(*boot_table)[ROOT_INDEX]}!=0{
        fail("arena_root_slot_busy")
    }

    let mut physical=[0u64;ALL_PAGES];
    for i in 0..ALL_PAGES{
        physical[i]=pmm::allocate_frame().unwrap_or_else(||fail("pmem"));
        if physical[i]==boot||physical[i]==0||physical[i]&4095!=0
            ||physical[..i].contains(&physical[i]){
            fail("bad_frame_or_boot_alias")
        }
    }
    if pmm::statistics().allocated_frames!=initial+ALL_PAGES{
        fail("allocation_baseline")
    }
    let mut arena=GuardedArena::new(
        [physical[0],physical[1],physical[2]],boot
    ).unwrap_or_else(|_|fail("arena_admission"));
    let mut stacks=[None;PIDS];
    let mut leases=[[0u64;PROCESS_PAGES];PIDS];
    let mut processes=ProcessTable::<PIDS,PROCESS_PAGES>::new();
    let mut contexts=UserContextBank::<PIDS>::new();
    let mut fxs=UserFxBank::new();
    let (user_cs,user_ss,_)=interrupts::ring3_cpu_state();
    let mut handles=[None;PIDS];
    for i in 0..PIDS{
        let start=3+i*4;
        let lease=arena.reserve((i+1) as u64,
            [physical[start],physical[start+1],physical[start+2],physical[start+3]])
            .unwrap_or_else(|_|fail("arena_pid"));
        stacks[i]=Some(lease);
        let offset=ARENA_FRAMES+i*PROCESS_PAGES;
        leases[i].copy_from_slice(&physical[offset..offset+PROCESS_PAGES]);
        let pid=processes.reserve(leases[i][0],leases[i])
            .unwrap_or_else(|_|fail("root_pid"));
        if pid!=(i+1) as u64{fail("pid_generation")}
        let synthetic=frame(0x401000+i as u64*0x1000,
            0x405000,user_cs,user_ss,XMM[i]);
        contexts.prepare_bootstrap(&processes,pid,leases[i][0],
            KernelStack{bottom:lease.bottom,top:lease.top},synthetic)
            .unwrap_or_else(|_|fail("context_pid"));
    }
    // SAFETY: all table frames and root pages are exclusively held by PMM,
    // unused as CR3/RSP0, and BSP remains on its original boot kernel stack.
    unsafe{
        for &p in &physical[..3]{
            core::ptr::write_bytes(table(hhdm,p).cast::<u8>(),0,PAGE as usize);
        }
        arena.publish(&mut *boot_table,&mut *table(hhdm,physical[0]),
            &mut *table(hhdm,physical[1]),&mut *table(hhdm,physical[2]))
            .unwrap_or_else(|_|fail("map_high_half"));
        arena.audit(&*boot_table,&*table(hhdm,physical[0]),
            &*table(hhdm,physical[1]),&*table(hhdm,physical[2]))
            .unwrap_or_else(|_|fail("audit_guard_ptes"));
    }
    for i in 0..12{
        tlb::flush(VirtAddr::new(BASE+i*PAGE));
    }
    for i in 0..PIDS{
        // A private root inherits all supervisor kernel mappings, including
        // the independently guard-mapped high-half stack arena. The sole
        // lower-half entry points to a ZERO private PDPT; no user ELF is
        // installed or made executable by this proof.
        let owned=leases[i];
        unsafe{
            for pa in owned{
                core::ptr::write_bytes(table(hhdm,pa).cast::<u8>(),0,PAGE as usize);
            }
            let shadow=&mut *table(hhdm,leases[i][0]);
            shadow[1]=leases[i][1]|7;
            let src=&*boot_table;
            let copied=kernel_half_shadow::graft_kernel_half(
                src,shadow,1,leases[i][1]|7,&leases[i])
                .unwrap_or_else(|_|fail("kernel_graft"));
            if copied<1||
                kernel_half_shadow::audit_kernel_half(
                    src,shadow,1,leases[i][1]|7,&leases[i]
                )!=Ok(copied)||
                shadow[ROOT_INDEX]==0||
                shadow[ROOT_INDEX]&4!=0 {
                fail("sanitized_kernel_root_or_guard")
            }
        }
    }
    let control=unsafe{fx_state::enter()}
        .unwrap_or_else(||fail("fx_enable"));
    let original_fx=unsafe{FxImage::capture_baseline()};
    for i in 0..PIDS {
        let h=fxs.prepare((i+1) as u64,&original_fx)
            .unwrap_or_else(|_|fail("fx_pid_admission"));
        fxs.seed_xmm0(h,XMM[i]).unwrap_or_else(|_|fail("fx_seed"));
        handles[i]=Some(h);
    }
    serial::write_line(
        "WOLFOS_HANDOFF_SETUP_OK ready_pids=2 private_roots=2 guarded_rsp0=2 fx_images=2 real_pmm_frames=25"
    );
    let mut markers=XMM;
    for step in 0..64{
        let i=step%PIDS;
        let current=processes.snapshot((i+1) as u64)
            .unwrap_or_else(||fail("pid_missing"));
        if current.state!=ProcessState::Ready||
            current.cr3_root!=leases[i][0]{
            fail("wrong_process_state")
        }
        let plan=contexts.plan_next(&processes,(2-i) as u64,boot)
            .unwrap_or_else(|_|fail("resume_plan"));
        let stack=stacks[i].unwrap_or_else(||fail("stack_missing"));
        if plan.pid!=(i+1) as u64 ||plan.cr3_root!=leases[i][0]
            ||plan.rsp0!=stack.top ||plan.frame.registers.r12!=XMM[i]{
            fail("per_pid_gpr_rsp0_plan")
        }
        if !unsafe{interrupts::test_handoff_rsp0(stack.top)}{
            fail("hardware_tss_write")
        }
        // We are on the BOOT supervisor stack; the high-half stack is
        // MAPPED in the selected root, but not currently active RSP.
        unsafe{
            asm!("mov cr3, {}",in(reg) leases[i][0],
                options(nostack,preserves_flags));
        }
        let read_cr3=Cr3::read().0.start_address().as_u64();
        if read_cr3!=leases[i][0]||
            interrupts::test_actual_rsp0()!=stack.top{
            fail("actual_cr3_or_tss_mismatch")
        }
        let observed=unsafe{fxs.switch_to(handles[i].unwrap())}
            .unwrap_or_else(|_|fail("fx_handoff"));
        if observed!=markers[i]||
            unsafe{fx_state::read_test_xmm0()}!=markers[i]{
            fail("cross_pid_xmm")
        }
        // Change CPU XMM0 while PID i's state is currently loaded.
        markers[i]=markers[i].wrapping_add(0x17+step as u64);
        unsafe{fx_state::set_test_xmm0(markers[i])};
        // Restore boot address space before inspecting next PID plan,
        // before unmapping any frame or retiring any PID-owned resource.
        unsafe{
            asm!("mov cr3, {}",in(reg) boot,
                options(nostack,preserves_flags));
        }
        if Cr3::read().0.start_address().as_u64()!=boot {
            fail("boot_cr3_not_restored")
        }
    }
    // Final PID2 is currently loaded, suspend and preserve it before
    // restoring the original BSP FPU control/state (CR0/CR4).
    if fxs.active_pid()!=Some(2) {fail("last_fx_pid")}
    if unsafe{fxs.suspend(handles[1].unwrap())}!=Ok(markers[1])
        || fxs.image_xmm0(handles[0].unwrap())!=Ok(markers[0]){
        fail("final_fx_frame")
    }
    unsafe{fx_state::leave(control)};
    if !unsafe{interrupts::test_handoff_rsp0(original_rsp0)}
        ||interrupts::test_actual_rsp0()!=original_rsp0{
        fail("restore_original_tss")
    }
    serial::write_line(
        "WOLFOS_HANDOFF_HARDWARE_OK rounds=64 real_cr3_writes=128 real_tss_rsp0=64 real_fx_switches=64 gpr_plan=64 cpl3_executions=0"
    );
    // No hardware state references any borrowed user frame at this point.
    for i in 0..PIDS{
        let pid=(i+1) as u64;
        let released=processes.cancel_ready(pid,boot)
            .unwrap_or_else(|_|fail("cancel_pid"));
        if released!=leases[i]||
            contexts.retire(&processes,pid).is_err()||
            fxs.retire_quiescent(handles[i].unwrap())!=Ok(true){
            fail("pid_context_retirement")
        }
    }
    unsafe{
        arena.unpublish(&mut *boot_table,
            &mut *table(hhdm,physical[0]),
            &mut *table(hhdm,physical[1]),
            &mut *table(hhdm,physical[2]))
            .unwrap_or_else(|_|fail("unpublish_guards"));
    }
    for i in 0..12 {tlb::flush(VirtAddr::new(BASE+i*PAGE));}
    for i in 0..PIDS{
        // SAFETY: all CPUs stopped, roots no longer loaded, TSS and BSP RSP
        // point to original supervisor stack, all virtual TLBs flushed.
        let frames=unsafe{arena.retire_after_quiescence(
            stacks[i].unwrap().handle)}
            .unwrap_or_else(|_|fail("retire_guards"));
        if frames!=stacks[i].unwrap().frames{fail("stack_owned_frames")}
    }
    for p in physical{
        if pmm::free_frame(p).is_err(){fail("release_frame")}
    }
    if processes.occupied()!=0||contexts.count()!=0||
        fxs.occupied()!=0||arena.occupied()!=0||
        pmm::statistics().allocated_frames!=initial||
        interrupts::test_actual_rsp0()!=original_rsp0||
        Cr3::read().0.start_address().as_u64()!=boot||
        unsafe{(*boot_table)[ROOT_INDEX]}!=0{
        fail("cleanup_invariants")
    }
    serial::write_line(
        "WOLFOS_HANDOFF_CLEANUP_OK frames_freed=25 cr3_restored=1 tss_restored=1 fx_restored=1 stale_pids_revoked=1 pmm_leak=0"
    );
}
