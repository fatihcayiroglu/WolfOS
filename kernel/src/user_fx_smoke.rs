//! Real BSP FX hardware test with two independently-owned READY PIDs.
//! Tests FXSAVE64/FXRSTOR64 on the CPU through 64 logical PID handoffs.
//! It does NOT switch a private CR3, enter Ring3, or implement a scheduler.
use x86_64::registers::control::Cr3;
use x86_64::instructions::interrupts;
use crate::{
    fx_state, pmm, serial,
    process_table::{ProcessTable,ProcessState},
    user_fx_bank::{FxImage,UserFxBank,IMAGE_BYTES},
};

const PIDS:usize=2;
const FRAMES:usize=7;
const ROUNDS:usize=64;
const INITIAL:[u64;2]=[
    0x574f_4c46_aabb_cc01,
    0x574f_4c46_dd33_7702,
];

fn fail(reason:&str)->!{
    serial::write_fmt(format_args!("WOLFOS_USER_FX_ERROR {reason}\n"));
    crate::halt_forever()
}
pub fn verify(){
    interrupts::disable();
    if !fx_state::supported(){fail("missing_FXSR_SSE2")}
    let root=Cr3::read().0.start_address().as_u64();
    if root==0 {fail("missing_boot_cr3")}
    let before=pmm::statistics().allocated_frames;
    let mut leases=[[0u64;FRAMES];PIDS];
    for group in &mut leases {
        for p in group {
            *p=pmm::allocate_frame().unwrap_or_else(||fail("pmem_exhausted"));
            if *p==root || *p==0 || *p&4095!=0 {fail("bad_owned_frame")}
        }
    }
    if pmm::statistics().allocated_frames!=before+PIDS*FRAMES{
        fail("frame_accounting")
    }
    let mut processes=ProcessTable::<PIDS,FRAMES>::new();
    for (index,frames) in leases.iter().copied().enumerate(){
        if processes.reserve(frames[0],frames)!=Ok(index as u64+1){
            fail("real_pid_admission")
        }
    }
    if processes.occupied()!=2||processes.running()!=0
        ||processes.owns_live_cr3(root){fail("wrong_active_cr3")}
    let original=unsafe{fx_state::enter()}.unwrap_or_else(||fail("fx_enable"));
    // SAFETY: fx_state::enter() confirmed FXSR and configured BSP CR0/CR4;
    // IF=0 and no other CPU may access these images or BSP FPU registers.
    let baseline=unsafe{FxImage::capture_baseline()};
    if !baseline.aligned(){fail("unaligned_legacy_image")}
    let mut bank=UserFxBank::new();
    let one=bank.prepare(1,&baseline).unwrap_or_else(|_|fail("pid1_seed"));
    let two=bank.prepare(2,&baseline).unwrap_or_else(|_|fail("pid2_seed"));
    let tokens=[one,two];
    let mut state=INITIAL;
    for i in 0..PIDS {
        if bank.seed_xmm0(tokens[i],state[i]).is_err(){
            fail("per_pid_image_seed")
        }
    }
    if bank.occupied()!=2 {
        fail("fx_bank_not_owned")
    }
    serial::write_line(
        "WOLFOS_USER_FX_READY_OK pids=2 owned_pmm_frames=14 images=2 fxsave_bytes=512 aligned=16 bsp_only=1"
    );

    // Activate initial PID's independent FX image.
    let first=unsafe{bank.switch_to(one)}.unwrap_or_else(|_|fail("start_pid1"));
    if first!=state[0] || unsafe{fx_state::read_test_xmm0()}!=state[0] {
        fail("fx_first_restore")
    }
    for step in 0..ROUNDS {
        let current=step%PIDS;
        let next=1-current;
        if bank.active_pid()!=Some(current as u64+1) {
            fail("wrong_current_fx_pid")
        }
        if processes.snapshot(next as u64+1)
            .is_none_or(|p| p.state!=ProcessState::Ready
                || p.cr3_root!=leases[next][0]) {
            fail("wrong_next_fx_pid")
        }
        // Change the LIVE register while this PID is active. Switching to
        // the other PID must FXSAVE the new value, not an old seeded image.
        state[current]=state[current].wrapping_add(
            0x1_0001 + step as u64
        );
        unsafe{fx_state::set_test_xmm0(state[current])};
        let saved=unsafe{bank.switch_to(tokens[next])}
            .unwrap_or_else(|_|fail("fx_hardware_handoff"));
        if saved!=state[next]
            || unsafe{fx_state::read_test_xmm0()}!=state[next]
            || bank.image_xmm0(tokens[current])!=Ok(state[current]){
            fail("cross_pid_register_state")
        }
    }
    serial::write_line(
        "WOLFOS_USER_FX_SWITCH_OK hardware_fxsave=1 hardware_fxrstor=1 alternations=64 xmm0_isolated=1 stale_restore_denied=1"
    );

    let current=bank.active_pid().unwrap_or_else(||fail("lost_active_pid"));
    if current!=1 {fail("unexpected_final_pid")}
    let final_image=unsafe{bank.suspend(one)}.unwrap_or_else(|_|fail("final_fxsave"));
    if final_image!=state[0] || bank.active_pid().is_some()
        || bank.image_xmm0(two)!=Ok(state[1]){
        fail("fx_final_state")
    }
    // IMPORTANT: fully restore original BSP FPU and CR0/CR4 BEFORE
    // retiring per-PID context images or releasing process PMM frames.
    unsafe{fx_state::leave(original)};
    for i in 0..PIDS {
        let pid=i as u64+1;
        let owned=processes.cancel_ready(pid,root)
            .unwrap_or_else(|_|fail("cancel_ready"));
        if owned!=leases[i]{fail("wrong_pmm_owner")}
        if bank.retire_quiescent(tokens[i])!=Ok(true){
            fail("fx_secure_scrub")
        }
        if bank.image_xmm0(tokens[i]).is_ok(){
            fail("stale_fx_token")
        }
        for p in owned {
            if pmm::free_frame(p).is_err(){fail("frame_release")}
        }
    }
    if bank.occupied()!=0 || processes.occupied()!=0
        || pmm::statistics().allocated_frames!=before
        || Cr3::read().0.start_address().as_u64()!=root {
        fail("bsp_fx_process_cleanup")
    }
    serial::write_fmt(format_args!(
        "WOLFOS_USER_FX_CLEANUP_OK released_pmm_frames=14 fx_images_wiped=2 cr3_unchanged=1 bsp_fx_restored=1 no_leak=1 legacy_bytes={} users_executed=0\n",
        IMAGE_BYTES
    ));
}
