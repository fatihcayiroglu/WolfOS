//! Actual QEMU + PMM preflight for PID-owned, whole saved user trap frames.
//! Two separate 7-frame leases and two real kernel-address RSP0 stack
//! allocations are checked; 64 alternating plans are produced and exact
//! stored GPR values observed, WITHOUT switching hardware CR3/TSS/IRETQ.
//! This feature NEVER claims two actual CPL3 tasks were scheduled.
use x86_64::registers::control::Cr3;
use crate::{
    pmm, serial, process_table::ProcessTable,
    user_context_bank::{KernelStack, UserContextBank, KSTACK_BYTES},
    user_syscall_abi::UserSyscallFrame,
};

const FRAMES: usize = 7;
const USERS: usize = 2;
const STACK_BYTES: usize = KSTACK_BYTES as usize;

#[repr(align(16))]
struct Stack([u8; STACK_BYTES]);
static KERNEL_STACKS: [Stack; USERS] =
    [const { Stack([0; STACK_BYTES]) }; USERS];

fn fail(reason: &str) -> ! {
    serial::write_fmt(format_args!("WOLFOS_USER_CONTEXT_ERROR {reason}\n"));
    crate::halt_forever()
}

fn stack(id: usize) -> KernelStack {
    let base = core::ptr::addr_of!(KERNEL_STACKS[id]) as u64;
    KernelStack { bottom: base, top: base + KSTACK_BYTES }
}

fn bootstrap(rip: u64, marker: u64) -> UserSyscallFrame {
    let mut frame = UserSyscallFrame::default();
    frame.hardware.rip = rip;
    frame.hardware.rsp = 0x405000;
    // These are synthetic bootstrap selectors, NOT actual GDT evidence.
    frame.hardware.cs = 0x2b;
    frame.hardware.ss = 0x23;
    frame.hardware.rflags = 0x2;
    frame.registers.r12 = marker;
    frame.registers.r13 = marker ^ u64::MAX;
    frame.registers.rax = 1;
    frame
}

pub fn verify() {
    let (actual, _) = Cr3::read();
    let boot_cr3 = actual.start_address().as_u64();
    if boot_cr3 == 0 { fail("invalid_boot_cr3") }
    let baseline = pmm::statistics().allocated_frames;
    let mut lease = [[0u64; FRAMES]; USERS];
    for i in 0..USERS {
        for n in 0..FRAMES {
            let Some(phys) = pmm::allocate_frame() else {
                fail("pmm_exhausted")
            };
            if phys == 0 || phys & 4095 != 0 || phys == boot_cr3
                || lease.iter().flatten().any(|x| *x == phys) {
                fail("bad_owned_frame")
            }
            lease[i][n] = phys;
        }
    }
    if pmm::statistics().allocated_frames != baseline + USERS * FRAMES {
        fail("frame_count")
    }
    let mut table = ProcessTable::<USERS,FRAMES>::new();
    let mut bank = UserContextBank::<USERS>::new();
    let mut signatures = [0u64; USERS];
    for i in 0..USERS {
        let Ok(pid) = table.reserve(lease[i][0],lease[i]) else {
            fail("resident_pid_admission")
        };
        if pid != (i as u64 + 1) { fail("wrong_pid_generation") }
        let context = bootstrap(0x401000 + (i as u64) * 0x1000,
            0x5700 + (i as u64) * 100);
        signatures[i] = context.registers.r12;
        if bank.prepare_bootstrap(&table,pid,lease[i][0],stack(i),context).is_err()
        { fail("bootstrap_context_validation") }
    }
    if bank.count() != USERS
        || !stack(0).valid() || !stack(1).valid()
        || stack(0).overlaps(stack(1)) {
        fail("disjoint_real_kernel_rsp0_stacks")
    }
    serial::write_line(
        "WOLFOS_USER_CONTEXT_READY_OK pids=2 frames=14 independent_rsp0=2 stored_gprs=15"
    );

    for round in 0..64 {
        let current = (round % 2 + 1) as u64;
        let Ok(plan) = bank.plan_next(&table,current,boot_cr3) else {
            fail("failed_alternating_resume_plan")
        };
        let wanted: usize = if current == 1 { 2 } else { 1 };
        if plan.pid != wanted as u64 || plan.cr3_root != lease[wanted-1][0]
            || plan.rsp0 != stack(wanted-1).top
            || plan.frame.registers.r12 != signatures[wanted-1]
            || plan.frame.registers.r13 != signatures[wanted-1] ^ u64::MAX
            || plan.frame.hardware.rip != 0x401000 + (wanted-1) as u64 * 0x1000 {
            fail("user_frame_cross_pid_corruption")
        }
    }
    if bank.plan_next(&table,1,lease[0][0]).is_ok() {
        fail("unsafe_active_cr3_accepted")
    }
    serial::write_line(
        "WOLFOS_USER_CONTEXT_PLAN_OK alternations=64 frames_independent=1 active_user_cr3_denied=1 actual_switches=0"
    );

    for i in 0..USERS {
        let pid = i as u64 + 1;
        if bank.retire(&table,pid).is_ok() { fail("live_frame_released") }
        let Ok(owned) = table.cancel_ready(pid,boot_cr3) else {
            fail("ready_cancel")
        };
        if owned != lease[i] || bank.retire(&table,pid).is_err() {
            fail("retirement_accounting")
        }
        for frame in owned {
            if pmm::free_frame(frame).is_err() { fail("frame_free") }
        }
    }
    if table.occupied() != 0 || bank.count() != 0
        || pmm::statistics().allocated_frames != baseline
        || Cr3::read().0.start_address().as_u64() != boot_cr3
    { fail("post_test_pmm_or_cr3") }
    serial::write_line(
        "WOLFOS_USER_CONTEXT_CLEANUP_OK released=14 no_pmm_leak=1 boot_cr3_intact=1 users_executed=0"
    );
}
