//! Real-PMM contiguous 16 KiB kernel stack leases for two READY user PIDs.
//! The stacks are supervisor HHDM mappings and are NEVER made active RSP0
//! in this isolated gate. Red-zone canaries are not hardware guard pages.
use core::arch::asm;
use x86_64::{instructions::interrupts, registers::control::Cr3};
use crate::{
    pmm, serial,
    kernel_stack_lease::{
        StackLeaseTable, RetirementGate, StackError, STACK_PAGES, STACK_BYTES,
    },
    process_table::ProcessTable,
    user_context_bank::{KernelStack, UserContextBank},
    user_syscall_abi::UserSyscallFrame,
};

const USERS: usize = 2;
const USER_FRAMES: usize = 7;
const CANARY: u64 = 0x574f_4c46_5354_4b21;

fn fail(name: &str) -> ! {
    serial::write_fmt(format_args!("WOLFOS_KSTACK_LEASE_ERROR {name}\n"));
    crate::halt_forever()
}

fn stack_words(bottom: u64, top: u64) -> (*mut u64, *mut u64) {
    (bottom as *mut u64, (top - 8) as *mut u64)
}

/// Single BSP; the supplied HHDM comes from the verified Limine response.
/// PMM holds all memory exclusively until explicit retire/free.
pub fn verify(hhdm: u64) {
    interrupts::disable();
    let (cr3, _) = Cr3::read();
    let boot_cr3 = cr3.start_address().as_u64();
    if boot_cr3 == 0 { fail("boot_cr3") }
    let mut rsp: u64;
    // SAFETY: reading current privileged RSP has no memory side effects.
    unsafe { asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)); }
    let before = pmm::statistics().allocated_frames;
    let mut user_frames = [[0u64; USER_FRAMES]; USERS];
    let mut stack_frames = [[0u64; STACK_PAGES]; USERS];

    for i in 0..USERS {
        for j in 0..USER_FRAMES {
            let Some(phys) = pmm::allocate_frame() else { fail("user_pmm") };
            if phys == boot_cr3 || phys == 0 || phys & 4095 != 0 {
                fail("unowned_user_frame")
            }
            user_frames[i][j] = phys;
        }
        for j in 0..STACK_PAGES {
            let Some(phys) = pmm::allocate_frame() else { fail("stack_pmm") };
            if phys == boot_cr3 || phys == 0 || phys & 4095 != 0 {
                fail("unowned_stack_frame")
            }
            stack_frames[i][j] = phys;
        }
    }
    if pmm::statistics().allocated_frames != before + USERS * (USER_FRAMES + STACK_PAGES) {
        fail("frame_count")
    }

    let mut processes = ProcessTable::<USERS,USER_FRAMES>::new();
    let mut stacks = StackLeaseTable::<USERS>::new();
    let mut frames = UserContextBank::<USERS>::new();
    let mut handles = [None; USERS];

    for i in 0..USERS {
        let Ok(pid) = processes.reserve(user_frames[i][0], user_frames[i])
            else { fail("process_admit") };
        if pid != (i+1) as u64 { fail("pid_order") }
        let Ok(lease) = stacks.admit(pid,stack_frames[i],hhdm)
            else { fail("real_contiguous_stack") };
        if lease.top - lease.bottom != STACK_BYTES
            || rsp >= lease.bottom && rsp < lease.top {
            fail("wrong_stack_bounds")
        }
        handles[i] = Some(lease.handle);
        let mut f = UserSyscallFrame::default();
        f.hardware.rip = 0x401000 + i as u64 * 0x1000;
        f.hardware.rsp = 0x405000;
        f.hardware.cs = 0x2b;
        f.hardware.ss = 0x23;
        f.hardware.rflags = 0x2;
        f.registers.r12 = 0x1234 + pid;
        if frames.prepare_bootstrap(
            &processes,pid,user_frames[i][0],
            KernelStack { bottom: lease.bottom, top: lease.top },f
        ).is_err() { fail("context_stack_binding") }
        let (low, high) = stack_words(lease.bottom,lease.top);
        // SAFETY: PMM owns four contiguous usable physical frames, mapped
        // by the verified Limine HHDM. This inactive kernel stack belongs
        // exclusively to the current BSP test until it is freed.
        unsafe {
            low.write_volatile(CANARY ^ pid);
            high.write_volatile(!(CANARY ^ pid));
        }
    }

    if stacks.occupied() != 2 || frames.count() != 2
        || stacks.inspect(handles[0].unwrap()).unwrap().top
            > stacks.inspect(handles[1].unwrap()).unwrap().bottom
            && stacks.inspect(handles[1].unwrap()).unwrap().top
            > stacks.inspect(handles[0].unwrap()).unwrap().bottom
    { fail("overlapping_rented_stacks") }
    serial::write_line(
        "WOLFOS_KSTACK_LEASE_READY_OK pids=2 real_pmm_frames=22 stack_pages=8 independent_rsp0=2 redzone=canary"
    );

    // This checks a future scheduler PLAN, not hardware context switching.
    for n in 0..64 {
        let current = (n % 2 + 1) as u64;
        let Ok(plan) = frames.plan_next(&processes,current,boot_cr3)
            else { fail("plan_next") };
        let wanted = if current == 1 { 1 } else { 0 };
        if plan.pid != wanted as u64 + 1
            || plan.cr3_root != user_frames[wanted][0]
            || plan.rsp0 != stacks.inspect(handles[wanted].unwrap()).unwrap().top
            || plan.frame.registers.r12 != 0x1234 + plan.pid {
            fail("wrong_pid_stack_plan")
        }
    }
    serial::write_line(
        "WOLFOS_KSTACK_LEASE_PLAN_OK alternations=64 cpl3_switches=0 root_aliases=0"
    );

    for i in 0..USERS {
        let pid = (i+1) as u64;
        let lease = stacks.inspect(handles[i].unwrap()).unwrap();
        let (low,high) = stack_words(lease.bottom,lease.top);
        // SAFETY: this is an INACTIVE HHDM stack still owned by PMM.
        let intact = unsafe {
            low.read_volatile() == CANARY ^ pid
                && high.read_volatile() == !(CANARY ^ pid)
        };
        if !intact { fail("canary_corruption") }
        let blocked = RetirementGate {
            interrupts_disabled: !interrupts::are_enabled(),
            scheduler_stopped: true, on_independent_supervisor_stack: true,
            no_borrowed_trap_frame: false,
            owning_pid_no_longer_live: false,
            owning_user_cr3_inactive: true,
        };
        if stacks.retire(handles[i].unwrap(), blocked) != Err(StackError::NotQuiescent)
            || frames.retire(&processes,pid).is_ok() {
            fail("premature_retire")
        }
        let owned_user = processes.cancel_ready(pid,boot_cr3)
            .unwrap_or_else(|_|fail("cancel_ready"));
        if owned_user != user_frames[i] || frames.retire(&processes,pid).is_err() {
            fail("cancel_then_context_retire")
        }
        // Re-check the actual BSP RSP and CR3 before metadata relinquishment.
        unsafe { asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)); }
        let (active,_) = Cr3::read();
        let gate = RetirementGate {
            interrupts_disabled: !interrupts::are_enabled(),
            scheduler_stopped: true,
            on_independent_supervisor_stack: rsp < lease.bottom || rsp >= lease.top,
            no_borrowed_trap_frame: frames.snapshot(pid).is_none(),
            owning_pid_no_longer_live: processes.snapshot(pid).is_none(),
            owning_user_cr3_inactive: active.start_address().as_u64() != user_frames[i][0],
        };
        let owned_stack = stacks.retire(handles[i].unwrap(),gate)
            .unwrap_or_else(|_|fail("stack_not_quiescent"));
        if owned_stack != stack_frames[i] { fail("returned_foreign_stack") }
        for physical in owned_stack.into_iter().chain(owned_user) {
            if pmm::free_frame(physical).is_err() { fail("pmm_release") }
        }
    }
    if stacks.occupied() != 0 || processes.occupied() != 0 || frames.count() != 0
        || pmm::statistics().allocated_frames != before
        || Cr3::read().0.start_address().as_u64() != boot_cr3 {
        fail("reclaimed_pmm_ownership")
    }
    serial::write_line(
        "WOLFOS_KSTACK_LEASE_CLEANUP_OK frames_freed=22 pmm_leak=0 boot_cr3_restored=1 guard_page=0 user_tasks_switched=0"
    );
}
