//! Actual CPL3-to-CPL3 cooperative task switches between TWO separately
//! linked native ET_EXEC ELF64 applications, each on its own CR3, its own
//! real guarded high-half TSS.RSP0 stack, its own FXSAVE64 image, its own
//! private user text/data/stack. Zero APs run user tasks. The optional
//! xAPIC smoke has TWO bounded hardware preemptions, not a general scheduler.
//!
//! Test-only SYS_YIELD=9; never part of the stable WolfOS syscall ABI.
//! The existing 15-GPR INT80 entry restores the POINTER we return, then
//! IRETQ resumes the other PID. Faults and unexpected syscalls fail closed.
use core::{arch::asm,cell::UnsafeCell};
#[cfg(any(feature = "p2-ring3-timer-preempt-smoke",
          feature = "p3-ring3-event-wait-hardware-smoke"))]
use crate::ring3_runqueue::{Handle as RunHandle,Ring3RunQueue,State as RrState};
#[cfg(feature = "p3-ring3-event-wait-hardware-smoke")]
use crate::ring3_event_wait_gate::{
    Commit as EventCommit, Delivery as EventDelivery, Error as EventError,
    EventToken, EventWaitGate,
};
#[cfg(feature="p3-ring3-four-elf-live-smoke")]
use crate::ring3_irq_eoi_ledger::Ring3IrqEoiLedger;
use x86_64::{VirtAddr,instructions::{interrupts as cpu_interrupts,tlb},
             instructions::segmentation::{CS,Segment},registers::control::Cr3};
#[cfg(feature="p3-ring3-four-elf-preflight-smoke")]
use crate::{
    high_half_stack_arena::{FourPidGuardedArena,FOUR_PID_OWNED,FOUR_PID_STACKS},
    user_context_bank::{KernelStack,UserContextBank},
    user_fx_bank::FourPidFxBank,
};
use crate::{
    elf64_preflight::preflight,elf64_page_image::{materialize,PAGE_SIZE},
    high_half_stack_arena::{GuardedArena,Stack,ROOT_INDEX,BASE,PAGE},
    process_table::ProcessTable,process_lifecycle::ProcessState,
    user_syscall_abi::{self,UserSyscallFrame},
    user_ring_entry::{self,Ring3Entry},
    user_fx_bank::{FxImage,FxHandle,UserFxBank},
    fx_state,kernel_half_shadow,interrupts,pmm,serial,
};
#[cfg(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
use crate::user_irq_preempt_contract::{self,Evidence};

mod sym {include!(concat!(env!("OUT_DIR"),"/wolfos_yield_symbols.rs"));}
#[cfg(feature = "p2-ring3-timer-preempt-smoke")]
mod noyield_sym {include!(concat!(env!("OUT_DIR"),"/wolfos_nonyield_symbols.rs"));}
#[cfg(feature = "p2-ring3-timer-preempt-smoke")]
const NONYIELD_ELFS:[&[u8];2]=[
    include_bytes!(concat!(env!("OUT_DIR"),"/wolfos-nonyield-1.elf")),
    include_bytes!(concat!(env!("OUT_DIR"),"/wolfos-nonyield-2.elf")),
];
#[cfg(feature="p3-ring3-four-elf-preflight-smoke")]
const FOUR_NOYIELD_ELFS:[&[u8];4]=[
    NONYIELD_ELFS[0], NONYIELD_ELFS[1],
    include_bytes!(concat!(env!("OUT_DIR"),"/wolfos-nonyield-3.elf")),
    include_bytes!(concat!(env!("OUT_DIR"),"/wolfos-nonyield-4.elf")),
];
// The independent event-WAIT QEMU flavor links different native programs
// into these exact slots without changing historical yield/timer fixtures.
const ELFS:[&[u8];2]=[
    include_bytes!(concat!(env!("OUT_DIR"),"/wolfos-yield-1.elf")),
    include_bytes!(concat!(env!("OUT_DIR"),"/wolfos-yield-2.elf")),
];
#[cfg(feature="p3-ring3-four-elf-live-smoke")]
const COUNT:usize=4;
#[cfg(not(feature="p3-ring3-four-elf-live-smoke"))]
const COUNT:usize=2;
#[cfg(feature="p3-ring3-four-elf-live-smoke")]
const ARENA_FRAMES:usize=FOUR_PID_OWNED;
#[cfg(not(feature="p3-ring3-four-elf-live-smoke"))]
const ARENA_FRAMES:usize=crate::high_half_stack_arena::OWNED;
#[cfg(feature="p3-ring3-four-elf-live-smoke")]
type RuntimeArena=FourPidGuardedArena;
#[cfg(not(feature="p3-ring3-four-elf-live-smoke"))]
type RuntimeArena=GuardedArena;
#[cfg(feature="p3-ring3-four-elf-live-smoke")]
type RuntimeFxBank=FourPidFxBank;
#[cfg(not(feature="p3-ring3-four-elf-live-smoke"))]
type RuntimeFxBank=UserFxBank;
const PER_PID:usize=7;
#[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
const PHYSICAL:usize=ARENA_FRAMES+COUNT*PER_PID+3; // 25 frames + 3 xAPIC high MMIO page tables
#[cfg(not(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
const PHYSICAL:usize=ARENA_FRAMES+COUNT*PER_PID; // 11+14=25
const P:u64=1;const W:u64=2;const U:u64=4;const NX:u64=1<<63;
const CODE:u64=0x401000;const DATA:u64=0x403000;
const STACK:u64=0x404000;const USER_TOP:u64=STACK+PAGE;
const TEST_YIELD:u64=9;
#[cfg(feature = "p3-ring3-event-wait-hardware-smoke")]
const EVENT_ID:u64=77;
#[cfg(feature = "p3-ring3-event-wait-hardware-smoke")]
const SYS_WAIT_EVENT:u64=10;
#[cfg(feature = "p3-ring3-event-wait-hardware-smoke")]
const SYS_SIGNAL_EVENT:u64=11;
#[cfg(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
const IRQ_USER_RFLAGS:u64=0x202;
#[cfg(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
fn pic_read(port:u16)->u8{
    let value:u8;
    // SAFETY: exclusive BSP x86 I/O access, PIC queried only in isolated
    // QEMU while maskable IRQs are off in privileged code.
    unsafe{asm!("in al, dx",in("dx")port,lateout("al")value,
        options(nostack,nomem,preserves_flags));}
    value
}
#[cfg(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
fn pic_write(port:u16,value:u8){
    // SAFETY: only BSP owns PIC mask ports while APs are parked.
    unsafe{asm!("out dx, al",in("dx")port,in("al")value,
        options(nostack,nomem,preserves_flags));}
}

const TRAPS:usize=if cfg!(feature="p3-ring3-event-wait-hardware-smoke"){5}
    else if cfg!(feature="p2-ring3-timer-nonyield-smoke"){COUNT}else{10};
const ROUNDS:u64=if cfg!(feature="p3-ring3-event-wait-hardware-smoke"){1}
    else if cfg!(feature="p2-ring3-timer-nonyield-smoke"){16}else{4};
#[cfg(feature="p3-ring3-four-elf-live-smoke")]
const USER_ID:[u64;COUNT]=[0x5a5a_0001_0000_0001,0x5a5a_0001_0000_0002,
    0x5a5a_0001_0000_0003,0x5a5a_0001_0000_0004];
#[cfg(not(feature="p3-ring3-four-elf-live-smoke"))]
const USER_ID:[u64;COUNT]=[0x5a5a_0001_0000_0001,0x5a5a_0001_0000_0002];

fn valid_test_user_flags(flags:u64)->bool{
    #[cfg(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
    {user_irq_preempt_contract::safe_irq_user_flags(flags)}
    #[cfg(not(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))))]
    {user_syscall_abi::valid_user_rflags(flags)}
}
fn fail(why:&str)->!{
    serial::write_fmt(format_args!("WOLFOS_RING3_YIELD_ERROR {why}\n"));
    // Dedicated QEMU-only hardware feature: fail with isa-debug-exit
    // status 35 (distinct from successful 33), rather than spend the
    // smoke timeout halted after a real invalid CPL3 interrupt.
    #[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
    unsafe{asm!("out dx, al",in("dx")0xf4u16,in("al")0x11u8,
        options(nostack,nomem,preserves_flags));}
    crate::halt_forever()
}
fn ptr(hhdm:u64,physical:u64)->*mut u8{
    VirtAddr::try_new(hhdm.checked_add(physical)
        .unwrap_or_else(||fail("hhdm_overflow")))
        .unwrap_or_else(|_|fail("hhdm_noncanonical"))
        .as_mut_ptr::<u8>()
}
fn root(hhdm:u64,phys:u64)->*mut [u64;512]{
    ptr(hhdm,phys).cast::<[u64;512]>()
}
fn actual_cr3()->u64{Cr3::read().0.start_address().as_u64()}

struct Runtime{
    boot:u64,
    hhdm:u64,
    original_rsp0:u64,
    boot_rsp:u64,
    before:usize,
    owned:[u64;PHYSICAL],
    leases:[[u64;PER_PID];COUNT],
    stacks:[Stack;COUNT],
    arena:RuntimeArena,
    processes:ProcessTable<COUNT,PER_PID>,
    fx:RuntimeFxBank,
    fx_tokens:[FxHandle;COUNT],
    control:fx_state::OriginalControl,
    frames:[u64;COUNT],
    current:usize,
    yields:[u64;COUNT],
    exits:[bool;COUNT],
    hardware_traps:usize,
    #[cfg(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
    pic_before:[u8;2],
    #[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
    timer_irqs:[u64;COUNT],
    #[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
    timer_busy:[u64;COUNT],
    #[cfg(feature = "p2-ring3-timer-preempt-smoke")]
    timer_preempts:[u64;COUNT],
    #[cfg(feature="p3-ring3-four-elf-live-smoke")]
    first_exit_timer_counts:Option<[u64;COUNT]>,
    #[cfg(feature="p3-ring3-four-elf-live-smoke")]
    irq_eoi:Ring3IrqEoiLedger<COUNT>,
    #[cfg(any(feature = "p2-ring3-timer-preempt-smoke",
              feature = "p3-ring3-event-wait-hardware-smoke"))]
    rr:Ring3RunQueue<COUNT>,
    #[cfg(any(feature = "p2-ring3-timer-preempt-smoke",
              feature = "p3-ring3-event-wait-hardware-smoke"))]
    rr_handles:[RunHandle;COUNT],
    #[cfg(feature = "p3-ring3-event-wait-hardware-smoke")]
    event_wait:Option<EventToken>,
    #[cfg(feature = "p3-ring3-event-wait-hardware-smoke")]
    event_gate:EventWaitGate<COUNT>,
    #[cfg(feature = "p3-ring3-event-wait-hardware-smoke")]
    event_wakes:u64,
    #[cfg(feature = "p3-ring3-event-wait-hardware-smoke")]
    event_rejections:u64,
}
struct BspRuntime(UnsafeCell<Option<Runtime>>);
// SAFETY: only one BSP may access the runtime; IF=0 from admission until
// exit, no preemptible AP/async scheduler and no parallel user task exists.
unsafe impl Sync for BspRuntime {}
static RUNTIME:BspRuntime=BspRuntime(UnsafeCell::new(None));
#[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
static TIMER_LIVE:core::sync::atomic::AtomicBool=
    core::sync::atomic::AtomicBool::new(false);

/// True only after the two private user processes and high xAPIC MMIO
/// alias exist. No serial, allocation, locks or FX manipulation in IRQ.
#[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
pub fn timer_irq_active()->bool{
    TIMER_LIVE.load(core::sync::atomic::Ordering::Acquire)
}
#[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
fn user_busy(pid:usize)->(u64,u64){
    #[cfg(feature="p2-ring3-timer-nonyield-smoke")]
    {
        #[cfg(feature="p3-ring3-four-elf-live-smoke")]
        {match pid {
            0=>(noyield_sym::PID1_WORK_BEGIN,noyield_sym::PID1_WORK_END),
            1=>(noyield_sym::PID2_WORK_BEGIN,noyield_sym::PID2_WORK_END),
            2=>(noyield_sym::PID3_WORK_BEGIN,noyield_sym::PID3_WORK_END),
            3=>(noyield_sym::PID4_WORK_BEGIN,noyield_sym::PID4_WORK_END),
            _=>fail("four_live_invalid_busy_pid"),
        }}
        #[cfg(not(feature="p3-ring3-four-elf-live-smoke"))]
        {if pid==0{(noyield_sym::PID1_WORK_BEGIN,noyield_sym::PID1_WORK_END)}
        else{(noyield_sym::PID2_WORK_BEGIN,noyield_sym::PID2_WORK_END)}}
    }
    #[cfg(not(feature="p2-ring3-timer-nonyield-smoke"))]
    {
        if pid==0{(sym::PID1_BUSY_BEGIN,sym::PID1_BUSY_END)}
        else{(sym::PID2_BUSY_BEGIN,sym::PID2_BUSY_END)}
    }
}

/// Called by the REAL installed xAPIC timer IRQ entry, not by INT80.
/// Interrupt gate already cleared IF; caller retained all 15 GPRs.
/// Returns the SAME user frame, so this milestone proves genuine
/// involuntary interruption but NOT yet timer-driven task handoff.
#[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
pub extern "C" fn observe_timer_irq(
    raw:*const UserSyscallFrame,
)->*const UserSyscallFrame{
    let s=active();
    let i=s.current;
    let pid=(i+1) as u64;
    let st=s.stacks[i];
    if raw.is_null()||
        raw as u64!=st.top-user_syscall_abi::FRAME_BYTES as u64||
        actual_cr3()!=s.leases[i][0]||
        interrupts::test_actual_rsp0()!=st.top||
        s.fx.active_pid()!=Some(pid)||
        s.exits[i]||
        s.processes.snapshot(pid).is_none_or(|p|
            p.state!=ProcessState::Running||
            p.cr3_root!=s.leases[i][0]){
        fail("genuine_timer_irq_wrong_pid_cr3_rsp0_fx")
    }
    let f=unsafe{&*raw};
    let (user_cs,user_ss,_)=interrupts::ring3_cpu_state();
    let check=user_irq_preempt_contract::Evidence{
        pid,expected_pid:pid,actual_cr3:actual_cr3(),
        owned_cr3:s.leases[i][0],actual_rsp0:interrupts::test_actual_rsp0(),
        owned_stack_bottom:st.bottom,owned_stack_top:st.top,
        actual_frame_address:raw as u64,
        user_rip:f.hardware.rip,user_rsp:f.hardware.rsp,
        user_cs:f.hardware.cs,user_ss:f.hardware.ss,
        user_rflags:f.hardware.rflags,
        fpu_owner_pid:s.fx.active_pid().unwrap_or(0),
    };
    let (busy_start,busy_end)=user_busy(i);
    let in_busy=(busy_start..busy_end).contains(&f.hardware.rip);
    let reason=user_irq_preempt_contract::validate(check).err();
    let extra=f.hardware.cs!=user_cs as u64||
        f.hardware.ss!=user_ss as u64||
        f.hardware.rsp!=USER_TOP||
        f.hardware.rip<CODE||f.hardware.rip>=CODE+PAGE;
    // A genuine timer can interrupt the very FIRST instruction after
    // IRETQ, before user code initializes R12/R14. Verify PID sentinels
    // only INSIDE the precisely linked initialized busy-loop window.
    let bad_gpr=in_busy&&(f.registers.r12!=pid||f.registers.r14!=USER_ID[i]);
    if reason.is_some()||extra||bad_gpr{
        serial::write_fmt(format_args!(
            "WOLFOS_RING3_TIMER_DIAGNOSTIC pid={} rip={:#x} rsp={:#x} cs={:#x} ss={:#x} flags={:#x} r12={:#x} r14={:#x} frame={:#x} top={:#x} reason={:?} extra={} bad_gpr={} in_busy={}\n",
            pid,f.hardware.rip,f.hardware.rsp,f.hardware.cs,
            f.hardware.ss,f.hardware.rflags,f.registers.r12,
            f.registers.r14,raw as u64,st.top,reason,extra,bad_gpr,in_busy
        ));
        fail("real_cpl3_timer_iret_gpr_or_frame_validation")
    }
    // Frame, user selectors, private CR3, TSS.RSP0 and FX owner have
    // passed real hardware IRQ authentication before opening this EOI.
    #[cfg(feature="p3-ring3-four-elf-live-smoke")]
    if s.irq_eoi.begin(i).is_err() { fail("four_live_eoi_duplicate_irq") }
    s.timer_irqs[i]+=1;
    if in_busy{
        s.timer_busy[i]+=1;
    }
    if s.timer_irqs[i]>100_000{
        fail("unexpected_interrupt_storm")
    }
    // A REAL hardware timer IRQ may choose an independently mapped
    // OTHER PID's full hardware IRET frame, without a voluntary INT80.
    // Limit this isolated proof to one preemption PER PID in its assembly
    // no-syscall busy window. The remaining genuine IRQs resume the same
    // PID. The round-robin policy is called only for eligible hardware
    // switch events, never on INT80 or same-PID IRQ returns. This preserves
    // the existing strict eight-yield regression, which still
    // checks both ELF data counters after involuntary interruption.
    #[cfg(feature="p3-ring3-four-elf-live-smoke")]
    let preempt_target=if in_busy {
        // This IRQ has passed the real hardware-frame / CR3 / TSS / FX
        // provenance checks above. Charge it to the interrupted PID,
        // including those which resume without switching. A second
        // eligible IRQ must expire this bounded time slice. This policy
        // never produces an EOI or assumes INT80 was a hardware IRQ.
        let chosen=s.rr.timer_quantum_tick(s.rr_handles[i],2)
            .unwrap_or_else(|_|fail("four_live_invalid_timer_quantum"));
        if chosen==s.rr_handles[i] {
            None
        } else {
            let target=usize::try_from(chosen.pid-1)
                .unwrap_or_else(|_|fail("four_live_quantum_target_overflow"));
            if target>=COUNT || chosen!=s.rr_handles[target]
                || s.exits[target] || s.frames[target]==0 {
                fail("four_live_stale_quantum_target")
            }
            Some(target)
        }
    } else {None};
    #[cfg(all(feature="p2-ring3-timer-preempt-smoke",
              not(feature="p3-ring3-four-elf-live-smoke")))]
    let preempt_target={
        let other=1-i;
        if in_busy
            && (cfg!(feature="p2-ring3-timer-nonyield-smoke") || s.timer_preempts[i]==0)
            && s.frames[other]!=0 && !s.exits[other] {
            Some(other)
        } else {
            None
        }
    };
    #[cfg(feature = "p2-ring3-timer-preempt-smoke")]
    if let Some(next)=preempt_target{
        let next_frame=s.frames[next];
        if next_frame!=s.stacks[next].top
                -user_syscall_abi::FRAME_BYTES as u64
            || next_frame&15!=0
            || s.processes.snapshot((next+1) as u64)
                .is_none_or(|p| p.state!=ProcessState::Ready
                    || p.cr3_root!=s.leases[next][0]) {
            fail("involuntary_next_pid_frame_or_root")
        }
        // The IRQ's captured GPR+5-word hardware frame remains pinned
        // on the departing PID's *own* guarded high-half kernel stack.
        // It is safe to retain across CR3 switches: this supervisor
        // high-half subtree is shared by BOTH sanitized process roots.
        #[cfg(not(feature="p3-ring3-four-elf-live-smoke"))]
        if s.rr.timer_tick(s.rr_handles[i])!=Ok(s.rr_handles[next]) {
            fail("timer_policy_rejected_verified_irq_handoff")
        }
        #[cfg(feature="p3-ring3-four-elf-live-smoke")]
        if s.rr.running()!=Some(s.rr_handles[next]) {
            fail("four_live_quantum_selected_wrong_user")
        }
        s.frames[i]=raw as u64;
        if s.processes.park_running(pid,s.leases[i][0]).is_err() {
            fail("involuntary_park_running_pid")
        }
        if unsafe{s.fx.switch_to(s.fx_tokens[next])}.is_err()
            || s.fx.image_xmm0(s.fx_tokens[i])!=Ok(USER_ID[i]) {
            fail("involuntary_fx_state_save_restore")
        }
        if !unsafe{interrupts::test_handoff_rsp0(s.stacks[next].top)} {
            fail("involuntary_next_tss_rsp0")
        }
        // xAPIC in-service vector MUST be acknowledged exactly once
        // from the CURRENT validated private-CR3 supervisor UC alias.
        // No serial I/O, blocking locks, allocations or busy waits on
        // the successful timer IRQ scheduling path.
        acknowledge_validated_timer_irq(s,i);
        unsafe{
            asm!("mov cr3, {}",in(reg)s.leases[next][0],
                options(nostack,preserves_flags));
        }
        if actual_cr3()!=s.leases[next][0]
            || s.processes.mark_running((next+1) as u64,
                         s.leases[next][0]).is_err()
            || s.processes.running()!=1 {
            fail("involuntary_private_cr3_or_running_pid")
        }
        s.timer_preempts[i]+=1;
        #[cfg(feature="p3-ring3-four-elf-live-smoke")]
        if s.irq_eoi.finish(i,true).is_err() {
            fail("four_live_eoi_missing_switch_completion")
        }
        s.current=next;
        return next_frame as *const UserSyscallFrame;
    }
    // SAFETY: this high VA is supervisor-only UC in the CURRENT private
    // user CR3 root; this is a genuine local xAPIC in-service vector.
    // Exactly one EOI per hardware IRQ, never EOI a spurious IRQ.
    acknowledge_validated_timer_irq(s,i);
    #[cfg(feature="p3-ring3-four-elf-live-smoke")]
    if s.irq_eoi.finish(i,false).is_err() {
        fail("four_live_eoi_missing_same_pid_completion")
    }
    raw
}
/// Centralized exactly-once EOI callsite for a validated user timer IRQ.
/// No serial I/O, locks, allocations or APIC reads on the successful path.
#[cfg(any(feature="p2-ring3-timer-observe-smoke", feature="p2-ring3-timer-preempt-smoke"))]
fn acknowledge_validated_timer_irq(s:&mut Runtime, i:usize){
    #[cfg(not(feature="p3-ring3-four-elf-live-smoke"))]
    let _=(s,i);
    // SAFETY: BSP IF=0, verified in-service xAPIC timer vector and
    // supervisor-only UC alias in the CURRENT trusted private CR3.
    unsafe{
        crate::user_xapic_high::write(
            crate::lapic_irq_layout::EOI_OFFSET,
            crate::lapic_irq_layout::EOI_VALUE);
    }
    #[cfg(feature="p3-ring3-four-elf-live-smoke")]
    if s.irq_eoi.acknowledge(i).is_err() {
        fail("four_live_eoi_missing_or_duplicate")
    }
}

fn active()->&'static mut Runtime{
    unsafe{(*RUNTIME.0.get()).as_mut().unwrap_or_else(||fail("not_started"))}
}

fn entry(pid:usize)->u64{
    #[cfg(feature="p3-ring3-four-elf-preflight-smoke")]
    {match pid {
        0=>noyield_sym::PID1_ENTRY,1=>noyield_sym::PID2_ENTRY,
        2=>noyield_sym::PID3_ENTRY,3=>noyield_sym::PID4_ENTRY,
        _=>fail("invalid_four_pid_entry"),
    }}
    #[cfg(all(feature="p2-ring3-timer-nonyield-smoke",
              not(feature="p3-ring3-four-elf-preflight-smoke")))]
    {if pid==0{noyield_sym::PID1_ENTRY}else{noyield_sym::PID2_ENTRY}}
    #[cfg(not(feature="p2-ring3-timer-nonyield-smoke"))]
    {if pid==0{sym::PID1_ENTRY}else{sym::PID2_ENTRY}}
}
#[cfg(not(feature="p2-ring3-timer-nonyield-smoke"))]
fn after_yield(pid:usize)->u64{
    if pid==0{sym::PID1_AFTER_YIELD}else{sym::PID2_AFTER_YIELD}
}
fn after_exit(pid:usize)->u64{
    #[cfg(feature="p3-ring3-four-elf-preflight-smoke")]
    {match pid {
        0=>noyield_sym::PID1_AFTER_EXIT,1=>noyield_sym::PID2_AFTER_EXIT,
        2=>noyield_sym::PID3_AFTER_EXIT,3=>noyield_sym::PID4_AFTER_EXIT,
        _=>fail("invalid_four_pid_exit"),
    }}
    #[cfg(all(feature="p2-ring3-timer-nonyield-smoke",
              not(feature="p3-ring3-four-elf-preflight-smoke")))]
    {if pid==0{noyield_sym::PID1_AFTER_EXIT}else{noyield_sym::PID2_AFTER_EXIT}}
    #[cfg(not(feature="p2-ring3-timer-nonyield-smoke"))]
    {if pid==0{sym::PID1_AFTER_EXIT}else{sym::PID2_AFTER_EXIT}}
}
fn progress(pid:usize)->u64{
    #[cfg(feature="p3-ring3-four-elf-preflight-smoke")]
    {match pid {
        0=>noyield_sym::PID1_PROGRESS,1=>noyield_sym::PID2_PROGRESS,
        2=>noyield_sym::PID3_PROGRESS,3=>noyield_sym::PID4_PROGRESS,
        _=>fail("invalid_four_pid_progress"),
    }}
    #[cfg(all(feature="p2-ring3-timer-nonyield-smoke",
              not(feature="p3-ring3-four-elf-preflight-smoke")))]
    {if pid==0{noyield_sym::PID1_PROGRESS}else{noyield_sym::PID2_PROGRESS}}
    #[cfg(not(feature="p2-ring3-timer-nonyield-smoke"))]
    {if pid==0{sym::PID1_PROGRESS}else{sym::PID2_PROGRESS}}
}
fn prepare_elf(hhdm:u64,frames:[u64;7],source:*const [u64;512],
               pid:usize){
    #[cfg(feature="p3-ring3-four-elf-preflight-smoke")]
    let elf=FOUR_NOYIELD_ELFS[pid];
    #[cfg(all(feature="p2-ring3-timer-nonyield-smoke",
              not(feature="p3-ring3-four-elf-preflight-smoke")))]
    let elf=NONYIELD_ELFS[pid];
    #[cfg(not(feature="p2-ring3-timer-nonyield-smoke"))]
    let elf=ELFS[pid];
    let plan=preflight(elf).unwrap_or_else(|_|fail("independent_elf_preflight"));
    #[cfg(feature="p2-ring3-timer-nonyield-smoke")]
    let symbols_ok=entry(pid)==CODE && progress(pid)==DATA &&
        after_exit(pid)>CODE && after_exit(pid)<DATA;
    #[cfg(not(feature="p2-ring3-timer-nonyield-smoke"))]
    let symbols_ok=entry(pid)==CODE && progress(pid)==DATA &&
        after_yield(pid)>CODE && after_exit(pid)>after_yield(pid) &&
        after_exit(pid)<DATA;
    if plan.entry!=CODE||plan.len!=2||!symbols_ok{
        fail("native_elf_symbols_or_layout")
    }
    let (Some(text),Some(data))=(plan.segments[0],plan.segments[1])
        else{fail("missing_load_segments")};
    if text.page_start!=CODE||text.page_end!=CODE+PAGE
        ||!text.executable||text.writable||
        data.page_start!=DATA||data.page_end!=DATA+PAGE||
        !data.writable||data.executable||data.file_size!=8{
        fail("elf_permissions")
    }
    // SAFETY: frames reserved uniquely by PMM, cannot alias boot root or
    // other PID; kernel HHDM maps all frames for setup.
    unsafe{
        for &p in &frames{
            core::ptr::write_bytes(ptr(hhdm,p),0,PAGE as usize);
        }
        let text_page=&mut *ptr(hhdm,frames[4]).cast::<[u8;PAGE_SIZE]>();
        let data_page=&mut *ptr(hhdm,frames[5]).cast::<[u8;PAGE_SIZE]>();
        if materialize(elf,&text,CODE,text_page).is_err()
            ||materialize(elf,&data,DATA,data_page).is_err()
            ||data_page[..8]!=[0;8]{
            fail("materialize_two_separate_ELFs")
        }
        let pdpt=&mut *root(hhdm,frames[1]);
        let pd=&mut *root(hhdm,frames[2]);
        let pt=&mut *root(hhdm,frames[3]);
        pdpt[0]=frames[2]|P|W|U;
        pd[2]=frames[3]|P|W|U;
        pt[1]=frames[4]|P|U;
        pt[3]=frames[5]|P|W|U|NX;
        pt[4]=frames[6]|P|W|U|NX;
        let pml4=&mut *root(hhdm,frames[0]);
        let user_root=frames[1]|P|W|U;
        pml4[0]=user_root;
        let src=&*source;
        let copied=kernel_half_shadow::graft_kernel_half(
            src,pml4,0,user_root,&frames
        ).unwrap_or_else(|_|fail("root_supervisor_graft"));
        if copied<1||pml4[ROOT_INDEX]&P==0||
            pml4[ROOT_INDEX]&U!=0||
            kernel_half_shadow::audit_kernel_half(
                src,pml4,0,user_root,&frames)!=Ok(copied){
            fail("root_cpl3_isolation")
        }
        if pt.iter().filter(|x|**x!=0).count()!=3||
            pd.iter().filter(|x|**x!=0).count()!=1||
            pdpt.iter().filter(|x|**x!=0).count()!=1{
            fail("unexpected_extra_user_pages")
        }
    }
}

/// Validate the two newly built no-yield ELF files using the *actual*
/// allocation-free WolfOS kernel loader preflight, without executing them
/// or changing any legacy IRQ/user process run. This is admission only.
#[cfg(feature = "p2-ring3-timer-preempt-smoke")]
fn validate_nonyield_elf_admission() {
    let info=[
        (noyield_sym::PID1_ENTRY,noyield_sym::PID1_WORK_BEGIN,
         noyield_sym::PID1_WORK_END,noyield_sym::PID1_AFTER_EXIT,
         noyield_sym::PID1_PROGRESS),
        (noyield_sym::PID2_ENTRY,noyield_sym::PID2_WORK_BEGIN,
         noyield_sym::PID2_WORK_END,noyield_sym::PID2_AFTER_EXIT,
         noyield_sym::PID2_PROGRESS),
    ];
    for (i,&(entry,begin,end,after_exit,progress)) in
        info.iter().enumerate() {
        let plan=preflight(NONYIELD_ELFS[i])
            .unwrap_or_else(|_|fail("nonyield_elf_kernel_preflight"));
        if plan.len!=2 || plan.entry!=CODE || entry!=CODE ||
           !(CODE..end).contains(&begin) || end>=after_exit ||
           after_exit>=CODE+PAGE || progress!=DATA {
            fail("nonyield_elf_kernel_symbol_bounds")
        }
        let (Some(text),Some(data))=(plan.segments[0],plan.segments[1])
            else{fail("nonyield_elf_kernel_missing_segment")};
        if text.page_start!=CODE || text.page_end!=CODE+PAGE ||
            !text.executable || text.writable ||
            data.page_start!=DATA || data.page_end!=DATA+PAGE ||
            !data.writable || data.executable || data.file_size!=8 {
            fail("nonyield_elf_kernel_permissions")
        }
    }
}

/// Kernel admission of four independently assembled native no-yield ELF64
/// binaries. This does NOT allocate, launch or schedule PID3 and PID4.
#[cfg(feature="p3-ring3-four-elf-preflight-smoke")]
fn validate_four_nonyield_elf_admission() {
    let info=[
        (noyield_sym::PID1_ENTRY,noyield_sym::PID1_WORK_BEGIN,
         noyield_sym::PID1_WORK_END,noyield_sym::PID1_AFTER_EXIT,
         noyield_sym::PID1_PROGRESS),
        (noyield_sym::PID2_ENTRY,noyield_sym::PID2_WORK_BEGIN,
         noyield_sym::PID2_WORK_END,noyield_sym::PID2_AFTER_EXIT,
         noyield_sym::PID2_PROGRESS),
        (noyield_sym::PID3_ENTRY,noyield_sym::PID3_WORK_BEGIN,
         noyield_sym::PID3_WORK_END,noyield_sym::PID3_AFTER_EXIT,
         noyield_sym::PID3_PROGRESS),
        (noyield_sym::PID4_ENTRY,noyield_sym::PID4_WORK_BEGIN,
         noyield_sym::PID4_WORK_END,noyield_sym::PID4_AFTER_EXIT,
         noyield_sym::PID4_PROGRESS),
    ];
    for (i,&(entry,begin,end,after_exit,progress)) in info.iter().enumerate() {
        let elf=FOUR_NOYIELD_ELFS[i];
        if elf.len()>=32768 || FOUR_NOYIELD_ELFS[..i].contains(&elf) {
            fail("four_elf_duplicated_or_oversized")
        }
        let plan=preflight(elf).unwrap_or_else(|_|fail("four_elf_strict_preflight"));
        if plan.len!=2 || plan.entry!=CODE || entry!=CODE ||
            begin<=entry || end<=begin || end>=after_exit ||
            after_exit>=DATA || progress!=DATA {
            fail("four_elf_symbols_or_layout")
        }
        let (Some(text),Some(data))=(plan.segments[0],plan.segments[1])
            else{fail("four_elf_missing_segment")};
        if text.page_start!=CODE || text.page_end!=CODE+PAGE ||
            !text.executable || text.writable ||
            data.page_start!=DATA || data.page_end!=DATA+PAGE ||
            !data.writable || data.executable || data.file_size!=8 {
            fail("four_elf_memory_permissions")
        }
    }
}

/// Isolated four-PID **real PMM residency** proof. Four independently linked
/// ELF64 images are materialized into disjoint physical code/data/stack
/// pages and four private sanitized CR3 roots; four actual guarded 16KiB
/// supervisor stack mappings are published, checked, then fully removed.
/// These are prepared READY contexts, not executed CPL3 tasks: the existing
/// two-ELF hardware workload starts only AFTER exact PMM reclamation.
#[cfg(feature="p3-ring3-four-elf-preflight-smoke")]
fn prove_four_resident_preflight(
    hhdm:u64, boot:u64, boot_root:*mut [u64;512], cs:u16, ss:u16,
){
    const FOUR:usize=FOUR_PID_STACKS;
    const OWNED:usize=FOUR_PID_OWNED+FOUR*PER_PID; // 19 guarded + 28 user = 47
    let before=pmm::statistics().allocated_frames;
    if actual_cr3()!=boot || unsafe{(*boot_root)[ROOT_INDEX]}!=0 {
        fail("four_resident_requires_quiescent_boot_cr3")
    }
    let mut phys=[0u64;OWNED];
    for i in 0..OWNED {
        let frame=pmm::allocate_frame().unwrap_or_else(||fail("four_resident_pmm_exhausted"));
        if frame==0 || frame&4095!=0 || frame==boot
            || phys[..i].contains(&frame) {
            fail("four_resident_duplicate_pmm_lease")
        }
        phys[i]=frame;
    }
    if pmm::statistics().allocated_frames!=before+OWNED {
        fail("four_resident_wrong_pmm_count")
    }

    let mut arena=FourPidGuardedArena::new([phys[0],phys[1],phys[2]],boot)
        .unwrap_or_else(|_|fail("four_resident_arena_root"));
    let mut processes=ProcessTable::<FOUR,PER_PID>::new();
    let mut contexts=UserContextBank::<FOUR>::new();
    let mut stacks=[None;FOUR];
    let mut leases=[[0u64;PER_PID];FOUR];
    for i in 0..FOUR {
        let n=3+i*4;
        let owned=[phys[n],phys[n+1],phys[n+2],phys[n+3]];
        let st=arena.reserve((i+1) as u64,owned)
            .unwrap_or_else(|_|fail("four_resident_guarded_stack"));
        let at=FOUR_PID_OWNED+i*PER_PID;
        leases[i].copy_from_slice(&phys[at..at+PER_PID]);
        let pid=processes.reserve(leases[i][0],leases[i])
            .unwrap_or_else(|_|fail("four_resident_private_cr3_owner"));
        if pid!=(i+1) as u64 {
            fail("four_resident_wrong_pid")
        }
        stacks[i]=Some(st);
    }
    // SAFETY: BSP IF=0; reserved high-half PML4 slot is empty and no CPU
    // can currently use any of these newly allocated high-half leaves.
    unsafe {
        for &p in &phys[..3] {
            core::ptr::write_bytes(ptr(hhdm,p),0,PAGE as usize);
        }
        arena.publish(&mut *boot_root,&mut *root(hhdm,phys[0]),
                      &mut *root(hhdm,phys[1]),&mut *root(hhdm,phys[2]))
            .unwrap_or_else(|_|fail("four_resident_publish_guarded_stacks"));
        arena.audit(&*boot_root,&*root(hhdm,phys[0]),
                    &*root(hhdm,phys[1]),&*root(hhdm,phys[2]))
            .unwrap_or_else(|_|fail("four_resident_audit_guarded_stacks"));
    }
    for i in 0..FOUR*6 { tlb::flush(VirtAddr::new(BASE+i as u64*PAGE)); }

    for i in 0..FOUR {
        prepare_elf(hhdm,leases[i],boot_root,i);
        let st=stacks[i].unwrap_or_else(||fail("four_resident_missing_stack"));
        let mut frame=UserSyscallFrame {
            hardware:user_syscall_abi::InterruptReturn {
                rip:entry(i),cs:cs as u64,rflags:2,
                rsp:USER_TOP,ss:ss as u64,
            },
            ..UserSyscallFrame::default()
        };
        frame.registers.r12=0x5700_0000+i as u64;
        frame.registers.r14=0x6400_0000+i as u64;
        contexts.prepare_bootstrap(
            &processes,(i+1) as u64,leases[i][0],
            KernelStack{bottom:st.bottom,top:st.top},frame,
        ).unwrap_or_else(|_|fail("four_resident_context_admission"));
    }
    if processes.occupied()!=FOUR || processes.running()!=0
        || contexts.count()!=FOUR || arena.occupied()!=FOUR {
        fail("four_resident_not_all_ready")
    }
    for i in 0..FOUR {
        let to=(i+1) as u64;
        let from=((i+1)%FOUR+1) as u64;
        let plan=contexts.plan_selected(&processes,from,to,boot)
            .unwrap_or_else(|_|fail("four_resident_context_selection"));
        let st=stacks[i].unwrap_or_else(||fail("four_resident_missing_context_stack"));
        if plan.pid!=to || plan.cr3_root!=leases[i][0]
            || plan.rsp0!=st.top || plan.frame.hardware.rip!=entry(i)
            || plan.frame.registers.r12!=0x5700_0000+i as u64
            || plan.frame.registers.r14!=0x6400_0000+i as u64
            || plan.frame.hardware.rsp!=USER_TOP {
            fail("four_resident_cross_pid_frame_alias")
        }
    }
    // Bind the four resident process records, scheduler generations, saved
    // 15-GPR IRET frames, guarded RSP0 and private FXSAVE64 ownership.
    // These 32 timer decisions are POLICY SIMULATIONS only. No user-mode
    // IRET, xAPIC EOI, CR3 write or hardware preemption happens here.
    // The real two-user xAPIC proof below remains mandatory and unchanged.
    let original_fx=unsafe{fx_state::enter()}
        .unwrap_or_else(||fail("four_resident_fx_cpu_contract"));
    let baseline_fx=unsafe{FxImage::capture_baseline()};
    let mut fx_bank=FourPidFxBank::new();
    let mut runqueue=Ring3RunQueue::<FOUR>::new();
    let mut fx_handles=[None;FOUR];
    let mut scheduler_handles=[None;FOUR];
    for i in 0..FOUR {
        let pid=(i+1) as u64;
        let fx_token=fx_bank.prepare(pid,&baseline_fx)
            .unwrap_or_else(|_|fail("four_resident_fx_prepare"));
        fx_bank.seed_xmm0(fx_token,0xf00d_0000+pid)
            .unwrap_or_else(|_|fail("four_resident_fx_private_seed"));
        fx_handles[i]=Some(fx_token);
        scheduler_handles[i]=Some(runqueue.admit(pid)
            .unwrap_or_else(|_|fail("four_resident_schedule_admission")));
    }
    if runqueue.start_next()!=Ok(scheduler_handles[0].unwrap())
        || fx_bank.occupied()!=FOUR {
        fail("four_resident_scheduler_start_or_fx_count")
    }
    for turn in 0..32 {
        let i=turn%FOUR;
        let j=(i+1)%FOUR;
        let current=scheduler_handles[i].unwrap();
        let chosen=runqueue.timer_tick(current)
            .unwrap_or_else(|_|fail("four_resident_simulated_policy_timer"));
        if chosen!=scheduler_handles[j].unwrap()
            || runqueue.running()!=Some(chosen) {
            fail("four_resident_scheduler_order")
        }
        let plan=contexts.plan_queue_handoff(
            &processes,&runqueue,current,chosen,boot,
        ).unwrap_or_else(|_|fail("four_resident_owned_policy_handoff"));
        if plan.pid!=(j+1) as u64
            || plan.cr3_root!=leases[j][0]
            || plan.rsp0!=stacks[j].unwrap().top
            || plan.frame.registers.r12!=0x5700_0000+j as u64
            || plan.frame.registers.r14!=0x6400_0000+j as u64
            || fx_bank.image_xmm0(fx_handles[j].unwrap())
                !=Ok(0xf00d_0000+(j+1) as u64) {
            fail("four_resident_fx_cr3_rsp0_gpr_mismatch")
        }
    }
    if runqueue.timer_switches()!=32
        || runqueue.slots().iter().any(|s|s.ticks!=8)
        || processes.running()!=0 {
        fail("four_resident_simulated_fairness_or_false_hardware")
    }
    for i in 0..FOUR {
        let expected=if i+1<FOUR {
            Some(scheduler_handles[i+1].unwrap())
        } else { None };
        if runqueue.exit_current(scheduler_handles[i].unwrap())!=Ok(expected){
            fail("four_resident_simulated_exit_order")
        }
    }
    if runqueue.running().is_some() {
        fail("four_resident_simulated_queue_still_running")
    }
    // Revoke READY ownership and invalidate every saved context before
    // unmapping the shared supervisor arena. None ever reached CPL3.
    for i in 0..FOUR {
        let pid=(i+1) as u64;
        if contexts.retire(&processes,pid).is_ok() {
            fail("four_resident_live_context_retired")
        }
        let released=processes.cancel_ready(pid,boot)
            .unwrap_or_else(|_|fail("four_resident_ready_cancel"));
        if released!=leases[i] || contexts.retire(&processes,pid).is_err() {
            fail("four_resident_revoke_ownership")
        }
    }
    // Both registries were revoked first. Scrub every retired PID's full
    // inactive 512-byte FX image and invalidate its scheduler generation;
    // neither old handle may ever select a replacement task.
    for i in 0..FOUR {
        let fx_token=fx_handles[i].unwrap();
        let q_handle=scheduler_handles[i].unwrap();
        if fx_bank.retire_quiescent(fx_token)!=Ok(true)
            || fx_bank.image_xmm0(fx_token).is_ok()
            || runqueue.reap(q_handle).is_err() {
            fail("four_resident_fx_wipe_or_scheduler_reap")
        }
    }
    if fx_bank.occupied()!=0 || runqueue.occupied()!=0
        || runqueue.timer_switches()!=32 {
        fail("four_resident_fx_scheduler_retirement")
    }
    // SAFETY: BSP retains original supervisor CR3 and stack, IF=0, and
    // no user task accessed FX state. Restore CR0/CR4 and BSP legacy xstate.
    unsafe { fx_state::leave(original_fx); }
    // SAFETY: no hardware user context was entered; boot CR3, BSP IF=0,
    // no RSP/TSS use of these mappings. Complete unpublication precedes
    // TLB invalidation, stack lease retirement and physical frame release.
    unsafe {
        arena.unpublish(&mut *boot_root,&mut *root(hhdm,phys[0]),
                        &mut *root(hhdm,phys[1]),&mut *root(hhdm,phys[2]))
            .unwrap_or_else(|_|fail("four_resident_unpublish"));
    }
    for i in 0..FOUR*6 { tlb::flush(VirtAddr::new(BASE+i as u64*PAGE)); }
    for st in stacks.into_iter().flatten() {
        if unsafe { arena.retire_after_quiescence(st.handle) }!=Ok(st.frames) {
            fail("four_resident_guard_lease_retirement")
        }
    }
    for owned in phys {
        if pmm::free_frame(owned).is_err() {
            fail("four_resident_double_free_or_leak")
        }
    }
    if arena.occupied()!=0 || contexts.count()!=0
        || processes.occupied()!=0 || actual_cr3()!=boot
        || pmm::statistics().allocated_frames!=before
        || unsafe{(*boot_root)[ROOT_INDEX]}!=0 {
        fail("four_resident_cleanup_or_boot_cr3")
    }
    serial::write_line(
        "WOLFOS_RING3_FOUR_RESIDENT_OK native_elf=4 private_cr3=4 guarded_rsp0=4 owned_frames=47 frame_gprs=4 executed=0 pmm_no_leak=1"
    );
    serial::write_line(
        "WOLFOS_RING3_FOUR_POLICY_FX_OK processes=4 queue_handles=4 fx_images=4 simulated_timer_decisions=32 hardware_irqs=0 fx_wiped=4 executed=0"
    );
}

/// Enter first native ELF through a REAL IRETQ with BSP IF=0.
/// On successful execution this function never returns.
pub fn enter(hhdm:u64)->!{
    cpu_interrupts::disable();
    if !interrupts::verify_ring3_preconditions() || !fx_state::supported() {
        fail("cpu_tss_or_fx_contract")
    }
    let (cs,ss,rsp0)=interrupts::ring3_cpu_state();
    let boot=actual_cr3();
    if boot==0||hhdm==0||interrupts::test_actual_rsp0()!=rsp0{
        fail("boot_rsp0_or_cr3")
    }
    let boot_root=root(hhdm,boot);
    if unsafe{(*boot_root)[ROOT_INDEX]}!=0{fail("guard_high_root_occupied")}
    #[cfg(feature = "p2-ring3-timer-preempt-smoke")]
    {
        validate_nonyield_elf_admission();
        #[cfg(not(feature="p2-ring3-timer-nonyield-smoke"))]
        serial::write_line(
            "WOLFOS_RING3_NONYIELD_PREFLIGHT_OK independent_elf=2 sys_yield=0 kernel_elf_loader=1 executed=0"
        );
        #[cfg(feature="p2-ring3-timer-nonyield-smoke")]
        serial::write_line(
            "WOLFOS_RING3_NONYIELD_PREFLIGHT_OK independent_elf=2 kernel_elf_loader=1 ready_for_execution=1"
        );
        #[cfg(feature="p3-ring3-four-elf-preflight-smoke")]
        {
            validate_four_nonyield_elf_admission();
            #[cfg(feature="p3-ring3-four-elf-live-smoke")]
            serial::write_line("WOLFOS_RING3_FOUR_ELF_PREFLIGHT_OK native_elf=4 unique_binaries=4 strict_loader=1 rx=4 rw_nx=4 executed=0");
            #[cfg(not(feature="p3-ring3-four-elf-live-smoke"))]
            serial::write_line("WOLFOS_RING3_FOUR_ELF_PREFLIGHT_OK native_elf=4 unique_binaries=4 strict_loader=1 rx=4 rw_nx=4 executed=2");
            prove_four_resident_preflight(hhdm,boot,boot_root,cs,ss);
        }
    }
    let before=pmm::statistics().allocated_frames;
    let mut phys=[0u64;PHYSICAL];
    for i in 0..PHYSICAL{
        phys[i]=pmm::allocate_frame().unwrap_or_else(||fail("pmem_exhausted"));
        if phys[i]==0||phys[i]&4095!=0||phys[i]==boot
            ||phys[..i].contains(&phys[i]){
            fail("non_exclusive_pmm_frames")
        }
    }
    if pmm::statistics().allocated_frames!=before+PHYSICAL{
        fail("pmm_baseline")
    }
    #[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
    {
        let phys_apic=crate::apic_timer_smoke::trusted_user_xapic_base()
            .unwrap_or_else(||fail("no_verified_bsp_xapic_physical_base"));
        let apic_pages=[phys[ARENA_FRAMES+COUNT*PER_PID],
            phys[ARENA_FRAMES+COUNT*PER_PID+1],
            phys[ARENA_FRAMES+COUNT*PER_PID+2]];
        // SAFETY: three exclusive PMM frames, no active private roots,
        // original boot CR3, interrupts masked and validated LAPIC physical
        // base from the current hardware/ACPI probe.
        unsafe{
            crate::user_xapic_high::publish(
                hhdm,boot,phys_apic,apic_pages
            ).unwrap_or_else(|_|fail("high_supervisor_xapic_publish"));
        }
        if unsafe{
            crate::user_xapic_high::read(
                crate::lapic_mmio_layout::XAPIC_ID_OFFSET)
        } >>24 != 0 {
            // Isolated Q35 single-BSP test's LAPIC logical ID is 0.
            fail("high_mmio_alias_wrong_bsp_id")
        }
        #[cfg(feature="p3-ring3-four-elf-live-smoke")]
        serial::write_line(
            "WOLFOS_RING3_TIMER_HIGH_MMIO_OK uc=1 supervisor_only=1 inherited_cr3=4 eoi_high=1 owned_frames=50"
        );
        #[cfg(not(feature="p3-ring3-four-elf-live-smoke"))]
        serial::write_line(
            "WOLFOS_RING3_TIMER_HIGH_MMIO_OK uc=1 supervisor_only=1 inherited_cr3=2 eoi_high=1 owned_frames=28"
        );
    }
    let mut arena=RuntimeArena::new([phys[0],phys[1],phys[2]],boot)
        .unwrap_or_else(|_|fail("guarded_arena_root"));
    let mut stacks=[None;COUNT];
    let mut leases=[[0u64;PER_PID];COUNT];
    let mut processes=ProcessTable::<COUNT,PER_PID>::new();
    for i in 0..COUNT{
        let b=3+i*4;
        let s=arena.reserve((i+1) as u64,
            [phys[b],phys[b+1],phys[b+2],phys[b+3]])
            .unwrap_or_else(|_|fail("guarded_pid_stack"));
        let entry_contract=Ring3Entry{
            rip:entry(i),user_rsp:USER_TOP,kernel_rsp0:s.top,
            user_cs:cs,user_ss:ss,
            rflags:if cfg!(feature="p2-ring3-irq-ready-smoke") {0x202}else{2},
        };
        let validated=if cfg!(feature="p2-ring3-irq-ready-smoke") {
            user_ring_entry::validate_interruptible(entry_contract)
        } else {
            user_ring_entry::validate(entry_contract)
        };
        if validated.is_err(){fail("strict_ring3_entry_metadata")}
        stacks[i]=Some(s);
        let at=ARENA_FRAMES+i*PER_PID;
        leases[i].copy_from_slice(&phys[at..at+PER_PID]);
        if processes.reserve(leases[i][0],leases[i])!=Ok((i+1) as u64){
            fail("disjoint_user_roots")
        }
    }
    // SAFETY: unused high PML4 root entry and disjoint zeroed private
    // page-table frames; no CPU currently references guarded VAs.
    unsafe{
        for &p in &phys[..3]{
            core::ptr::write_bytes(ptr(hhdm,p),0,PAGE as usize);
        }
        arena.publish(&mut *boot_root,&mut *root(hhdm,phys[0]),
            &mut *root(hhdm,phys[1]),&mut *root(hhdm,phys[2]))
            .unwrap_or_else(|_|fail("guard_root_publish"));
        arena.audit(&*boot_root,&*root(hhdm,phys[0]),
            &*root(hhdm,phys[1]),&*root(hhdm,phys[2]))
            .unwrap_or_else(|_|fail("guard_root_audit"));
    }
    for i in 0..COUNT*6{tlb::flush(VirtAddr::new(BASE+i as u64*PAGE));}
    for i in 0..COUNT {
        prepare_elf(hhdm,leases[i],boot_root,i);
    }
    // CPU modifies accessed/dirty PTE bits during these stack accesses,
    // which the audited arena already tolerates, while still denying U/S.
    let first=stacks[0].unwrap_or_else(||fail("pid1_missing_stack"));
    #[cfg(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
    let pic_before=[pic_read(0x21),pic_read(0xa1)];
    #[cfg(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
    {
        // Explicitly mask both legacy PICs before enabling CPL3 IF; the
        // local xAPIC timer is still intentionally NOT armed here.
        pic_write(0x21,0xff);
        pic_write(0xa1,0xff);
        if pic_read(0x21)!=0xff || pic_read(0xa1)!=0xff {
            fail("pic_mask_before_interruptible_cpl3")
        }
    }
    let control=unsafe{fx_state::enter()}
        .unwrap_or_else(||fail("fx_enable"));
    let baseline=unsafe{FxImage::capture_baseline()};
    let mut fx=RuntimeFxBank::new();
    let mut tokens=[None;COUNT];
    for i in 0..COUNT {
        tokens[i]=Some(fx.prepare((i+1) as u64,&baseline)
            .unwrap_or_else(|_|fail("fx_image_pid")));
    }
    let mut boot_rsp:u64;
    unsafe{asm!("mov {}, rsp",out(reg)boot_rsp,
        options(nomem,nostack,preserves_flags));}
    #[cfg(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
    let entry_flags=IRQ_USER_RFLAGS;
    #[cfg(not(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))))]
    let entry_flags=2u64;
    let mut saved_frames=[0u64;COUNT];
    for i in 1..COUNT {
        let st=stacks[i].unwrap_or_else(||fail("missing_user_stack"));
        let bootstrap=UserSyscallFrame{
            hardware:user_syscall_abi::InterruptReturn{
                rip:entry(i),cs:cs as u64,rflags:entry_flags,
                rsp:USER_TOP,ss:ss as u64,
            },
            ..UserSyscallFrame::default()
        };
        let frame=st.top-user_syscall_abi::FRAME_BYTES as u64;
        // SAFETY: independently PMM-backed and mapped supervisor-only leaf.
        // No other CPU/user process can access this pre-IRET frame.
        unsafe{(frame as *mut UserSyscallFrame).write(bootstrap);}
        saved_frames[i]=frame;
    }
    #[cfg(any(feature = "p2-ring3-timer-preempt-smoke",
              feature = "p3-ring3-event-wait-hardware-smoke"))]
    let (rr,rr_handles)={
        let mut q=Ring3RunQueue::<COUNT>::new();
        let mut handles=[None;COUNT];
        for i in 0..COUNT {
            handles[i]=Some(q.admit((i+1) as u64)
                .unwrap_or_else(|_|fail("rr_pid_admission")));
        }
        if q.start_next()!=Ok(handles[0].unwrap()) {fail("rr_initial_pid")}
        (q,handles.map(|h|h.unwrap()))
    };
    let state=Runtime{
        boot,hhdm,original_rsp0:rsp0,boot_rsp,before,owned:phys,
        leases,stacks:stacks.map(|x|x.unwrap_or_else(||fail("missing_runtime_stack"))),
        arena,processes,fx,
        fx_tokens:tokens.map(|x|x.unwrap_or_else(||fail("missing_fx_image"))),
        control,frames:saved_frames,current:0,
        yields:[0;COUNT],exits:[false;COUNT],hardware_traps:0,
        #[cfg(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
        pic_before,
        #[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
        timer_irqs:[0;COUNT],
        #[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
        timer_busy:[0;COUNT],
        #[cfg(feature = "p2-ring3-timer-preempt-smoke")]
        timer_preempts:[0;COUNT],
        #[cfg(feature="p3-ring3-four-elf-live-smoke")]
        first_exit_timer_counts:None,
        #[cfg(feature="p3-ring3-four-elf-live-smoke")]
        irq_eoi:Ring3IrqEoiLedger::new(),
        #[cfg(any(feature = "p2-ring3-timer-preempt-smoke",
                  feature = "p3-ring3-event-wait-hardware-smoke"))]
        rr,
        #[cfg(any(feature = "p2-ring3-timer-preempt-smoke",
                  feature = "p3-ring3-event-wait-hardware-smoke"))]
        rr_handles,
        #[cfg(feature = "p3-ring3-event-wait-hardware-smoke")]
        event_wait:None,
        #[cfg(feature = "p3-ring3-event-wait-hardware-smoke")]
        event_gate:EventWaitGate::new(),
        #[cfg(feature = "p3-ring3-event-wait-hardware-smoke")]
        event_wakes:0,
        #[cfg(feature = "p3-ring3-event-wait-hardware-smoke")]
        event_rejections:0,
    };
    unsafe{*RUNTIME.0.get()=Some(state);}
    let s=active();
    if unsafe{s.fx.switch_to(s.fx_tokens[0])}.is_err(){
        fail("activate_initial_fx")
    }
    if !unsafe{interrupts::test_handoff_rsp0(first.top)}{
        fail("activate_initial_tss_rsp0")
    }
    #[cfg(feature="p3-ring3-four-elf-live-smoke")]
    serial::write_line("WOLFOS_RING3_TIMER_ARMED_OK real_local_apic=1 user_if=1 no_yield_busy_loops=4");
    #[cfg(all(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"),
              not(feature="p3-ring3-four-elf-live-smoke")))]
    serial::write_line("WOLFOS_RING3_TIMER_ARMED_OK real_local_apic=1 user_if=1 no_yield_busy_loops=2");
    #[cfg(not(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
    serial::write_line(
        "WOLFOS_RING3_YIELD_START_OK separate_native_elf=2 live_user_roots=2 guarded_kernel_rsp0=2 fx_images=2 owned_frames=25"
    );
    #[cfg(all(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"),not(feature="p2-ring3-timer-nonyield-smoke")))]
    serial::write_line(
        "WOLFOS_RING3_YIELD_START_OK separate_native_elf=2 live_user_roots=2 guarded_kernel_rsp0=2 fx_images=2 owned_frames=28"
    );
    #[cfg(feature="p3-ring3-four-elf-live-smoke")]
    serial::write_line(
        "WOLFOS_RING3_FOUR_START_OK native_elf=4 user_if=1 private_cr3=4 guarded_rsp0=4 fx_images=4 owned_frames=50"
    );
    #[cfg(all(feature="p2-ring3-timer-nonyield-smoke",
              not(feature="p3-ring3-four-elf-live-smoke")))]
    serial::write_line(
        "WOLFOS_RING3_NONYIELD_START_OK native_elf=2 user_if=1 private_cr3=2 guarded_rsp0=2 fx_images=2 owned_frames=28"
    );
    // All accessible supervisor mappings are inherited in BOTH roots.
    // Real Ring3 selection happens only after actual private CR3 activated.
    unsafe{
        asm!("mov cr3, {}",in(reg)s.leases[0][0],
            options(nostack,preserves_flags));
    }
    if actual_cr3()!=s.leases[0][0]||
        s.processes.mark_running(1,s.leases[0][0]).is_err(){
        fail("boot_first_pid")
    }
    #[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
    TIMER_LIVE.store(true,core::sync::atomic::Ordering::Release);
    // SAFETY: GDT/TR/actual TSS.RSP0 verified, private page roots
    // checked, CPL3 RX and RW/NX pages physically separate, IF=0.
    // Real syscall handler switches to other saved CPU trap frame.
    unsafe{
        asm!(
            "push {ss}",
            "push {rsp}",
            "push {flags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss=in(reg)ss as u64,
            rsp=in(reg)USER_TOP,
            flags=in(reg)entry_flags,
            cs=in(reg)cs as u64,
            rip=in(reg)entry(0),
            options(noreturn),
        );
    }
}

/// Called by the existing native 15-GPR INT80 assembly entry and returns
/// a REAL alternative saved 15-GPR + CPU IRET frame pointer, on the newly
/// selected PID's own still-mapped, high-half, supervisor-only kernel stack.
#[unsafe(no_mangle)]
pub extern "C" fn wolfos_int80_syscall_dispatch(
    raw:*mut UserSyscallFrame,
)->*mut UserSyscallFrame{
    let s=active();
    let i=s.current;
    let active_root=actual_cr3();
    let pid=i as u64+1;
    let st=s.stacks[i];
    if raw.is_null()||raw as u64!=st.top-user_syscall_abi::FRAME_BYTES as u64
        ||active_root!=s.leases[i][0]
        ||interrupts::test_actual_rsp0()!=st.top
        ||CS::get_reg().0!=8
        ||s.processes.snapshot(pid).is_none_or(|p|
            p.state!=ProcessState::Running||p.cr3_root!=active_root)
        ||s.exits[i]{
        fail("trap_pid_cr3_rsp0_stack_ownership")
    }
    // SAFETY: assembly captured the CPU's hardware 5-field privilege
    // stack + 15 complete GPRs in this precise owned TSS.RSP0 interval.
    let f=unsafe{&mut *raw};
    let (cs,ss,_)=interrupts::ring3_cpu_state();
    #[cfg(feature="p3-ring3-event-wait-hardware-smoke")]
    let valid_arguments=f.registers.rsi==0 &&
        (if f.registers.rax==3 {f.registers.rdi==0}
         else if i==1 && f.registers.rax==SYS_SIGNAL_EVENT {
             f.registers.rdi==EVENT_ID || f.registers.rdi==EVENT_ID+1
         }else{f.registers.rdi==EVENT_ID});
    #[cfg(not(feature="p3-ring3-event-wait-hardware-smoke"))]
    let valid_arguments=f.registers.rdi==0&&f.registers.rsi==0;
    if f.hardware.cs!=cs as u64||f.hardware.ss!=ss as u64
        ||f.hardware.rsp!=USER_TOP
        ||!valid_test_user_flags(f.hardware.rflags)
        ||f.registers.r12!=pid
        ||f.registers.r14!=USER_ID[i]
        ||!valid_arguments {
        fail("real_user_gpr_iret_frame")
    }
    #[cfg(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
    {
        // These checks run on *real* INT80 hardware capture while CPL3
        // had IF=1. The trap is still voluntary; timer IRQ is NOT armed.
        let evidence=Evidence {
            pid,expected_pid:(i+1) as u64,
            actual_cr3:active_root,owned_cr3:s.leases[i][0],
            actual_rsp0:interrupts::test_actual_rsp0(),
            owned_stack_bottom:st.bottom,owned_stack_top:st.top,
            actual_frame_address:raw as u64,
            user_rip:f.hardware.rip,user_rsp:f.hardware.rsp,
            user_cs:f.hardware.cs,user_ss:f.hardware.ss,
            user_rflags:f.hardware.rflags,
            fpu_owner_pid:s.fx.active_pid().unwrap_or(0),
        };
        if user_irq_preempt_contract::validate(evidence).is_err() {
            fail("interruptible_ring3_irq_frame_or_pid_ownership")
        }
        if pic_read(0x21)!=0xff || pic_read(0xa1)!=0xff {
            fail("legacy_pic_unmasked_in_interruptible_guest")
        }
    }
    let val=unsafe{(ptr(s.hhdm,s.leases[i][5]) as *const u64).read_volatile()};
    let n=f.registers.rax;
    #[cfg(feature="p3-ring3-event-wait-hardware-smoke")]
    if i==1 && n==SYS_SIGNAL_EVENT
            && f.hardware.rip==sym::PID2_BAD_SIGNAL_RETURN {
        // The source is a genuine CPL3 syscall with a deliberately
        // incorrect event argument. It must return an error to PID2's
        // ORIGINAL hardware IRET frame without waking PID1, scheduling
        // a peer, changing PMM/FX ownership or claiming a timer IRQ.
        if f.registers.rdi!=EVENT_ID+1 || f.registers.r13!=1
            || val!=1 || s.yields[1]!=0 || s.event_wakes!=0
            || s.event_rejections!=0 || s.rr.timer_switches()!=0
            || s.rr.running()!=Some(s.rr_handles[1])
            || s.rr.slots()[0].state!=RrState::Blocked
            || s.processes.snapshot(1).is_none_or(|p|
                p.state!=ProcessState::Blocked
                || p.cr3_root!=s.leases[0][0]) {
            fail("bad_signal_invalid_hardware_provenance")
        }
        let ticket=s.event_wait
            .unwrap_or_else(||fail("bad_signal_missing_pending_ticket"));
        let queue_before=s.rr;
        let gate_before=s.event_gate;
        let blocked_before=s.processes.snapshot(1);
        let active_before=s.processes.snapshot(2);
        let saved_frame_before=s.frames[0];
        let fx_before=s.fx.active_pid();
        if s.event_gate.signal(&mut s.rr,ticket,f.registers.rdi)
                !=Err(EventError::WrongEvent)
            || s.rr!=queue_before
            || s.event_gate!=gate_before
            || s.processes.snapshot(1)!=blocked_before
            || s.processes.snapshot(2)!=active_before
            || s.frames[0]!=saved_frame_before
            || s.fx.active_pid()!=fx_before {
            fail("bad_signal_mutated_blocked_user_or_scheduler")
        }
        s.event_rejections=1;
        s.hardware_traps+=1;
        if s.hardware_traps>TRAPS {fail("extra_bad_signal_trap")}
        f.registers.rax=1; // explicit invalid-event status to Ring3
        serial::write_line(
            "WOLFOS_RING3_EVENT_TRAP pid=2 kind=signal_rejected count=1 cr3_private=1 rsp0_guarded=1"
        );
        serial::write_line(
            "WOLFOS_RING3_EVENT_REJECTED_OK wrong_event=78 pid1_still_blocked=1 queue_unchanged=1 saved_iret=1 no_fake_irq=1"
        );
        return raw;
    }
    #[cfg(all(not(feature="p2-ring3-timer-nonyield-smoke"),
              not(feature="p3-ring3-event-wait-hardware-smoke")))]
    let is_yield=n==TEST_YIELD&&f.hardware.rip==after_yield(i);
    #[cfg(feature="p3-ring3-event-wait-hardware-smoke")]
    let is_yield=(if i==0 {n==SYS_WAIT_EVENT}else{n==SYS_SIGNAL_EVENT})
        && f.hardware.rip==after_yield(i);
    #[cfg(feature="p2-ring3-timer-nonyield-smoke")]
    let is_yield=false; // no syscall may act as a cooperative yield
    let is_exit=n==3&&f.hardware.rip==after_exit(i);
    if !(is_yield||is_exit)||val!=f.registers.r13||val>ROUNDS{
        fail("real_ELF_rip_private_data_or_syscall")
    }
    if is_yield{
        if val!=s.yields[i]+1||val>ROUNDS{
            fail("nonsequential_yield_or_park")
        }
        #[cfg(not(feature="p3-ring3-event-wait-hardware-smoke"))]
        if s.processes.park_running(pid,active_root).is_err(){
            fail("nonsequential_yield_or_park")
        }
        #[cfg(feature="p3-ring3-event-wait-hardware-smoke")]
        {
            if i==0 {
                // A genuine user INT80 has supplied and authenticated this
                // full hardware GPR/IRET frame on the PID's pinned RSP0.
                // Block the real registry owner, then arm a one-use event
                // ticket *before* allowing the other user to execute.
                if s.event_wait.is_some()
                    || s.processes.block_running(pid,active_root).is_err(){
                    fail("real_wait_registry_block")
                }
                let token=s.event_gate.arm(&s.rr,s.rr_handles[0],EVENT_ID)
                    .unwrap_or_else(|_|fail("real_wait_event_registration"));
                let outcome=s.event_gate.commit(&mut s.rr,token)
                    .unwrap_or_else(|_|fail("real_wait_event_park"));
                if outcome!=EventCommit::Parked(Some(s.rr_handles[1]))
                    || s.rr.timer_switches()!=0 {
                    fail("real_wait_wrong_dispatch")
                }
                s.event_wait=Some(token);
            }else{
                // Only PID2's authenticated SIGNAL syscall can reach this
                // branch. The trusted event and exact nonreused ticket must
                // both match; this signal is not a timer IRQ and writes no EOI.
                if s.event_wakes!=0 || s.event_rejections!=1 {
                    fail("duplicate_or_missing_rejected_user_signal")
                }
                let ticket=s.event_wait
                    .take().unwrap_or_else(||fail("missing_user_wait_ticket"));
                if s.event_gate.signal(&mut s.rr,ticket,EVENT_ID)
                    !=Ok(EventDelivery::Woken(s.rr_handles[0])) {
                    fail("trusted_event_ticket_invalid")
                }
                // The ProcessTable correctly forbids using *any other
                // resident USER CR3* as an alleged supervisor root. Since
                // PID2 is still active, genuinely switch to the trusted,
                // still-mapped BOOT CR3 (IF=0) to perform the wake, then
                // restore PID2's private CR3 before scheduling it away.
                // High-half RSP0 and kernel mappings are pinned in both.
                unsafe{asm!("mov cr3, {}",in(reg)s.boot,
                           options(nostack,preserves_flags));}
                if actual_cr3()!=s.boot{fail("event_wake_boot_cr3_not_active")}
                let wake=s.processes.wake_blocked(1,s.boot);
                unsafe{asm!("mov cr3, {}",in(reg)active_root,
                           options(nostack,preserves_flags));}
                if actual_cr3()!=active_root || wake.is_err()
                    || s.processes.park_running(pid,active_root).is_err()
                    || s.rr.voluntary_yield(s.rr_handles[1])!=Ok(s.rr_handles[0]){
                    fail("trusted_event_wake_or_dispatch")
                }
                // Before resuming PID1, verify the original blocked INT80
                // frame remains pinned on its *own* guarded RSP0 stack.
                let saved=s.frames[0] as *const UserSyscallFrame;
                if s.frames[0]!=s.stacks[0].top
                        -user_syscall_abi::FRAME_BYTES as u64
                    || unsafe{(*saved).hardware.rip}!=after_yield(0)
                    || unsafe{(*saved).registers.rax}!=0
                    || unsafe{(*saved).registers.r12}!=1
                    || unsafe{(*saved).registers.r14}!=USER_ID[0]
                    || s.processes.snapshot(1).is_none_or(|p|
                        p.state!=ProcessState::Ready
                        || p.cr3_root!=s.leases[0][0]) {
                    fail("trusted_wake_lost_saved_hardware_frame")
                }
                s.event_wakes+=1;
            }
        }
        #[cfg(feature = "p2-ring3-timer-preempt-smoke")]
        if s.rr.voluntary_yield(s.rr_handles[i])!=Ok(s.rr_handles[1-i]) {
            fail("rr_voluntary_handoff_out_of_sync")
        }
        s.yields[i]=val;
        f.registers.rax=0;
    }else{
        if val!=ROUNDS
            ||s.yields[i]!=(if cfg!(feature="p2-ring3-timer-nonyield-smoke"){0}else{ROUNDS})
            ||s.processes.exit_zero(pid,active_root).is_err(){
            fail("early_or_bad_exit")
        }
        #[cfg(feature="p3-ring3-event-wait-hardware-smoke")]
        {
            if i==0 && (s.event_wait.is_some() || s.event_wakes!=1
                || s.rr.running()!=Some(s.rr_handles[0])
                || s.rr.timer_switches()!=0){
                fail("woken_pid_did_not_resume_own_cpl3_iret")
            }
            if s.rr.exit_current(s.rr_handles[i])
                !=Ok(if i==0 {Some(s.rr_handles[1])}else{None}){
                fail("real_event_exit_queue_owner")
            }
        }
        #[cfg(feature="p3-ring3-four-elf-live-smoke")]
        {
            // Snapshot the genuine IRQ-source counts at the FIRST EXIT,
            // while all four real users were still runnable. RR equality
            // must be checked at this moment, not after early finishers stop
            // accruing IRQs while survivors continue processing.
            if s.exits.iter().all(|done| !*done) {
                if s.first_exit_timer_counts.is_some() {
                    fail("four_live_duplicate_first_exit_snapshot")
                }
                s.first_exit_timer_counts=Some(s.timer_preempts);
            }
            let target=s.rr.exit_current(s.rr_handles[i])
                .unwrap_or_else(|_|fail("four_live_exit_queue_owner"));
            let more=s.exits.iter().enumerate()
                .any(|(j,done)|j!=i && !done);
            if target.is_some()!=more {
                fail("four_live_exit_queue_runnable_mismatch")
            }
        }
        #[cfg(all(feature = "p2-ring3-timer-preempt-smoke",
                  not(feature="p3-ring3-four-elf-live-smoke")))]
        if s.rr.exit_current(s.rr_handles[i])!=Ok(if s.exits[1-i]{None}else{Some(s.rr_handles[1-i])}) {
            fail("rr_exit_handoff_out_of_sync")
        }
        s.exits[i]=true;
    }
    s.frames[i]=raw as u64;
    s.hardware_traps+=1;
    if s.hardware_traps>TRAPS{fail("extra_user_trap")}
    #[cfg(feature="p3-ring3-event-wait-hardware-smoke")]
    {
        serial::write_fmt(format_args!(
            "WOLFOS_RING3_EVENT_TRAP pid={} kind={} count={} cr3_private=1 rsp0_guarded=1\n",
            pid,
            if is_yield {if i==0{"wait"}else{"signal"}}else{"exit"},
            val,
        ));
        if !is_yield && i==0 {
            serial::write_line(
                "WOLFOS_RING3_EVENT_RESUME_OK pid=1 wait_return=0 saved_gprs=1 fx_state=1 real_iret=1");
        }
    }
    #[cfg(not(feature="p2-ring3-timer-nonyield-smoke"))]
    serial::write_fmt(format_args!(
        "WOLFOS_RING3_YIELD_TRAP pid={} kind={} count={} cr3_private=1 rsp0_guarded=1\n",
        pid,if is_yield{"yield"}else{"exit"},val,
    ));
    #[cfg(feature="p3-ring3-four-elf-live-smoke")]
    serial::write_fmt(format_args!(
        "WOLFOS_RING3_FOUR_EXIT pid={} progress={} private_cr3=1 rsp0_guarded=1\n",
        pid,val,
    ));
    #[cfg(all(feature="p2-ring3-timer-nonyield-smoke",
              not(feature="p3-ring3-four-elf-live-smoke")))]
    serial::write_fmt(format_args!(
        "WOLFOS_RING3_NONYIELD_EXIT pid={} progress={} private_cr3=1 rsp0_guarded=1\n",
        pid,val,
    ));
    if s.exits.iter().all(|done|*done) {
        if !s.exits[i] { fail("unexpected_finished_other") }
        if s.hardware_traps!=TRAPS ||
            s.yields!=[if cfg!(feature="p2-ring3-timer-nonyield-smoke"){0}else{ROUNDS};COUNT] {
            fail("incomplete_two_ELF_schedule")
        }
        #[cfg(feature="p3-ring3-event-wait-hardware-smoke")]
        {
            if s.event_wait.is_some() || s.event_wakes!=1
                || s.event_rejections!=1 || s.event_gate.in_flight()!=0
                || s.rr.running().is_some() || s.rr.timer_switches()!=0
                || s.rr.slots().iter().any(|slot|slot.state!=RrState::Exited){
                fail("real_event_wait_policy_or_irq_counter_corrupted")
            }
            serial::write_line(
                "WOLFOS_RING3_EVENT_HARDWARE_OK user_wait=1 rejected_signal=1 trusted_signal=1 resumed_wait=1 exits=2 traps=5 timer_switches=0 real_int80_iret=1 independent_cr3=2 rsp0=2 fx=2");
        }
        if unsafe{s.fx.suspend(s.fx_tokens[i])}.is_err(){
            fail("capture_last_pid_fx")
        }
        // Critical: return to BOOT CR3 and original TSS/FX while the current
        // high-half kernel trap stack is still mapped, then JUMP (no return)
        // onto the separate retained BSP stack BEFORE unmapping anything.
        unsafe{asm!("mov cr3, {}",in(reg)s.boot,
                   options(nostack,preserves_flags));}
        if actual_cr3()!=s.boot||
            !unsafe{interrupts::test_handoff_rsp0(s.original_rsp0)}{
            fail("restore_boot_rsp0_or_cr3")
        }
        unsafe{fx_state::leave(s.control);}
        let escape=s.boot_rsp;
        #[cfg(feature = "p2-ring3-irq-ready-smoke")]
        serial::write_line(
            "WOLFOS_RING3_IRQ_READY_OK actual_cpl3_if=1 hardware_int80_traps=10 pid_cr3_rsp0_fx_checks=10 pic_masked=1 timer_armed=0"
        );
        #[cfg(all(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"),not(feature="p2-ring3-timer-nonyield-smoke")))]
        serial::write_line(
            "WOLFOS_RING3_IRQ_READY_OK actual_cpl3_if=1 hardware_int80_traps=10 pid_cr3_rsp0_fx_checks=10 pic_masked=1 timer_armed=1"
        );
        #[cfg(feature="p3-ring3-four-elf-live-smoke")]
        serial::write_line(
            "WOLFOS_RING3_IRQ_READY_OK actual_cpl3_if=1 hardware_int80_traps=4 pid_cr3_rsp0_fx_checks=4 pic_masked=1 timer_armed=1"
        );
        #[cfg(all(feature="p2-ring3-timer-nonyield-smoke",
                  not(feature="p3-ring3-four-elf-live-smoke")))]
        serial::write_line(
            "WOLFOS_RING3_IRQ_READY_OK actual_cpl3_if=1 hardware_int80_traps=2 pid_cr3_rsp0_fx_checks=2 pic_masked=1 timer_armed=1"
        );
        #[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
        {
            if s.timer_busy.iter().any(|&v|v==0)||
                s.timer_irqs.iter().any(|&v|v==0){
                fail("missing_real_cpl3_busy_loop_timer_irq")
            }
            TIMER_LIVE.store(false,core::sync::atomic::Ordering::Release);
            #[cfg(all(feature = "p2-ring3-timer-preempt-smoke",not(feature="p2-ring3-timer-nonyield-smoke")))]
            {
                if s.timer_preempts!=[1,1] {
                    fail("missing_two_real_involuntary_pid_switches")
                }
                let slots=s.rr.slots();
                if s.rr.timer_switches()!=2 || s.rr.running().is_some()
                   || slots[0].handle!=s.rr_handles[0] || slots[1].handle!=s.rr_handles[1]
                   || slots[0].state!=RrState::Exited
                   || slots[1].state!=RrState::Exited
                   || slots[0].ticks!=1 || slots[1].ticks!=1 {
                    fail("rr_hardware_policy_ledger_mismatch")
                }
                serial::write_fmt(format_args!(
                    "WOLFOS_RING3_TIMER_PREEMPT_OK real_timer_switches=2 pid1_to_pid2={} pid2_to_pid1={} irq_frame_preserved=1 private_cr3=1 tss_rsp0=1 fx_save_restore=1 no_int80=1\n",
                    s.timer_preempts[0],s.timer_preempts[1]
                ));
                serial::write_line("WOLFOS_RING3_RR_POLICY_OK hardware_timer_decisions=2 voluntary_yield_decisions=8 exited=2 single_running=1");
            }
            #[cfg(feature="p3-ring3-four-elf-live-smoke")]
            {
                let switches=s.timer_preempts.iter().sum::<u64>();
                let eligible=s.timer_busy.iter().sum::<u64>();
                let irq=s.irq_eoi.verify_drained()
                    .unwrap_or_else(|_|fail("four_live_eoi_unfinished_or_double"));
                let raw_irqs=s.timer_irqs.iter().sum::<u64>();
                // Independent counters: one physical EOI per authenticated
                // real xAPIC IRQ, then exactly ONE same-PID IRET or cross-PID
                // handoff. No YIELD or EXIT can increase this IRQ ledger.
                if irq.received!=raw_irqs || irq.eoi!=raw_irqs
                    || irq.switched!=switches
                    || irq.resumed_same.checked_add(irq.switched)!=Some(raw_irqs)
                    || irq.received<eligible {
                    fail("four_live_eoi_irqs_or_switches_disagree")
                }
                let first=s.first_exit_timer_counts
                    .unwrap_or_else(||fail("four_live_missing_first_exit_evidence"));
                let first_min=*first.iter().min().unwrap();
                let first_max=*first.iter().max().unwrap();
                let last_min=*s.timer_preempts.iter().min().unwrap();
                let slots=s.rr.slots();
                let bad_slot=slots.iter().enumerate().any(|(i,slot)|
                    slot.state!=RrState::Exited
                    || slot.handle!=s.rr_handles[i]
                    // Every authenticated eligible IRQ is charged to its
                    // source, not only the ones that trigger a context switch.
                    || slot.ticks!=s.timer_busy[i]);
                // Strict FIFO round-robin fairness must hold WHILE all four
                // PIDs are READY/RUNNING. After a PID legitimately EXITs,
                // it cannot collect more IRQ counts; surviving users may
                // accumulate additional authentic preemptions. Requiring
                // equal *lifetime* counts would be mathematically wrong.
                if switches<16 || last_min<4 || first_min<4
                    || first_max-first_min>1
                    || eligible<2*switches
                    || s.rr.current_slice_ticks()!=0
                    || s.rr.timer_switches()!=switches
                    || s.rr.running().is_some() || bad_slot {
                    serial::write_fmt(format_args!(
                        "WOLFOS_RING3_FOUR_DIAGNOSTIC total={} pids={:?} first_exit_pids={:?} policy_switches={} ticks=[{},{},{},{}] first_min={} first_spread={} running={:?} bad_slot={}\n",
                        switches,s.timer_preempts,first,s.rr.timer_switches(),
                        slots[0].ticks,slots[1].ticks,slots[2].ticks,slots[3].ticks,
                        first_min,first_max-first_min,s.rr.running(),bad_slot
                    ));
                    fail("four_live_real_irq_fairness_or_ledger")
                }
                serial::write_fmt(format_args!(
                    "WOLFOS_RING3_FOUR_EOI_OK irq_received={} eoi_writes={} same_pid_iret={} cross_pid_switches={} drained=1\n",
                    irq.received,irq.eoi,irq.resumed_same,irq.switched
                ));
                serial::write_fmt(format_args!(
                    "WOLFOS_RING3_FOUR_HARDWARE_OK timer_switches={} pid1={} pid2={} pid3={} pid4={} fair_four_min={} fair_four_spread={} quantum_ticks=2 eligible_irqs={} voluntary_yields=0 exits=4 progress_per_pid=16 private_cr3=4 tss_rsp0=4 fx_state=4 executed=4\n",
                    switches,s.timer_preempts[0],s.timer_preempts[1],
                    s.timer_preempts[2],s.timer_preempts[3],
                    first_min,first_max-first_min,eligible
                ));
            }
            #[cfg(all(feature="p2-ring3-timer-nonyield-smoke",
                      not(feature="p3-ring3-four-elf-live-smoke")))]
            {
                let switches=s.timer_preempts[0]+s.timer_preempts[1];
                let slots=s.rr.slots();
                if switches<8 || s.timer_preempts.iter().any(|&n|n<4)
                    || s.timer_preempts[0].abs_diff(s.timer_preempts[1])>1
                    || s.rr.timer_switches()!=switches || s.rr.running().is_some()
                    || slots[0].state!=RrState::Exited
                    || slots[1].state!=RrState::Exited
                    || slots[0].handle!=s.rr_handles[0]
                    || slots[1].handle!=s.rr_handles[1]
                    || slots[0].ticks!=s.timer_preempts[0]
                    || slots[1].ticks!=s.timer_preempts[1] {
                    fail("nonyield_hardware_rr_fairness_or_ledger")
                }
                serial::write_fmt(format_args!(
                    "WOLFOS_RING3_NONYIELD_HARDWARE_OK timer_switches={} pid1={} pid2={} voluntary_yields=0 exits=2 progress_per_pid=16 private_cr3=1 tss_rsp0=1 fx_state=1\n",
                    switches,s.timer_preempts[0],s.timer_preempts[1]
                ));
            }
            #[cfg(not(feature = "p2-ring3-timer-preempt-smoke"))]
            serial::write_fmt(format_args!(
                "WOLFOS_RING3_TIMER_HARDWARE_OK real_apic_irqs={} pid1_busy_irqs={} pid2_busy_irqs={} eoi_each=1 real_user_if=1 yield_free_busy_windows=8 same_pid_iret=1\n",
                s.timer_irqs[0]+s.timer_irqs[1],
                s.timer_busy[0],s.timer_busy[1]
            ));
            #[cfg(all(feature = "p2-ring3-timer-preempt-smoke",not(feature="p2-ring3-timer-nonyield-smoke")))]
            serial::write_fmt(format_args!(
                "WOLFOS_RING3_TIMER_HARDWARE_OK real_apic_irqs={} pid1_busy_irqs={} pid2_busy_irqs={} eoi_each=1 real_user_if=1 yield_free_busy_windows=8 same_pid_iret=0\n",
                s.timer_irqs[0]+s.timer_irqs[1],
                s.timer_busy[0],s.timer_busy[1]
            ));
        }
        #[cfg(all(not(feature="p2-ring3-timer-nonyield-smoke"),
                  not(feature="p3-ring3-event-wait-hardware-smoke")))]
        serial::write_line(
            "WOLFOS_RING3_YIELD_HARDWARE_OK native_elves=2 real_cpl3=1 total_traps=10 yields=8 exits=2 iret_cross_pid=9 separate_cr3=1 distinct_guarded_rsp0=1 xmm0_preserved=1"
        );
        // SAFETY: never execute on any owned guardable PID stack again.
        unsafe{
            asm!(
                "mov rsp, {stack}",
                "and rsp, -16",
                "sub rsp, 8",
                "jmp {done}",
                stack=in(reg)escape,
                done=sym finalize,
                options(noreturn),
            );
        }
    }
    #[cfg(feature="p3-ring3-four-elf-live-smoke")]
    let next={
        let active=s.rr.running().unwrap_or_else(||fail("four_live_missing_queue_target"));
        let index=usize::try_from(active.pid-1)
            .unwrap_or_else(|_|fail("four_live_target_pid_overflow"));
        if index>=COUNT || s.rr_handles[index]!=active || s.exits[index] {
            fail("four_live_wrong_queue_target")
        }
        index
    };
    #[cfg(not(feature="p3-ring3-four-elf-live-smoke"))]
    let next=1-i;
    #[cfg(any(feature = "p2-ring3-timer-preempt-smoke",
              feature = "p3-ring3-event-wait-hardware-smoke"))]
    if s.rr.running()!=Some(s.rr_handles[next]) {
        fail("rr_selected_pid_differs_from_hardware_target")
    }
    if s.frames[next]==0||s.frames[next]!=
        s.stacks[next].top-user_syscall_abi::FRAME_BYTES as u64
        ||s.exits[next]{
        fail("next_trap_frame_not_owned")
    }
    // The target frame was either synthesized in its own kernel stack
    // before initial Ring3 entry, or captured from that PID's genuine
    // hardware INT80 on the same independently protected stack.
    if unsafe{s.fx.switch_to(s.fx_tokens[next])}.is_err(){
        fail("per_pid_fx_switch")
    }
    if s.fx.image_xmm0(s.fx_tokens[i])!=Ok(USER_ID[i]){
        fail("user_fx_cpu_state_not_isolated")
    }
    if !unsafe{interrupts::test_handoff_rsp0(s.stacks[next].top)}{
        fail("tss_target_stack_not_mapped")
    }
    unsafe{asm!("mov cr3, {}",in(reg)s.leases[next][0],
               options(nostack,preserves_flags));}
    if actual_cr3()!=s.leases[next][0]||
        s.processes.mark_running((next+1) as u64,s.leases[next][0]).is_err()||
        s.processes.running()!=1 {
        fail("atomic_next_pid_activation")
    }
    s.current=next;
    #[cfg(feature="p3-ring3-event-wait-hardware-smoke")]
    serial::write_fmt(format_args!(
        "WOLFOS_RING3_EVENT_SWITCH from={} to={} private_cr3=1 tss_rsp0=1 fx_saved=1\n",
        pid,next+1,
    ));
    #[cfg(not(feature="p2-ring3-timer-nonyield-smoke"))]
    serial::write_fmt(format_args!(
        "WOLFOS_RING3_YIELD_SWITCH from={} to={} private_cr3=1 tss_rsp0=1 fx_saved=1\n",
        pid,next+1,
    ));
    #[cfg(feature="p3-ring3-four-elf-live-smoke")]
    serial::write_fmt(format_args!(
        "WOLFOS_RING3_FOUR_EXIT_SWITCH from={} to={} private_cr3=1 tss_rsp0=1 fx_saved=1\n",
        pid,next+1,
    ));
    #[cfg(all(feature="p2-ring3-timer-nonyield-smoke",
              not(feature="p3-ring3-four-elf-live-smoke")))]
    serial::write_fmt(format_args!(
        "WOLFOS_RING3_NONYIELD_EXIT_SWITCH from={} to={} private_cr3=1 tss_rsp0=1 fx_saved=1\n",
        pid,next+1,
    ));
    s.frames[next] as *mut UserSyscallFrame
}

/// Runs on preserved BOOT kernel stack, boot CR3, original TSS.RSP0 and FX,
/// never on a guarded PID stack. Only here can we unmap/free PID resources.
extern "C" fn finalize()->! {
    let s=active();
    if actual_cr3()!=s.boot||
        interrupts::test_actual_rsp0()!=s.original_rsp0||
        !s.exits.iter().all(|x|*x)||s.processes.running()!=0{
        fail("unsafe_cleanup_hardware_ownership")
    }
    for i in 0..COUNT{
        let pid=i as u64+1;
        let p=s.processes.reap(pid,s.boot)
            .unwrap_or_else(|_|fail("pid_reap"));
        if p!=s.leases[i]||s.fx.retire_quiescent(s.fx_tokens[i])!=Ok(true)
            ||s.fx.image_xmm0(s.fx_tokens[i]).is_ok(){
            fail("pid_fx_or_frame_retirement")
        }
    }
    unsafe{
        s.arena.unpublish(
            &mut *root(s.hhdm,s.boot),
            &mut *root(s.hhdm,s.owned[0]),
            &mut *root(s.hhdm,s.owned[1]),
            &mut *root(s.hhdm,s.owned[2]),
        ).unwrap_or_else(|_|fail("retire_guarded_root"));
    }
    for i in 0..COUNT*6{tlb::flush(VirtAddr::new(BASE+i as u64*PAGE));}
    for i in 0..COUNT{
        // SAFETY: first restore BSP escape stack, original CR3/TSS/FX,
        // finish ALL CPL3 tasks, retire their active roots, unpublish and
        // invalidate guarded virtual leaves on BSP only.
        if unsafe{s.arena.retire_after_quiescence(s.stacks[i].handle)}
            !=Ok(s.stacks[i].frames){
            fail("guarded_stack_retirement")
        }
    }
    #[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
    {
        if !crate::apic_timer_smoke::stop_user_timer(){
            fail("failed_lvt_svr_pic_restore_after_user_timer")
        }
        // SAFETY: no IRQ delivery, active CPU is on BSP boot CR3 and
        // safe stack, users are EXITED, and timer's LVT is masked.
        unsafe{
            crate::user_xapic_high::unpublish(
                s.hhdm,s.boot,[s.owned[ARENA_FRAMES+COUNT*PER_PID],
                    s.owned[ARENA_FRAMES+COUNT*PER_PID+1],
                    s.owned[ARENA_FRAMES+COUNT*PER_PID+2]]
            ).unwrap_or_else(|_|fail("high_mmio_teardown"));
        }
        serial::write_line(
            "WOLFOS_RING3_TIMER_CLEANUP_OK actual_irq_eoi=1 lvt_masked=1 pic_restored=1 high_mmio_unmapped=1"
        );
    }
    for physical in s.owned{
        if pmm::free_frame(physical).is_err(){fail("exact_pmm_reclaim")}
    }
    if pmm::statistics().allocated_frames!=s.before
        ||s.processes.occupied()!=0||s.fx.occupied()!=0
        ||s.arena.occupied()!=0||actual_cr3()!=s.boot
        ||unsafe{(*root(s.hhdm,s.boot))[ROOT_INDEX]}!=0{
        fail("post_yield_resource_leak")
    }
    #[cfg(feature = "p2-ring3-irq-ready-smoke")]
    {
        if x86_64::instructions::interrupts::are_enabled() {
            fail("restore_pic_only_with_kernel_if_off")
        }
        pic_write(0x21,s.pic_before[0]);
        pic_write(0xa1,s.pic_before[1]);
        if pic_read(0x21)!=s.pic_before[0]||pic_read(0xa1)!=s.pic_before[1] {
            fail("pic_mask_restore")
        }
        serial::write_line("WOLFOS_RING3_IRQ_READY_RESTORE_OK original_pic_masks=1 kernel_if_off=1");
    }
    #[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
    {
        if x86_64::instructions::interrupts::are_enabled() {
            fail("timer_guest_cleanup_IF_unexpectedly_enabled")
        }
        serial::write_line(
            "WOLFOS_RING3_IRQ_READY_RESTORE_OK original_pic_masks=1 kernel_if_off=1"
        );
    }
    #[cfg(not(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
    serial::write_line(
        "WOLFOS_RING3_YIELD_CLEANUP_OK frames_freed=25 both_ELF_exited=1 fx_wiped=2 tss_restored=1 cr3_restored=1 pmm_no_leak=1"
    );
    #[cfg(feature="p3-ring3-event-wait-hardware-smoke")]
    serial::write_line(
        "WOLFOS_RING3_EVENT_CLEANUP_OK frames_freed=25 wait_ticket_drained=1 fx_wiped=2 tss_restored=1 cr3_restored=1 pmm_no_leak=1"
    );
    #[cfg(all(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"),not(feature="p2-ring3-timer-nonyield-smoke")))]
    serial::write_line(
        "WOLFOS_RING3_YIELD_CLEANUP_OK frames_freed=28 both_ELF_exited=1 fx_wiped=2 tss_restored=1 cr3_restored=1 pmm_no_leak=1"
    );
    #[cfg(feature="p3-ring3-four-elf-live-smoke")]
    serial::write_line(
        "WOLFOS_RING3_FOUR_CLEANUP_OK frames_freed=50 exited=4 fx_wiped=4 tss_restored=1 cr3_restored=1 pmm_no_leak=1"
    );
    #[cfg(all(feature="p2-ring3-timer-nonyield-smoke",
              not(feature="p3-ring3-four-elf-live-smoke")))]
    serial::write_line(
        "WOLFOS_RING3_NONYIELD_CLEANUP_OK frames_freed=28 exited=2 fx_wiped=2 tss_restored=1 cr3_restored=1 pmm_no_leak=1"
    );
    serial::qemu_exit_success();
}
