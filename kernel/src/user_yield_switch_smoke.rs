//! Actual CPL3-to-CPL3 cooperative task switches between TWO separately
//! linked native ET_EXEC ELF64 applications, each on its own CR3, its own
//! real guarded high-half TSS.RSP0 stack, its own FXSAVE64 image, its own
//! private user text/data/stack. Zero APs run user tasks. No timer preemption.
//!
//! Test-only SYS_YIELD=9; never part of the stable WolfOS syscall ABI.
//! The existing 15-GPR INT80 entry restores the POINTER we return, then
//! IRETQ resumes the other PID. Faults and unexpected syscalls fail closed.
use core::{arch::asm,cell::UnsafeCell};
use x86_64::{VirtAddr,instructions::{interrupts as cpu_interrupts,tlb},
             instructions::segmentation::{CS,Segment},registers::control::Cr3};
use crate::{
    elf64_preflight::preflight,elf64_page_image::{materialize,PAGE_SIZE},
    high_half_stack_arena::{GuardedArena,Stack,ROOT_INDEX,BASE,PAGE,OWNED as ARENA_FRAMES},
    process_table::ProcessTable,process_lifecycle::ProcessState,
    user_syscall_abi::{self,UserSyscallFrame},
    user_ring_entry::{self,Ring3Entry},
    user_fx_bank::{FxImage,FxHandle,UserFxBank},
    fx_state,kernel_half_shadow,interrupts,pmm,serial,
};
mod sym {include!(concat!(env!("OUT_DIR"),"/wolfos_yield_symbols.rs"));}
const ELFS:[&[u8];2]=[
    include_bytes!(concat!(env!("OUT_DIR"),"/wolfos-yield-1.elf")),
    include_bytes!(concat!(env!("OUT_DIR"),"/wolfos-yield-2.elf")),
];
const COUNT:usize=2;
const PER_PID:usize=7;
const PHYSICAL:usize=ARENA_FRAMES+COUNT*PER_PID; // 11+14=25
const P:u64=1;const W:u64=2;const U:u64=4;const NX:u64=1<<63;
const CODE:u64=0x401000;const DATA:u64=0x403000;
const STACK:u64=0x404000;const USER_TOP:u64=STACK+PAGE;
const TEST_YIELD:u64=9;
const TRAPS:usize=10;
const ROUNDS:u64=4;
const USER_ID:[u64;COUNT]=[0x5a5a_0001_0000_0001,0x5a5a_0001_0000_0002];

fn fail(why:&str)->!{
    serial::write_fmt(format_args!("WOLFOS_RING3_YIELD_ERROR {why}\n"));
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
    arena:GuardedArena,
    processes:ProcessTable<COUNT,PER_PID>,
    fx:UserFxBank,
    fx_tokens:[FxHandle;COUNT],
    control:fx_state::OriginalControl,
    frames:[u64;COUNT],
    current:usize,
    yields:[u64;COUNT],
    exits:[bool;COUNT],
    hardware_traps:usize,
}
struct BspRuntime(UnsafeCell<Option<Runtime>>);
// SAFETY: only one BSP may access the runtime; IF=0 from admission until
// exit, no preemptible AP/async scheduler and no parallel user task exists.
unsafe impl Sync for BspRuntime {}
static RUNTIME:BspRuntime=BspRuntime(UnsafeCell::new(None));
fn active()->&'static mut Runtime{
    unsafe{(*RUNTIME.0.get()).as_mut().unwrap_or_else(||fail("not_started"))}
}

fn entry(pid:usize)->u64{
    if pid==0{sym::PID1_ENTRY}else{sym::PID2_ENTRY}
}
fn after_yield(pid:usize)->u64{
    if pid==0{sym::PID1_AFTER_YIELD}else{sym::PID2_AFTER_YIELD}
}
fn after_exit(pid:usize)->u64{
    if pid==0{sym::PID1_AFTER_EXIT}else{sym::PID2_AFTER_EXIT}
}
fn progress(pid:usize)->u64{
    if pid==0{sym::PID1_PROGRESS}else{sym::PID2_PROGRESS}
}
fn prepare_elf(hhdm:u64,frames:[u64;7],source:*const [u64;512],
               pid:usize){
    let elf=ELFS[pid];
    let plan=preflight(elf).unwrap_or_else(|_|fail("independent_elf_preflight"));
    if plan.entry!=CODE||plan.len!=2||entry(pid)!=CODE||
        progress(pid)!=DATA||after_yield(pid)<=CODE||
        after_exit(pid)<=after_yield(pid)||after_exit(pid)>=DATA{
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
    let mut arena=GuardedArena::new([phys[0],phys[1],phys[2]],boot)
        .unwrap_or_else(|_|fail("guarded_arena_root"));
    let mut stacks=[None;COUNT];
    let mut leases=[[0u64;PER_PID];COUNT];
    let mut processes=ProcessTable::<COUNT,PER_PID>::new();
    for i in 0..COUNT{
        let b=3+i*4;
        let s=arena.reserve((i+1) as u64,
            [phys[b],phys[b+1],phys[b+2],phys[b+3]])
            .unwrap_or_else(|_|fail("guarded_pid_stack"));
        if user_ring_entry::validate(Ring3Entry{
            rip:entry(i),user_rsp:USER_TOP,kernel_rsp0:s.top,
            user_cs:cs,user_ss:ss,rflags:2,
        }).is_err(){fail("strict_ring3_entry_metadata")}
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
    for i in 0..12{tlb::flush(VirtAddr::new(BASE+i*PAGE));}
    for i in 0..COUNT {
        prepare_elf(hhdm,leases[i],boot_root,i);
    }
    // CPU modifies accessed/dirty PTE bits during these stack accesses,
    // which the audited arena already tolerates, while still denying U/S.
    let first=stacks[0].unwrap_or_else(||fail("pid1_missing_stack"));
    let second=stacks[1].unwrap_or_else(||fail("pid2_missing_stack"));
    let control=unsafe{fx_state::enter()}
        .unwrap_or_else(||fail("fx_enable"));
    let baseline=unsafe{FxImage::capture_baseline()};
    let mut fx=UserFxBank::new();
    let mut tokens=[None;COUNT];
    for i in 0..COUNT {
        tokens[i]=Some(fx.prepare((i+1) as u64,&baseline)
            .unwrap_or_else(|_|fail("fx_image_pid")));
    }
    let mut boot_rsp:u64;
    unsafe{asm!("mov {}, rsp",out(reg)boot_rsp,
        options(nomem,nostack,preserves_flags));}
    let bootstrap=UserSyscallFrame{
        hardware:user_syscall_abi::InterruptReturn{
            rip:entry(1),cs:cs as u64,rflags:2,
            rsp:USER_TOP,ss:ss as u64,
        },
        ..UserSyscallFrame::default()
    };
    let second_frame=second.top-user_syscall_abi::FRAME_BYTES as u64;
    // SAFETY: preflight-mapped, fully reserved 16 KiB supervisor-only
    // upper-half stack leaf; frame is exactly bounded by its stack.
    unsafe{(second_frame as *mut UserSyscallFrame).write(bootstrap);}
    let state=Runtime{
        boot,hhdm,original_rsp0:rsp0,boot_rsp,before,owned:phys,
        leases,stacks:[first,second],arena,processes,fx,
        fx_tokens:[tokens[0].unwrap(),tokens[1].unwrap()],
        control,frames:[0,second_frame],current:0,
        yields:[0;COUNT],exits:[false;COUNT],hardware_traps:0,
    };
    unsafe{*RUNTIME.0.get()=Some(state);}
    let s=active();
    if unsafe{s.fx.switch_to(s.fx_tokens[0])}.is_err(){
        fail("activate_initial_fx")
    }
    if !unsafe{interrupts::test_handoff_rsp0(first.top)}{
        fail("activate_initial_tss_rsp0")
    }
    serial::write_line(
        "WOLFOS_RING3_YIELD_START_OK separate_native_elf=2 live_user_roots=2 guarded_kernel_rsp0=2 fx_images=2 owned_frames=25"
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
            flags=in(reg)2u64,
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
    if f.hardware.cs!=cs as u64||f.hardware.ss!=ss as u64
        ||f.hardware.rsp!=USER_TOP
        ||!user_syscall_abi::valid_user_rflags(f.hardware.rflags)
        ||f.registers.r12!=pid
        ||f.registers.r14!=USER_ID[i]
        ||f.registers.rdi!=0||f.registers.rsi!=0 {
        fail("real_user_gpr_iret_frame")
    }
    let val=unsafe{(ptr(s.hhdm,s.leases[i][5]) as *const u64).read_volatile()};
    let n=f.registers.rax;
    let is_yield=n==TEST_YIELD&&f.hardware.rip==after_yield(i);
    let is_exit=n==3&&f.hardware.rip==after_exit(i);
    if !(is_yield||is_exit)||val!=f.registers.r13||val>ROUNDS{
        fail("real_ELF_rip_private_data_or_syscall")
    }
    if is_yield{
        if val!=s.yields[i]+1||val>ROUNDS||
            s.processes.park_running(pid,active_root).is_err(){
            fail("nonsequential_yield_or_park")
        }
        s.yields[i]=val;
        f.registers.rax=0;
    }else{
        if val!=ROUNDS||s.yields[i]!=ROUNDS
            ||s.processes.exit_zero(pid,active_root).is_err(){
            fail("early_or_bad_exit")
        }
        s.exits[i]=true;
    }
    s.frames[i]=raw as u64;
    s.hardware_traps+=1;
    if s.hardware_traps>TRAPS{fail("extra_user_trap")}
    serial::write_fmt(format_args!(
        "WOLFOS_RING3_YIELD_TRAP pid={} kind={} count={} cr3_private=1 rsp0_guarded=1\n",
        pid,if is_yield{"yield"}else{"exit"},val,
    ));
    let next=1-i;
    if s.exits[next] {
        if !s.exits[i] { fail("unexpected_finished_other") }
        if s.hardware_traps!=TRAPS||s.yields!=[ROUNDS;COUNT]{
            fail("incomplete_two_ELF_schedule")
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
    serial::write_fmt(format_args!(
        "WOLFOS_RING3_YIELD_SWITCH from={} to={} private_cr3=1 tss_rsp0=1 fx_saved=1\n",
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
    for i in 0..12{tlb::flush(VirtAddr::new(BASE+i*PAGE));}
    for i in 0..COUNT{
        // SAFETY: first restore BSP escape stack, original CR3/TSS/FX,
        // finish ALL CPL3 tasks, retire their active roots, unpublish and
        // invalidate guarded virtual leaves on BSP only.
        if unsafe{s.arena.retire_after_quiescence(s.stacks[i].handle)}
            !=Ok(s.stacks[i].frames){
            fail("guarded_stack_retirement")
        }
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
    serial::write_line(
        "WOLFOS_RING3_YIELD_CLEANUP_OK frames_freed=25 both_ELF_exited=1 fx_wiped=2 tss_restored=1 cr3_restored=1 pmm_no_leak=1"
    );
    serial::qemu_exit_success();
}
