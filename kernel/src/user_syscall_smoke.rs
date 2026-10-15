//! P2 first REAL bounded RAX/RDI/RSI system-call ABI on an independent
//! active sanitized CR3, with actual assembly GPR capture and IRETQ RAX
//! results. A fixed, trusted 122-byte user test program calls ID, unknown,
//! ADD, invalid ADD, EXIT and checks return values and saved RBX/R12.
//! This is a single-vCPU QEMU smoke only, NOT an untrusted-user app runner.
//! No user buffers, generic SYSCALL/SYSRET, process lifetime or scheduler.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, AtomicU64, AtomicUsize, Ordering};
use x86_64::{
    instructions::segmentation::{CS, Segment},
    registers::control::Cr3,
    VirtAddr,
};
use crate::{interrupts, kernel_half_shadow, pmm, serial,
    user_ring_entry::{self, Ring3Entry},
    user_syscall_abi::{self, Outcome, UserSyscallFrame}};

const PAGE: u64 = 4096;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const USER: u64 = 4;
const NX: u64 = 1 << 63;
const SLOTS: usize = 512;
const FRAMES: usize = 7;
const CODE_OFFSET: u64 = 0x401000;
const DATA_OFFSET: u64 = 0x402000;
const STACK_OFFSET: u64 = 0x403000;
// Instruction bytes compiled from auditable x86-64 assembler. Four INT 0x80
// returns at byte offsets [22,36,59,84], EXIT at 118; UD2 otherwise.
// Actual user code branches to UD2 if ANY syscall RAX mismatches, or if
// RBX/R12 were corrupted by the assembly entry or kernel dispatcher.
const USER_PROGRAM: [u8; 122] = [
    0xbb, 0x78, 0x56, 0x34, 0x12, 0x41, 0xbc, 0x10, 0x32, 0x54, 0x76, 0x31,
    0xff, 0x31, 0xf6, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x3d, 0x46,
    0x4c, 0x4f, 0x57, 0x75, 0x5b, 0xb8, 0xff, 0x7f, 0x00, 0x00, 0xcd, 0x80,
    0x48, 0x83, 0xf8, 0xda, 0x75, 0x4e, 0xb8, 0x02, 0x00, 0x00, 0x00, 0xbf,
    0x07, 0x00, 0x00, 0x00, 0xbe, 0x23, 0x00, 0x00, 0x00, 0xcd, 0x80, 0x48,
    0x83, 0xf8, 0x2a, 0x75, 0x37, 0xb8, 0x02, 0x00, 0x00, 0x00, 0x48, 0xc7,
    0xc7, 0xff, 0xff, 0xff, 0xff, 0xbe, 0x01, 0x00, 0x00, 0x00, 0xcd, 0x80,
    0x48, 0x83, 0xf8, 0xea, 0x75, 0x1e, 0x81, 0xfb, 0x78, 0x56, 0x34, 0x12,
    0x75, 0x16, 0x41, 0x81, 0xfc, 0x10, 0x32, 0x54, 0x76, 0x75, 0x0d, 0xb8,
    0x03, 0x00, 0x00, 0x00, 0x31, 0xff, 0x31, 0xf6, 0xcd, 0x80, 0x0f, 0x0b,
    0x0f, 0x0b,
];
const RETURN_OFFSETS: [u64; 5] = [22, 36, 59, 84, 118];
const REQUESTS: [(u64, u64, u64); 5] = [
    (user_syscall_abi::SYS_WOLFOS_ID, 0, 0),
    (0x7fff, 0, 0),
    (user_syscall_abi::SYS_U32_ADD, 7, 35),
    (user_syscall_abi::SYS_U32_ADD, u64::MAX, 1),
    (user_syscall_abi::SYS_EXIT_ZERO, 0, 0),
];

static ENTRY: AtomicU64 = AtomicU64::new(0);
static STACK_TOP: AtomicU64 = AtomicU64::new(0);
static DATA_HHDM: AtomicU64 = AtomicU64::new(0);
static CR3_PHYS: AtomicU64 = AtomicU64::new(0);
static STAGE: AtomicUsize = AtomicUsize::new(0);

fn fail(why: &str) -> ! {
    serial::write_fmt(format_args!("WOLFOS_SYSCALL_ERROR {why}\n"));
    crate::halt_forever();
}

fn hhdm_ptr(hhdm: u64, phys: u64) -> Option<*mut u8> {
    VirtAddr::try_new(hhdm.checked_add(phys)?).ok()
        .map(|v| v.as_mut_ptr::<u8>())
}

fn allocate_unique() -> Option<[u64; FRAMES]> {
    let mut f = [0u64; FRAMES];
    for at in 0..FRAMES {
        let Some(phys) = pmm::allocate_frame() else {
            for old in f[..at].iter().copied().rev() { let _ = pmm::free_frame(old); }
            return None;
        };
        if phys == 0 || phys & (PAGE - 1) != 0 || phys >= (1 << 52)
            || f[..at].contains(&phys)
        {
            let _ = pmm::free_frame(phys);
            for old in f[..at].iter().copied().rev() { let _ = pmm::free_frame(old); }
            return None;
        }
        f[at] = phys;
    }
    Some(f)
}

/// Called once after normal boot, on one BSP with IF=0; never returns.
pub fn enter(hhdm: u64) -> ! {
    if !interrupts::verify_ring3_preconditions() { fail("gdt_tss"); }
    let (user_cs, user_ss, rsp0) = interrupts::ring3_cpu_state();
    let (boot_root_frame, _) = Cr3::read();
    let boot_phys = boot_root_frame.start_address().as_u64();
    let Some(boot_ptr) = hhdm_ptr(hhdm, boot_phys) else { fail("boot_root"); };
    let boot_root = unsafe { &*boot_ptr.cast::<[u64; SLOTS]>() };

    // Choose a single clean lower-half PML4 entry, never alias the boot root.
    let Some(slot) = (1..256).find(|at| boot_root[*at] == 0) else {
        fail("no_clean_user_slot");
    };
    let base = (slot as u64) << 39;
    let code = base + CODE_OFFSET;
    let data = base + DATA_OFFSET;
    let stack = base + STACK_OFFSET;
    let top = stack + PAGE;
    if user_ring_entry::validate(Ring3Entry {
        rip: code, user_rsp: top, kernel_rsp0: rsp0,
        user_cs, user_ss, rflags: 2,
    }).is_err() { fail("entry_contract"); }
    let kernel_code = crate::kmain as usize as u64;
    let kernel_idx = ((kernel_code >> 39) & 511) as usize;
    let hhdm_idx = ((hhdm >> 39) & 511) as usize;
    if kernel_idx < 256 || hhdm_idx < 256
        || boot_root[kernel_idx] & PRESENT == 0
        || boot_root[hhdm_idx] & PRESENT == 0
    { fail("kernel_hhdm_mappings_missing"); }

    // Require hardware-enforced XD on writable user data/stack.
    let (efer_lo, efer_hi): (u32, u32);
    unsafe {
        asm!("rdmsr", in("ecx") 0xc000_0080u32,
            out("eax") efer_lo, out("edx") efer_hi,
            options(nostack, preserves_flags));
    }
    if efer_lo & (1 << 11) == 0 { fail("nxe_off"); }
    let _ = efer_hi;

    let Some(frames) = allocate_unique() else { fail("pmm"); };
    let mut ptrs = [core::ptr::null_mut::<u8>(); FRAMES];
    for (i, phys) in frames.iter().copied().enumerate() {
        let Some(ptr) = hhdm_ptr(hhdm, phys) else { fail("hhdm_frame"); };
        ptrs[i] = ptr;
    }

    // SAFETY: seven distinct PMM frames, exclusive BSP ownership,
    // accessible through preexisting HHDM; no root is live until CR3 write.
    unsafe {
        for ptr in ptrs { core::ptr::write_bytes(ptr, 0, PAGE as usize); }
        core::ptr::copy_nonoverlapping(USER_PROGRAM.as_ptr(), ptrs[4], USER_PROGRAM.len());

        let root = &mut *ptrs[0].cast::<[u64; SLOTS]>();
        let pdpt = &mut *ptrs[1].cast::<[u64; SLOTS]>();
        let pd = &mut *ptrs[2].cast::<[u64; SLOTS]>();
        let pt = &mut *ptrs[3].cast::<[u64; SLOTS]>();

        pdpt[0] = frames[2] | PRESENT | WRITE | USER;
        pd[2] = frames[3] | PRESENT | WRITE | USER;
        pt[1] = frames[4] | PRESENT | USER;
        pt[2] = frames[5] | PRESENT | WRITE | USER | NX;
        pt[3] = frames[6] | PRESENT | WRITE | USER | NX;
        let user_root = frames[1] | PRESENT | WRITE | USER;
        root[slot] = user_root;
        let copied = kernel_half_shadow::graft_kernel_half(
            boot_root, root, slot, user_root, &frames,
        );
        let audited = kernel_half_shadow::audit_kernel_half(
            boot_root, root, slot, user_root, &frames,
        );
        if !matches!(copied, Ok(count) if count >= 1) || copied != audited
            || root[slot] != user_root
            || root[kernel_idx] != (boot_root[kernel_idx] & !USER)
            || root[hhdm_idx] != (boot_root[hhdm_idx] & !USER)
            || root[256..].iter().any(|entry| entry & USER != 0)
            || root[..256].iter().filter(|entry| **entry != 0).count() != 1
            || pdpt.iter().filter(|entry| **entry != 0).count() != 1
            || pd.iter().filter(|entry| **entry != 0).count() != 1
            || pt.iter().filter(|entry| **entry != 0).count() != 3
        { fail("sanitized_root_audit"); }

        ENTRY.store(code, Ordering::Release);
        STACK_TOP.store(top, Ordering::Release);
        DATA_HHDM.store(ptrs[5] as u64, Ordering::Release);
        CR3_PHYS.store(frames[0], Ordering::Release);
        STAGE.store(0, Ordering::Release);
        compiler_fence(Ordering::SeqCst);
        // The code, static BSP stack/TSS, IDT, HHDM and serial logger are
        // all in the same pre-existing higher-half kernel mappings.
        // The new PML4 clears U/S in EVERY high-half root entry.
        asm!("mov cr3, {}", in(reg) frames[0], options(nostack, preserves_flags));
        let (now, _) = Cr3::read();
        if now.start_address().as_u64() != frames[0] { fail("cr3_not_active"); }

        serial::write_fmt(format_args!(
            "WOLFOS_SYSCALL_ENTER cr3_new=1 cr3_distinct=1 high_supervisor=1 user_pages=3 rx=1 rw_nx=2 root_slot={} nxe=1 abi=int80\n",
            slot,
        ));
        // This IRETQ must reach actual CPL3 under the NEW sanitized root.
        // Five distinct user INT80 entries have register-based arguments.
        // The first four return actual ABI result values to RAX; the fifth
        // must exit from CPL0 via SYS_EXIT_ZERO on the RSP0 kernel stack.
        asm!(
            "push {ss}",
            "push {rsp}",
            "push {flags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = in(reg) u64::from(user_ss),
            rsp = in(reg) top,
            flags = in(reg) 2u64,
            cs = in(reg) u64::from(user_cs),
            rip = in(reg) code,
            options(noreturn),
        );
    }
}

/// Custom assembly supplies a pointer to the genuine saved 15-GPR + CPL3
/// hardware IRET frame. Validating it BEFORE writing any user result means
/// malformed privilege levels, forged return state or unexpected syscall
/// ordering cannot receive a success marker or privileged capabilities.
#[unsafe(no_mangle)]
pub extern "C" fn wolfos_int80_syscall_dispatch(
    raw_frame: *mut UserSyscallFrame,
) -> *mut UserSyscallFrame {
    if raw_frame.is_null() { fail("null_saved_frame") }
    let stage = STAGE.load(Ordering::Acquire);
    if stage >= REQUESTS.len() { fail("unexpected_extra_syscall") }
    let (user_cs, user_ss, rsp0) = interrupts::ring3_cpu_state();
    let code = ENTRY.load(Ordering::Acquire);
    let top = STACK_TOP.load(Ordering::Acquire);
    let data = DATA_HHDM.load(Ordering::Acquire);
    let active_root = CR3_PHYS.load(Ordering::Acquire);
    let frame_addr = raw_frame as u64;
    let (cr3, _) = Cr3::read();
    // The complete frame (160 bytes) must be contained inside TSS.RSP0.
    if code == 0 || data == 0 || active_root == 0
        || frame_addr & 7 != 0
        || frame_addr < rsp0 - (16 * 1024)
        || frame_addr.checked_add(user_syscall_abi::FRAME_BYTES as u64)
            .is_none_or(|end| end > rsp0)
        || cr3.start_address().as_u64() != active_root
        || CS::get_reg().0 != 8
    {
        fail("invalid_active_cr3_or_rsp0")
    }
    // SAFETY: hardware TSS entered the live supervisor stack, the complete
    // assembly saved frame is within its validated limits, and this is
    // single-BSP IF=0 QEMU only. No other CPU mutates or frees this frame.
    let frame = unsafe { &mut *raw_frame };
    let expected = REQUESTS[stage];
    if frame.hardware.cs != u64::from(user_cs)
        || frame.hardware.ss != u64::from(user_ss)
        || frame.hardware.rip != code + RETURN_OFFSETS[stage]
        || frame.hardware.rsp != top
        || frame.hardware.rflags != 0x2
        || frame.registers.rax != expected.0
        || frame.registers.rdi != expected.1
        || frame.registers.rsi != expected.2
        || frame.registers.rbx != 0x12345678
        || frame.registers.r12 != 0x76543210
    {
        serial::write_fmt(format_args!(
            "WOLFOS_SYSCALL_ERROR bad_frame stage={} nr={:#x} rdi={:#x} rsi={:#x} rip={:#x} cs={:#x} ss={:#x} flags={:#x}\\n",
            stage, frame.registers.rax, frame.registers.rdi,
            frame.registers.rsi, frame.hardware.rip, frame.hardware.cs,
            frame.hardware.ss, frame.hardware.rflags,
        ));
        crate::halt_forever()
    }
    // Kernel never dereferences any user-provided pointer. All caller
    // numeric arguments have independent pure, host-tested validation.
    let outcome = user_syscall_abi::dispatch(
        frame.registers.rax, frame.registers.rdi, frame.registers.rsi,
    );
    let expected_result = match stage {
        0 => Outcome::Return(user_syscall_abi::WOLFOS_ID),
        1 => Outcome::Return(user_syscall_abi::ENOSYS),
        2 => Outcome::Return(42),
        3 => Outcome::Return(user_syscall_abi::EINVAL),
        _ => Outcome::ExitZero,
    };
    if outcome != expected_result { fail("incorrect_syscall_dispatch") }
    STAGE.store(stage + 1, Ordering::Release);
    match outcome {
        Outcome::Return(result) => {
            // Only RAX is changed. Assembly restores ALL other 14 GPRs.
            frame.registers.rax = result;
            serial::write_fmt(format_args!(
                "WOLFOS_SYSCALL_RETURN stage={} rax={:#x} saved_gpr=1 cpl3=1 kernel_cpl=0\\n",
                stage + 1, result,
            ));
            raw_frame // assembly restores complete register state + IRETQ
        }
        Outcome::ExitZero => {
            if STAGE.load(Ordering::Acquire) != 5
                || data == 0 || unsafe { (data as *const u8).read_volatile() } != 0
            { fail("bad_exit_or_user_data") }
            serial::write_line("WOLFOS_SYSCALL_EXIT_OK stage=5 code=0 returned_to_user=4");
            serial::write_line("WOLFOS_SYSCALL_OK cr3_distinct=1 cpl3=1 call_count=5 results_checked=4 enosys=1 einval=1 gprs_preserved=1 exit_zero=1 processes=0");
            serial::qemu_exit_success()
        }
    }
}
