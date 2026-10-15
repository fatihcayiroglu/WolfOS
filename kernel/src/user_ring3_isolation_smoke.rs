//! P2 isolated-CR3 CPL3 hardware access-denial proof.
//!
//! Feature-isolated single-BSP QEMU only. Allocate SEVEN independent PMM
//! frames: one PML4, three descendant user tables, RX code, RW+NX data,
//! RW+NX stack. Copy the ACTIVE kernel HIGH HALF but CLEAR its PML4 U/S on
//! every entry. Lower PML4: exactly one user mapping. Switch CR3 for real,
//! enter CPL3, run INT80 -> IRETQ -> INT80 -> IRETQ, then attempt to READ
//! an existing supervisor-only kernel code address. The CPU MUST deliver
//! #PF with PRESENT=1, USER_MODE=1, WRITE=0. Only this fault passes QEMU.
//!
//! This is not yet a general address space / safe execution of untrusted
//! ELF programs. Kernel child tables are shared with Limine and owned by
//! the boot environment; the hardcoded user payload is trusted. No memory
//! management lifetime, scheduler, syscall ABI or fault recovery exists.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, AtomicU64, AtomicUsize, Ordering};
use x86_64::{
    instructions::segmentation::{CS, Segment},
    registers::control::{Cr2, Cr3},
    structures::idt::{InterruptStackFrame, PageFaultErrorCode},
    VirtAddr,
};
use crate::{interrupts, kernel_half_shadow, pmm, serial,
    user_ring_entry::{self, Ring3Entry}};

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
const FIRST_RETURN: u64 = 9;
const SECOND_RETURN: u64 = 18;
const FAULT_RIP_OFFSET: u64 = 28;

// mov byte ptr [rip+0xff9], 0x11; int 0x80;
// mov byte ptr [rip+0xff0], 0x22; int 0x80;
// movabs rax, <EXACT KERNEL CODE VA>; mov rax, [rax]; ud2.
// Fault RIP is 28 bytes after user entry. The address immediate is patched
// ONLY while the RX frame is unexposed and accessed through supervisor HHDM.
const USER_PROGRAM: [u8; 33] = [
    0xc6, 0x05, 0xf9, 0x0f, 0, 0, 0x11, 0xcd, 0x80,
    0xc6, 0x05, 0xf0, 0x0f, 0, 0, 0x22, 0xcd, 0x80,
    0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,
    0x48, 0x8b, 0x00, 0x0f, 0x0b,
];

static ENTRY: AtomicU64 = AtomicU64::new(0);
static STACK_TOP: AtomicU64 = AtomicU64::new(0);
static DATA_HHDM: AtomicU64 = AtomicU64::new(0);
static CR3_PHYS: AtomicU64 = AtomicU64::new(0);
static KERNEL_TARGET: AtomicU64 = AtomicU64::new(0);
static STAGE: AtomicUsize = AtomicUsize::new(0);

fn fail(why: &str) -> ! {
    serial::write_fmt(format_args!("WOLFOS_USER_ISOLATION_ERROR {why}\n"));
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
        core::ptr::copy_nonoverlapping(kernel_code.to_le_bytes().as_ptr(), ptrs[4].add(20), 8);

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
        KERNEL_TARGET.store(kernel_code, Ordering::Release);
        STAGE.store(0, Ordering::Release);
        compiler_fence(Ordering::SeqCst);
        // The code, static BSP stack/TSS, IDT, HHDM and serial logger are
        // all in the same pre-existing higher-half kernel mappings.
        // The new PML4 clears U/S in EVERY high-half root entry.
        asm!("mov cr3, {}", in(reg) frames[0], options(nostack, preserves_flags));
        let (now, _) = Cr3::read();
        if now.start_address().as_u64() != frames[0] { fail("cr3_not_active"); }

        serial::write_fmt(format_args!(
            "WOLFOS_USER_ISOLATION_ENTER cr3_new=1 cr3_distinct=1 high_supervisor=1 user_pages=3 rx=1 rw_nx=2 root_slot={} nxe=1\n",
            slot,
        ));
        // This IRETQ MUST reach actual CPL3 under the NEW root. Two INT80s
        // must independently return; user then accesses kernel RIP via RAX,
        // where the processor MUST raise #PF due upper PML4 U/S=0.
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

fn check_entry(frame: &InterruptStackFrame, stage: usize, expected_nonce: u8)
    -> Result<(), ()>
{
    let code = ENTRY.load(Ordering::Acquire);
    let top = STACK_TOP.load(Ordering::Acquire);
    let data = DATA_HHDM.load(Ordering::Acquire);
    let expected_cr3 = CR3_PHYS.load(Ordering::Acquire);
    let (user_cs, user_ss, rsp0) = interrupts::ring3_cpu_state();
    let kernel_rsp: u64;
    unsafe { asm!("mov {}, rsp", out(reg) kernel_rsp,
        options(nomem, nostack, preserves_flags)); }
    let actual = if data != 0 {
        unsafe { (data as *const u8).read_volatile() }
    } else { 0 };
    let (current_cr3, _) = Cr3::read();
    if code == 0 || data == 0 || stage > 1
        || actual != expected_nonce
        || current_cr3.start_address().as_u64() != expected_cr3
        || CS::get_reg().0 != 8
        || frame.code_segment.0 != user_cs || frame.stack_segment.0 != user_ss
        || frame.instruction_pointer.as_u64() != code + if stage == 0 { 9 } else { 18 }
        || frame.stack_pointer.as_u64() != top
        || kernel_rsp < rsp0 - (16 * 1024) || kernel_rsp >= rsp0
    {
        return Err(());
    }
    Ok(())
}

pub extern "x86-interrupt" fn interrupt_80(frame: InterruptStackFrame) {
    let stage = STAGE.load(Ordering::Acquire);
    let nonce = if stage == 0 { 0x11 } else { 0x22 };
    if check_entry(&frame, stage, nonce).is_err() {
        serial::write_fmt(format_args!(
            "WOLFOS_USER_ISOLATION_ERROR int80 stage={} cs={:#x} rip={:?}\n",
            stage, frame.code_segment.0, frame.instruction_pointer,
        ));
        crate::halt_forever();
    }
    STAGE.store(stage + 1, Ordering::Release);
    if stage == 0 {
        serial::write_line("WOLFOS_USER_ISOLATION_INT80_FIRST cpl3=1 cpl0=1 rsp0=1 nonce=0x11");
    } else {
        serial::write_line("WOLFOS_USER_ISOLATION_INT80_SECOND cpl3=1 cpl0=1 rsp0=1 nonce=0x22");
    }
    // ALWAYS return by real compiler x86-interrupt IRETQ; neither INT alone
    // is accepted. The next user instruction after second INT is MOVABS.
}

pub extern "x86-interrupt" fn user_page_fault(
    frame: InterruptStackFrame, error: PageFaultErrorCode,
) {
    let target = KERNEL_TARGET.load(Ordering::Acquire);
    let user_entry = ENTRY.load(Ordering::Acquire);
    let (user_cs, user_ss, rsp0) = interrupts::ring3_cpu_state();
    let (now, _) = Cr3::read();
    let kernel_rsp: u64;
    unsafe { asm!("mov {}, rsp", out(reg) kernel_rsp,
        options(nomem, nostack, preserves_flags)); }
    let fault_matches = matches!(Cr2::read(), Ok(addr) if addr.as_u64() == target);
    if STAGE.load(Ordering::Acquire) != 2
        || !fault_matches
        || !error.contains(PageFaultErrorCode::PROTECTION_VIOLATION)
        || !error.contains(PageFaultErrorCode::USER_MODE)
        || error.contains(PageFaultErrorCode::CAUSED_BY_WRITE)
        || error.contains(PageFaultErrorCode::INSTRUCTION_FETCH)
        || now.start_address().as_u64() != CR3_PHYS.load(Ordering::Acquire)
        || CS::get_reg().0 != 8
        || frame.code_segment.0 != user_cs || frame.stack_segment.0 != user_ss
        || frame.instruction_pointer.as_u64() != user_entry + 28
        || frame.stack_pointer.as_u64() != STACK_TOP.load(Ordering::Acquire)
        || kernel_rsp < rsp0 - (16 * 1024) || kernel_rsp >= rsp0
    {
        serial::write_fmt(format_args!(
            "WOLFOS_USER_ISOLATION_ERROR pf stage={} flags={:?} cr2={:?} rip={:?} cs={:#x} krsp={:#x}\n",
            STAGE.load(Ordering::Acquire), error, Cr2::read(),
            frame.instruction_pointer, frame.code_segment.0, kernel_rsp,
        ));
        crate::halt_forever();
    }
    serial::write_line("WOLFOS_USER_ISOLATION_PF_OK present=1 user=1 read=1 kernel_supervisor=1 cr3_new=1 rsp0=1");
    serial::write_line("WOLFOS_USER_ISOLATION_OK cpl3=1 int80=2 iretq_returns=2 denied_kernel_read=1 sanitized_cr3=1 processes=0");
    serial::qemu_exit_success();
}
