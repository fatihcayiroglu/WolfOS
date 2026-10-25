//! First *independently assembled and linked* static ET_EXEC ELF64 executed
//! in actual hardware CPL3 under a separate supervisor-protected CR3.
//!
//! The guest lives in user/hello.S + user/hello.ld, built by GNU as/ld into
//! a genuine ELF file by build.rs. The kernel consumes that binary ONLY via
//! strict existing elf64_preflight::preflight + elf64_page_image::materialize:
//! user text RX, ELF data+BSS RW/NX, and an independent RW/NX user stack.
//! Two ordinary INT80 syscalls, 19 user-console PUTC syscalls, and EXIT(0)
//! are verified by saved GPRs, user RIP and real TSS.RSP0 stack bounds.
//! Upon exit, the BSP MUST restore boot CR3 and release every allocated
//! user/PML4/page-table frame without leaks before emitting success.
//!
//! This feature is single-BSP, IF=0, a fixed TEST ELF compiled with native
//! GNU binutils, NOT yet a general process or an untrusted executable loader.
//! Kernel high-half descendant page tables remain borrowed from Limine.

use core::arch::asm;
#[cfg(any(feature = "user-invalid-opcode-retire-smoke", feature = "user-page-fault-retire-smoke"))]
use x86_64::structures::idt::InterruptStackFrame;
#[cfg(feature = "user-page-fault-retire-smoke")]
use x86_64::{registers::control::Cr2, structures::idt::PageFaultErrorCode};
use core::sync::atomic::{compiler_fence, AtomicU64, AtomicUsize, Ordering};
use x86_64::{
    instructions::segmentation::{CS, Segment},
    registers::control::Cr3,
    VirtAddr,
};
use crate::{
    elf64_page_image::{materialize, PAGE_SIZE},
    elf64_preflight::preflight,
    interrupts, kernel_half_shadow, pmm, serial,
    process_lifecycle::ProcessState,
    process_table::{ProcessTableCell, TableError},
    user_ring_entry::{self, Ring3Entry},
    user_syscall_abi::{self, Outcome, UserSyscallFrame},
};

mod symbols {
    include!(concat!(env!("OUT_DIR"), "/wolfos_elf_symbols.rs"));
}
const ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wolfos-user-hello.elf"));
#[cfg(feature = "user-process-fault-recovery-smoke")]
const RECOVERY_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wolfos-user-recovery.elf"));
const HELLO: &[u8; 19] = b"Hello from WolfOS!\n";
const PAGE: u64 = 4096;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const USER: u64 = 4;
const NX: u64 = 1 << 63;
const SLOTS: usize = 512;
const FRAMES: usize = 7; // new PML4, PDPT, PD, PT, RX text, RW data/BSS, RW stack
const STACK_VA: u64 = 0x404000;
const RETURN_COUNT: usize = if cfg!(feature = "user-file-io-smoke") { 11 }
    else if cfg!(feature = "user-copy-smoke") { 3 } else { HELLO.len() + 2 };
const TOTAL_CALLS: usize = RETURN_COUNT + 1;

static ENTRY: AtomicU64 = AtomicU64::new(0);
static STACK_TOP: AtomicU64 = AtomicU64::new(0);
static DATA_HHDM: AtomicU64 = AtomicU64::new(0);
static CR3_PHYS: AtomicU64 = AtomicU64::new(0);
static BOOT_CR3: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BEFORE: AtomicUsize = AtomicUsize::new(0);
static STAGE: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "user-file-io-smoke")]
static FILE_FD: AtomicU64 = AtomicU64::new(0);
static OWNED: [AtomicU64; FRAMES] = [const { AtomicU64::new(0) }; FRAMES];
/// The same bounded multi-PID ownership table tested with real PMM leases
/// now owns the hardware Ring3 ELF path. Slots can be reused after reap,
/// while PID generations increase monotonically.
static PROCESS_TABLE: ProcessTableCell<2, FRAMES> = ProcessTableCell::new();
static RUN_INDEX: AtomicUsize = AtomicUsize::new(0);
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);
const MAX_RUNS: usize = if cfg!(feature = "user-process-smoke") { 2 } else { 1 };

/// Read only PTEs inside this task's four exclusively owned paging pages.
/// No unchecked physical address from user inputs can reach the HHDM.
#[cfg(any(feature = "user-copy-smoke", feature = "user-file-io-smoke"))]
pub(crate) fn private_pte(physical: u64) -> Option<u64> {
    let frame = physical & !4095;
    if physical & 7 != 0
        || !OWNED[..4].iter().any(|f| f.load(Ordering::Acquire) == frame)
    { return None }
    let ptr = hhdm_ptr(HHDM_OFFSET.load(Ordering::Acquire), physical)?;
    // SAFETY: physical address belongs to a fixed owned page-table frame;
    // a checked 8-byte aligned entry is contained in that page.
    Some(unsafe { core::ptr::read_volatile(ptr.cast::<u64>()) })
}

#[cfg(any(feature = "user-copy-smoke", feature = "user-file-io-smoke"))]
pub(crate) fn private_byte(physical: u64) -> Option<u8> {
    let frame = physical & !4095;
    if !OWNED[4..].iter().any(|f| f.load(Ordering::Acquire) == frame) {
        return None
    }
    let ptr = hhdm_ptr(HHDM_OFFSET.load(Ordering::Acquire), physical)?;
    // SAFETY: exact physical frame is one of the three owned user leaves.
    Some(unsafe { core::ptr::read_volatile(ptr) })
}

#[cfg(any(feature = "user-copy-smoke", feature = "user-file-io-smoke"))]
pub(crate) fn private_rw_byte(physical: u64, value: Option<u8>) -> Option<u8> {
    let frame = physical & !4095;
    if !OWNED[5..].iter().any(|f| f.load(Ordering::Acquire) == frame) {
        return None
    }
    let ptr = hhdm_ptr(HHDM_OFFSET.load(Ordering::Acquire), physical)?;
    // SAFETY: page walk has proved full supervisor/user write permissions
    // and the leaf frame is exclusively owned RW data or stack, never text.
    unsafe {
        if let Some(v) = value { core::ptr::write_volatile(ptr, v) }
        Some(core::ptr::read_volatile(ptr))
    }
}

fn fail(reason: &str) -> ! {
    serial::write_fmt(format_args!("WOLFOS_ELF_RUN_ERROR {reason}\n"));
    crate::halt_forever()
}

fn hhdm_ptr(hhdm: u64, phys: u64) -> Option<*mut u8> {
    VirtAddr::try_new(hhdm.checked_add(phys)?).ok()
        .map(|addr| addr.as_mut_ptr::<u8>())
}

/// The seven frames are exclusively owned by this single-BSP isolated smoke.
fn allocate_owned() -> Option<[u64; FRAMES]> {
    let mut frames = [0u64; FRAMES];
    for i in 0..FRAMES {
        let Some(phys) = pmm::allocate_frame() else {
            for old in frames[..i].iter().copied().rev() {
                let _ = pmm::free_frame(old);
            }
            return None;
        };
        if phys == 0 || phys & (PAGE - 1) != 0
            || phys >= (1 << 52) || frames[..i].contains(&phys)
        {
            let _ = pmm::free_frame(phys);
            for old in frames[..i].iter().copied().rev() {
                let _ = pmm::free_frame(old);
            }
            return None;
        }
        frames[i] = phys;
    }
    Some(frames)
}

pub fn enter(hhdm: u64) -> ! {
    let index = RUN_INDEX.load(Ordering::Acquire);
    if index >= MAX_RUNS || hhdm == 0 { fail("invalid_process_launch") }
    let pid = index as u64 + 1;
    HHDM_OFFSET.store(hhdm, Ordering::Release);
    #[cfg(feature = "user-vfs-smoke")]
    crate::vfs_smoke::prepare(ELF);
    #[cfg(feature = "user-file-io-smoke")]
    crate::user_file_io_smoke::prepare();
    #[cfg(feature = "user-ramfs-smoke")]
    crate::ramfs_smoke::prepare(ELF);
    #[cfg(feature = "user-vfs-smoke")]
    let elf: &[u8] = crate::vfs_smoke::elf_file();
    #[cfg(feature = "user-ramfs-smoke")]
    let elf: &[u8] = crate::ramfs_smoke::elf_file();
    #[cfg(not(any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke", feature = "user-process-fault-recovery-smoke")))]
    let elf: &[u8] = ELF;
    #[cfg(feature = "user-process-fault-recovery-smoke")]
    let elf: &[u8] = if index == 1 { RECOVERY_ELF } else { ELF };
    if index == 0 {
        if !interrupts::verify_ring3_preconditions() { fail("gdt_tss") }
    } else {
        #[cfg(feature = "user-process-smoke")]
        {
            // Only allow the second user admission AFTER the first PID was
            // fully reaped and no PMM pages remain owned. CPU SS=0 is valid
            // here because the kernel arrived via a real CPL3 INT80 trap.
            let safely_reaped = matches!(
                PROCESS_TABLE.with(|t| (t.snapshot(1), t.occupied(), t.running())),
                Ok((None, 0, 0)),
            );
            if !safely_reaped || OWNED.iter().any(|p| p.load(Ordering::Acquire) != 0)
                || !interrupts::verify_ring3_reentry_preconditions()
            { fail("second_user_kernel_reentry_preflight") }
        }
        #[cfg(not(feature = "user-process-smoke"))]
        fail("unreachable_user_reentry");
    }
    #[cfg(feature = "user-file-io-smoke")]
    if !(symbols::AFTER_ADD < symbols::FILE_POLICY_DENIED_OPEN
        && symbols::FILE_POLICY_DENIED_OPEN < symbols::FILE_BAD_OPEN
        && symbols::FILE_BAD_OPEN < symbols::FILE_OPEN
        && symbols::FILE_OPEN < symbols::FILE_BAD_READ
        && symbols::FILE_BAD_READ < symbols::FILE_READ
        && symbols::FILE_READ < symbols::FILE_POLICY_REVOKED_READ
        && symbols::FILE_POLICY_REVOKED_READ < symbols::FILE_EOF
        && symbols::FILE_EOF < symbols::FILE_CLOSE
        && symbols::FILE_CLOSE < symbols::FILE_STALE_CLOSE
        && symbols::FILE_STALE_CLOSE <= symbols::AFTER_PUTC
        && symbols::FILE_PATH >= symbols::HELLO_END
        && symbols::FILE_PATH_END - symbols::FILE_PATH == 12
        && symbols::FILE_PATH_END < 0x402000)
    { fail("independent_file_io_symbols") }
    #[cfg(feature = "user-copy-smoke")]
    if symbols::AFTER_WRITE <= symbols::AFTER_ADD
        || symbols::AFTER_WRITE >= symbols::AFTER_EXIT {
        fail("linked_user_write_return_address")
    }
    if symbols::ENTRY != 0x401000 || symbols::AFTER_ID <= symbols::ENTRY
        || symbols::AFTER_ADD <= symbols::AFTER_ID
        || symbols::AFTER_PUTC <= symbols::AFTER_ADD
        || symbols::AFTER_EXIT <= symbols::AFTER_PUTC
        || symbols::HELLO_TEXT <= symbols::AFTER_EXIT
        || symbols::HELLO_END != symbols::HELLO_TEXT + HELLO.len() as u64
        || symbols::FIXTURE_MAGIC != 0x403000
        || symbols::BSS_START != 0x403001
        || elf.len() >= 32768
    { fail("unexpected_independent_elf_symbols") }

    // Unlike the old syscall proof, executable bytes are NEVER hardcoded in
    // the kernel's source or directly copied from a handbuilt instruction
    // array. They must pass the strict ELF64 ET_EXEC parser and PT_LOAD
    // data/BSS materialization path developed in PRs #62-#65.
    let Ok(plan) = preflight(elf) else { fail("elf_preflight") };
    if plan.len != 2 || plan.entry != symbols::ENTRY { fail("elf_entry_or_segments") }
    let (Some(text), Some(data)) = (plan.segments[0], plan.segments[1])
    else { fail("elf_missing_load") };
    if text.page_start != 0x401000 || text.page_end != 0x402000
        || text.virtual_address != 0x401000
        || text.writable || !text.executable
        || text.memory_size != text.file_size
        || text.file_size < symbols::HELLO_END - text.virtual_address
        || data.page_start != 0x403000 || data.page_end != 0x404000
        || data.virtual_address != 0x403000
        || !data.writable || data.executable
        || data.file_size != 1 || data.memory_size != 65
        || symbols::AFTER_EXIT >= symbols::HELLO_TEXT
    { fail("elf_permissions_or_layout") }
    let hello_offset = usize::try_from(symbols::HELLO_TEXT - text.virtual_address)
        .unwrap_or(usize::MAX);
    let hello_in_file = usize::try_from(text.file_offset).ok()
        .and_then(|begin| begin.checked_add(hello_offset))
        .and_then(|start| elf.get(start..start + HELLO.len()));
    if hello_in_file != Some(&HELLO[..]) { fail("elf_message_content") }
    #[cfg(feature = "user-file-io-smoke")]
    {
        let file_path_offset = usize::try_from(
            symbols::FILE_PATH - text.virtual_address
        ).unwrap_or(usize::MAX);
        let path_from_file = usize::try_from(text.file_offset).ok()
            .and_then(|begin| begin.checked_add(file_path_offset))
            .and_then(|start| elf.get(start..start + 12));
        if path_from_file != Some(&b"/tmp/msg.txt"[..]) {
            fail("independently_linked_file_path")
        }
    }

    let (user_cs, user_ss, rsp0) = interrupts::ring3_cpu_state();
    let (boot_frame, _) = Cr3::read();
    let boot_cr3 = boot_frame.start_address().as_u64();
    let Some(boot_ptr) = hhdm_ptr(hhdm, boot_cr3) else { fail("boot_root_hhdm") };
    let source = unsafe { &*boot_ptr.cast::<[u64; SLOTS]>() };
    let Some(slot) = (1..256).find(|at| source[*at] == 0)
    else { fail("no_unused_user_pml4") };
    let base = (slot as u64) << 39;
    let code = base + plan.entry;
    let text_va = base + text.page_start;
    let data_va = base + data.page_start;
    let stack_va = base + STACK_VA;
    let user_top = stack_va + PAGE;
    if user_ring_entry::validate(Ring3Entry {
        rip: code, user_rsp: user_top, kernel_rsp0: rsp0,
        user_cs, user_ss, rflags: 2,
    }).is_err() { fail("entry_contract") }
    let kernel_idx = ((crate::kmain as usize as u64 >> 39) & 511) as usize;
    let hhdm_idx = ((hhdm >> 39) & 511) as usize;
    if kernel_idx < 256 || hhdm_idx < 256
        || source[kernel_idx] & PRESENT == 0
        || source[hhdm_idx] & PRESENT == 0
    { fail("missing_boot_supervisor_mappings") }

    let (efer_lo, _efer_hi): (u32, u32);
    unsafe {
        asm!("rdmsr", in("ecx") 0xc000_0080u32,
            out("eax") efer_lo, out("edx") _efer_hi,
            options(nostack, preserves_flags));
    }
    if efer_lo & (1 << 11) == 0 { fail("efer_nxe") }

    let before = pmm::statistics().allocated_frames;
    let Some(frames) = allocate_owned() else { fail("pmm_seven_frames") };
    let mut ptrs = [core::ptr::null_mut::<u8>(); FRAMES];
    for (i, phys) in frames.iter().copied().enumerate() {
        let Some(ptr) = hhdm_ptr(hhdm, phys) else { fail("owned_frame_hhdm") };
        ptrs[i] = ptr;
    }

    // SAFETY: all frames fresh and disjoint. No CR3 points to the new root
    // until AFTER segment copying and full source/destination root audit.
    unsafe {
        for ptr in ptrs { core::ptr::write_bytes(ptr, 0, PAGE as usize); }
        let text_page = &mut *ptrs[4].cast::<[u8; PAGE_SIZE]>();
        let data_page = &mut *ptrs[5].cast::<[u8; PAGE_SIZE]>();
        let Ok(t) = materialize(elf, &text, text.page_start, text_page)
        else { fail("text_materialize") };
        let Ok(d) = materialize(elf, &data, data.page_start, data_page)
        else { fail("data_materialize") };
        if !t.executable || t.writable || t.copied != text.file_size as usize
            || d.executable || !d.writable || d.copied != 1
            || data_page[0] != 0x5a || data_page[1..65].iter().any(|b| *b != 0)
            || text_page[0..2] != [0xb8, 0x01]
        { fail("elf_pt_load_incorrect") }
        let root = &mut *ptrs[0].cast::<[u64; SLOTS]>();
        let pdpt = &mut *ptrs[1].cast::<[u64; SLOTS]>();
        let pd = &mut *ptrs[2].cast::<[u64; SLOTS]>();
        let pt = &mut *ptrs[3].cast::<[u64; SLOTS]>();
        if ((code >> 30) & 511) != 0 || ((code >> 21) & 511) != 2
            || ((code >> 12) & 511) != 1
        { fail("user_table_indices") }
        pdpt[0] = frames[2] | PRESENT | WRITE | USER;
        pd[2] = frames[3] | PRESENT | WRITE | USER;
        pt[1] = frames[4] | PRESENT | USER;
        pt[3] = frames[5] | PRESENT | WRITE | USER | NX;
        pt[4] = frames[6] | PRESENT | WRITE | USER | NX;
        let entry = frames[1] | PRESENT | WRITE | USER;
        root[slot] = entry;
        let inherited = kernel_half_shadow::graft_kernel_half(
            source, root, slot, entry, &frames
        );
        if !matches!(inherited, Ok(count) if count >= 1)
            || kernel_half_shadow::audit_kernel_half(
                source, root, slot, entry, &frames
            ) != inherited
            || root[256..].iter().any(|e| e & USER != 0)
            || root[..256].iter().filter(|e| **e != 0).count() != 1
            || pt.iter().filter(|e| **e != 0).count() != 3
            || pd.iter().filter(|e| **e != 0).count() != 1
            || pdpt.iter().filter(|e| **e != 0).count() != 1
        { fail("sanitized_root_or_permissions") }

        BOOT_CR3.store(boot_cr3, Ordering::Release);
        ALLOCATED_BEFORE.store(before, Ordering::Release);
        ENTRY.store(code, Ordering::Release);
        STACK_TOP.store(user_top, Ordering::Release);
        DATA_HHDM.store(ptrs[5] as u64, Ordering::Release);
        CR3_PHYS.store(frames[0], Ordering::Release);
        STAGE.store(0, Ordering::Release);
        #[cfg(feature = "user-file-io-smoke")]
        FILE_FD.store(0, Ordering::Release);
        for (at, phys) in frames.iter().copied().enumerate() {
            OWNED[at].store(phys, Ordering::Release);
        }
        if !matches!(PROCESS_TABLE.with(|t| t.reserve(frames[0], frames)),
            Ok(Ok(issued)) if issued == pid
        ) { fail("process_table_admission_or_pid_generation") }
        compiler_fence(Ordering::SeqCst);
        asm!("mov cr3, {}", in(reg) frames[0],
            options(nostack, preserves_flags));
        let (now, _) = Cr3::read();
        if now.start_address().as_u64() != frames[0] { fail("new_cr3_not_active") }
        if !matches!(PROCESS_TABLE.with(|t| t.mark_running(pid, frames[0])), Ok(Ok(()))) {
            fail("process_table_running_transition")
        }
        // Read the actual hardware CR3 above; this table check must reject
        // freeing a RUNNING user root or any of its own PMM frames.
        if !matches!(PROCESS_TABLE.with(|t| (
            t.snapshot(pid), t.occupied(), t.running(),
            t.reap_with_status(pid, frames[0]),
        )), Ok((Some(record), 1, 1, Err(TableError::Process(
            crate::process_lifecycle::ProcessError::ActiveCr3
        )))) if record.state == ProcessState::Running
            && record.cr3_root == frames[0] && record.frames == frames
        ) { fail("process_table_active_cr3_guard") }
        #[cfg(feature = "user-process-smoke")]
        serial::write_fmt(format_args!(
            "WOLFOS_PROCESS_START pid={} state=running private_cr3=1 owned_frames=7\n",
            pid,
        ));
        serial::write_fmt(format_args!(
            "WOLFOS_ELF_RUN_ENTER elf64=1 et_exec=1 pt_load=2 rx=1 rw_nx=2 bss_zero=1 cr3_new=1 root_slot={} user_entry={:#x}\n",
            slot, plan.entry,
        ));
        // Real CPU IRETQ into independently LINKED & VALIDATED ELF image.
        asm!(
            "push {ss}", "push {rsp}", "push {flags}",
            "push {cs}", "push {rip}", "iretq",
            ss = in(reg) u64::from(user_ss),
            rsp = in(reg) user_top,
            flags = in(reg) 2u64,
            cs = in(reg) u64::from(user_cs),
            rip = in(reg) code,
            options(noreturn),
        );
    }
}


/// Authenticate the CPU's user-fault frame and the exact live process.
/// Unexpected supervisor faults, wrong RIP/stage, or a swapped CR3 are fatal.
#[cfg(any(feature = "user-invalid-opcode-retire-smoke", feature = "user-page-fault-retire-smoke"))]
fn checked_user_fault_owner(frame: &InterruptStackFrame, symbol_offset: u64) -> u64 {
    let stage = STAGE.load(Ordering::Acquire);
    let active = CR3_PHYS.load(Ordering::Acquire);
    let entry = ENTRY.load(Ordering::Acquire);
    let user_top = STACK_TOP.load(Ordering::Acquire);
    let (user_cs, user_ss, rsp0) = interrupts::ring3_cpu_state();
    let (root, _) = Cr3::read();
    let kernel_rsp: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) kernel_rsp,
            options(nomem, nostack, preserves_flags));
    }
    let base = entry.checked_sub(symbols::ENTRY)
        .unwrap_or_else(|| fail("fault_invalid_user_entry"));
    let fault_rip = base.checked_add(symbol_offset)
        .unwrap_or_else(|| fail("fault_invalid_user_rip"));
    if stage != RETURN_COUNT || RUN_INDEX.load(Ordering::Acquire) != 0
        || active == 0 || entry == 0 || user_top == 0
        || root.start_address().as_u64() != active
        || CS::get_reg().0 != 8
        || frame.code_segment.0 != user_cs
        || frame.stack_segment.0 != user_ss
        || frame.instruction_pointer.as_u64() != fault_rip
        || frame.stack_pointer.as_u64() != user_top
        || rsp0 < 16 * 1024
        || kernel_rsp < rsp0 - (16 * 1024) || kernel_rsp >= rsp0
    { fail("fault_provenance_or_stage") }
    let data = DATA_HHDM.load(Ordering::Acquire);
    if data == 0 { fail("fault_missing_owned_elf_data") }
    let actual = unsafe { &*(data as *const [u8; 65]) };
    if actual[0] != 0x5a || actual[1..].iter().any(|b| *b != 0)
    { fail("fault_guest_data_or_bss_corrupted") }
    active
}

/// Genuine hardware #UD originating at the fixed USER RIP.
/// Other #UD faults remain hard errors; never classify kernel defects as user exits.
#[cfg(feature = "user-invalid-opcode-retire-smoke")]
pub(crate) fn retire_user_invalid_opcode(frame: &InterruptStackFrame) -> ! {
    let active = checked_user_fault_owner(frame, symbols::FAULT_UD);
    const USER_SIGILL_STATUS: u32 = 128 + 4;
    if !matches!(PROCESS_TABLE.with(|t| t.exit_with_status(1, active, USER_SIGILL_STATUS)), Ok(Ok(()))) {
        fail("ud_process_exit_transition")
    }
    serial::write_line("WOLFOS_ELF_USER_UD_OK vector=6 cpl3=1 status=132 int80_calls=21 user_rip_verified=1");
    finish_exited(1, USER_SIGILL_STATUS, active)
}

/// Real CPU #PF on a fixed high-half read from CPL3, never a synthetic
/// kernel failure. The address and fault bits are independently validated.
/// No IRETQ after process exit: restore boot CR3 before releasing PMM.
#[cfg(feature = "user-page-fault-retire-smoke")]
pub(crate) fn retire_user_page_fault(frame: &InterruptStackFrame, code: PageFaultErrorCode) -> ! {
    const DENIED_SUPERVISOR_ADDR: u64 = 0xffff_8000_0000_0000;
    if !matches!(Cr2::read(), Ok(addr) if addr.as_u64() == DENIED_SUPERVISOR_ADDR)
        || !code.contains(PageFaultErrorCode::USER_MODE)
        || code.contains(PageFaultErrorCode::CAUSED_BY_WRITE)
        || code.contains(PageFaultErrorCode::INSTRUCTION_FETCH)
    { fail("pf_wrong_cr2_or_fault_bits") }
    let active = checked_user_fault_owner(frame, symbols::FAULT_PF);
    const USER_SIGSEGV_STATUS: u32 = 128 + 11;
    if !matches!(PROCESS_TABLE.with(|t| t.exit_with_status(1, active, USER_SIGSEGV_STATUS)), Ok(Ok(()))) {
        fail("pf_process_exit_transition")
    }
    serial::write_line("WOLFOS_ELF_USER_PF_OK vector=14 cpl3=1 status=139 address=0xffff800000000000 read_denied=1 user_rip_verified=1");
    finish_exited(1, USER_SIGSEGV_STATUS, active)
}

/// Shared single-owner retirement for EXIT(0), EXIT(42), authenticated
/// #UD and #PF paths, after the PID has entered Exited state.
/// Never dereference the former user root after restoring supervisor CR3.
fn finish_exited(pid: u64, exit_status: u32, active: u64) -> ! {
    // Hardware restoration before FREE: the boot CR3 has all needed
    // kernel, HHDM, TSS and serial mappings. Never release an ACTIVE
    // PML4; interrupt return will NOT be executed after this exit.
    let boot = BOOT_CR3.load(Ordering::Acquire);
    if boot == 0 || boot == active { fail("invalid_boot_root_ownership") }
    unsafe {
        asm!("mov cr3, {}", in(reg) boot,
            options(nostack, preserves_flags));
    }
    let (now, _) = Cr3::read();
    if now.start_address().as_u64() != boot { fail("boot_cr3_not_restored") }
    // The audited PID ledger authorizes release ONLY after CR3
    // restoration, only for this exact owning PID, exactly once.
    let owned_by_pid = match PROCESS_TABLE.with(|t| t.reap_with_status(pid, boot)) {
        Ok(Ok((code, frames))) if code == exit_status => frames,
        _ => fail("process_reap_or_exit_status"),
    };
    if cfg!(feature = "user-page-fault-retire-smoke")
        && (!cfg!(feature = "user-process-fault-recovery-smoke") || pid == 1)
    {
        serial::write_line("WOLFOS_ELF_USER_PF_REAP_OK pid=1 status=139 active_cr3_restored=1 lease=7");
    } else if cfg!(feature = "user-invalid-opcode-retire-smoke") {
        serial::write_line("WOLFOS_ELF_USER_UD_REAP_OK pid=1 status=132 active_cr3_restored=1 lease=7");
    } else if cfg!(feature = "user-exit-status-smoke") {
        serial::write_line("WOLFOS_ELF_STATUS_REAP_OK pid=1 code=42 active_cr3_restored=1 lease=7");
    }
    for i in (0..FRAMES).rev() {
        let owned = OWNED[i].swap(0, Ordering::AcqRel);
        if owned == 0 || owned != owned_by_pid[i]
            || pmm::free_frame(owned).is_err()
        {
            fail("owned_user_frame_free_failed")
        }
    }
    // The exact former PID must be absent, its slot free, and an attempted
    // second reap must fail. No other live table entry may remain.
    if !matches!(PROCESS_TABLE.with(|t| (
        t.snapshot(pid), t.occupied(), t.running(),
        t.reap_with_status(pid, boot),
    )), Ok((None, 0, 0, Err(TableError::UnknownPid)))) {
        fail("process_table_stale_pid_or_double_reap")
    }
    if pmm::statistics().allocated_frames != ALLOCATED_BEFORE.load(Ordering::Acquire)
    { fail("pmm_frame_leak") }
    serial::write_line("WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1");
    serial::write_fmt(format_args!(
        "WOLFOS_PROCESS_TABLE_REAP_OK pid={} slots=2 occupied=0 running=0 stale_denied=1 double_reap_denied=1 real_cpl3=1\n",
        pid,
    ));
    if cfg!(feature = "user-page-fault-retire-smoke")
        && (!cfg!(feature = "user-process-fault-recovery-smoke") || pid == 1)
    {
        serial::write_line("WOLFOS_ELF_USER_PF_RUN_OK linked_elf=1 hardware_cpl3=1 pf_vector=14 status=139 int80_calls=21 frames_freed=7 pmm_no_leak=1");
    } else if cfg!(feature = "user-invalid-opcode-retire-smoke") {
        serial::write_line("WOLFOS_ELF_USER_UD_RUN_OK linked_elf=1 hardware_cpl3=1 ud_vector=6 status=132 int80_calls=21 frames_freed=7 pmm_no_leak=1");
    } else if cfg!(feature = "user-exit-status-smoke") {
        serial::write_line("WOLFOS_ELF_STATUS_RUN_OK linked_elf=1 hardware_cpl3=1 user_console=1 int80_calls=22 exit=42 resources_released=1 real_process_manager=0");
    } else if cfg!(feature = "user-file-io-smoke") {
        serial::write_line("WOLFOS_FILE_IO_RUN_OK linked_elf=1 hardware_cpl3=1 real_file_syscalls=3 int80_calls=12 exit=0 resources_released=1 persistent=0 production=0");
    } else if cfg!(feature = "user-copy-smoke") {
        serial::write_line("WOLFOS_USERCOPY_RUN_OK linked_elf=1 hardware_cpl3=1 real_user_pointer=1 int80_calls=4 exit=0 resources_released=1 production_user_copy=0");
    } else {
        serial::write_line("WOLFOS_ELF_RUN_OK linked_elf=1 hardware_cpl3=1 user_console=1 int80_calls=22 exit=0 resources_released=1 real_process_manager=0");
    }
    #[cfg(feature = "user-process-smoke")]
    {
        serial::write_fmt(format_args!(
            "WOLFOS_PROCESS_REAP_OK pid={} exited=1 restored_cr3=1 freed_frames=7 no_leak=1\n",
            pid,
        ));
        if pid == 1 {
            #[cfg(feature = "user-process-fault-recovery-smoke")]
            if exit_status != 139 { fail("recovery_pid1_expected_sigsegv") }
            RUN_INDEX.store(1, Ordering::Release);
            serial::write_line("WOLFOS_PROCESS_RELAUNCH pid=2 generation=2 first_reaped=1");
            // No return to user kernel-stack frames from PID 1:
            // only start a new independent root after full CR3
            // restoration and prior PMM resources were reclaimed.
            enter(HHDM_OFFSET.load(Ordering::Acquire));
        }
        if pid != 2 { fail("invalid_second_process_pid") }
        RUN_INDEX.store(2, Ordering::Release);
        if cfg!(feature = "user-process-fault-recovery-smoke") {
            if exit_status != 0 { fail("recovery_pid2_expected_exit_zero") }
            serial::write_line("WOLFOS_PROCESS_FAULT_RECOVERY_OK first_pid=1 first_status=139 second_pid=2 second_status=0 total_int80=43 restored_cr3=2 frames_freed=14 pmm_no_leak=1");
        } else {
            serial::write_line("WOLFOS_PROCESS_LIFECYCLE_OK launched=2 exited=2 reaped=2 total_int80=44 restored_cr3=1 per_pid_owner=1 pmm_no_leak=1 concurrent=0");
        }
    }
    #[cfg(feature = "user-ramfs-smoke")]
    crate::ramfs_smoke::report_elf_exit();
    #[cfg(feature = "user-vfs-smoke")]
    crate::vfs_smoke::report_exit();
    serial::qemu_exit_success()
}

#[unsafe(no_mangle)]
pub extern "C" fn wolfos_int80_syscall_dispatch(
    raw: *mut UserSyscallFrame,
) -> *mut UserSyscallFrame {
    if raw.is_null() { fail("null_iret_frame") }
    let stage = STAGE.load(Ordering::Acquire);
    if stage >= TOTAL_CALLS { fail("unexpected_extra_syscall") }
    let (user_cs, user_ss, rsp0) = interrupts::ring3_cpu_state();
    let active = CR3_PHYS.load(Ordering::Acquire);
    let user_entry = ENTRY.load(Ordering::Acquire);
    let user_top = STACK_TOP.load(Ordering::Acquire);
    let frame_addr = raw as u64;
    let (root, _) = Cr3::read();
    if active == 0 || user_entry == 0
        || root.start_address().as_u64() != active
        || CS::get_reg().0 != 8
        || frame_addr & 7 != 0 || frame_addr < rsp0 - (16 * 1024)
        || frame_addr.checked_add(user_syscall_abi::FRAME_BYTES as u64)
            .is_none_or(|end| end > rsp0)
    { fail("trap_cr3_rsp0_or_privilege") }
    // SAFETY: the custom assembly saved ALL registers onto the checked
    // TSS.RSP0 supervisor stack before calling this dispatcher. No user
    // pointer is dereferenced; all virtual user inputs are only numbers.
    let frame = unsafe { &mut *raw };
    let base = user_entry - symbols::ENTRY;
    #[cfg(feature = "user-file-io-smoke")]
    if stage >= 2 && stage < RETURN_COUNT {
        let pid = RUN_INDEX.load(Ordering::Acquire) as u64 + 1;
        let fd = FILE_FD.load(Ordering::Acquire);
        let (expected_rip, nr, a0, a1, a2, want) = match stage {
            2 => (symbols::FILE_POLICY_DENIED_OPEN, 6, base + symbols::FILE_PATH,
                  12, 0, crate::user_file_io::EACCES as u64),
            3 => (symbols::FILE_BAD_OPEN, 6, 0xffff_8000_0000_0000,
                  12, 0, crate::user_file_io::EFAULT as u64),
            4 => (symbols::FILE_OPEN, 6, base + symbols::FILE_PATH,
                  12, 0, 256),
            5 => (symbols::FILE_BAD_READ, 7, fd,
                  base + symbols::HELLO_TEXT, 8, crate::user_file_io::EFAULT as u64),
            6 => (symbols::FILE_READ, 7, fd, user_top - 32, 8, 8),
            7 => (symbols::FILE_POLICY_REVOKED_READ, 7, fd,
                  user_top - 32, 8, crate::user_file_io::EACCES as u64),
            8 => (symbols::FILE_EOF, 7, fd, user_top - 32, 8, 0),
            9 => (symbols::FILE_CLOSE, 8, fd, 0, 0, 0),
            10 => (symbols::FILE_STALE_CLOSE, 8, fd, 0, 0,
                  crate::user_file_io::EBADF as u64),
            _ => fail("invalid_file_io_stage"),
        };
        if frame.hardware.cs != u64::from(user_cs)
            || frame.hardware.ss != u64::from(user_ss)
            || frame.hardware.rip != base + expected_rip
            || frame.hardware.rsp != user_top
            || !user_syscall_abi::valid_user_rflags(frame.hardware.rflags)
            || frame.registers.rax != nr || frame.registers.rdi != a0
            || frame.registers.rsi != a1 || frame.registers.rdx != a2
            || (stage >= 5 && frame.registers.r12 != fd)
        { fail("file_io_guest_trap_frame_or_registers") }
        let result = crate::user_file_io_smoke::dispatch(pid, active, nr, a0, a1, a2);
        if result != want { 
            serial::write_fmt(format_args!(
                "WOLFOS_FILE_IO_ERROR stage={} result={:#x} expected={:#x}\n",
                stage, result, want
            ));
            fail("file_io_return_value")
        }
        match stage {
            2 => {
                crate::user_file_io_smoke::prove_default_denial(pid);
                crate::user_file_io_smoke::grant_file_read(pid, 0);
            },
            3 => serial::write_line("WOLFOS_FILE_IO_BAD_OPEN_OK supervisor_denied=1"),
            4 => {
                FILE_FD.store(result, Ordering::Release);
                serial::write_line("WOLFOS_FILE_IO_OPEN_OK path_user_rx=1 fd=256");
            },
            5 => serial::write_line("WOLFOS_FILE_IO_BAD_READ_OK rx_write_denied=1 cursor_rollback=1"),
            6 => {
                let mut proof = [0u8;8];
                if crate::user_copy::copy_from(
                    active, user_top - 32, &mut proof, private_pte, private_byte
                ).is_err() || proof != *b"FILE_OK\n"
                { fail("user_stack_file_contents") }
                serial::write_line("WOLFOS_FILE_IO_READ_OK bytes=8 user_stack=1 payload=FILE_OK");
                crate::user_file_io_smoke::revoke_file_read(pid);
            },
            7 => {
                crate::user_file_io_smoke::prove_revoked_read(pid);
                crate::user_file_io_smoke::grant_file_read(pid, 1);
            },
            8 => serial::write_line("WOLFOS_FILE_IO_EOF_OK read=0"),
            9 => serial::write_line("WOLFOS_FILE_IO_CLOSE_OK released=1"),
            10 => serial::write_line("WOLFOS_FILE_IO_STALE_OK ebadf=1"),
            _ => fail("invalid_file_io_marker"),
        }
        frame.registers.rax = result;
        STAGE.store(stage + 1, Ordering::Release);
        return raw;
    }
    let expected_rip = if stage == 0 { symbols::AFTER_ID }
        else if stage == 1 { symbols::AFTER_ADD }
        else if cfg!(feature = "user-copy-smoke") && stage == 2 {
            symbols::AFTER_WRITE
        } else if stage < RETURN_COUNT { symbols::AFTER_PUTC }
        else { symbols::AFTER_EXIT };
    let number = if stage == 0 { user_syscall_abi::SYS_WOLFOS_ID }
        else if stage == 1 { user_syscall_abi::SYS_U32_ADD }
        else if cfg!(feature = "user-copy-smoke") && stage == 2 { 5 }
        else if stage < RETURN_COUNT { user_syscall_abi::SYS_PUTC }
        else if cfg!(feature = "user-exit-status-smoke") { user_syscall_abi::SYS_EXIT_STATUS }
        else { user_syscall_abi::SYS_EXIT_ZERO };
    let arg0 = if stage == 1 { 7 }
        else if cfg!(feature = "user-copy-smoke") && stage == 2 {
            base + symbols::HELLO_TEXT
        } else if stage < RETURN_COUNT && stage >= 2 {
            u64::from(HELLO[stage - 2])
        } else if cfg!(feature = "user-exit-status-smoke") && stage == RETURN_COUNT {
            42
        } else { 0 };
    let arg1 = if stage == 1 { 35 }
        else if cfg!(feature = "user-copy-smoke") && stage == 2 {
            HELLO.len() as u64
        } else { 0 };
    if frame.hardware.cs != u64::from(user_cs)
        || frame.hardware.ss != u64::from(user_ss)
        || frame.hardware.rip != base + expected_rip
        || frame.hardware.rsp != user_top
        || !user_syscall_abi::valid_user_rflags(frame.hardware.rflags)
        || frame.registers.rax != number
        || frame.registers.rdi != arg0
        || frame.registers.rsi != arg1
    {
        serial::write_fmt(format_args!(
            "WOLFOS_ELF_RUN_ERROR trap stage={} nr={:#x} arg0={:#x} arg1={:#x} rip={:#x} expected={:#x} flags={:#x}\n",
            stage, frame.registers.rax, frame.registers.rdi, frame.registers.rsi,
            frame.hardware.rip, base + expected_rip, frame.hardware.rflags
        ));
        crate::halt_forever()
    }
    if !cfg!(feature = "user-copy-smoke")
        && stage >= 2 && stage < RETURN_COUNT
        && (frame.registers.rbx != base + symbols::HELLO_TEXT + (stage - 2) as u64
            || frame.registers.rcx != (HELLO.len() - (stage - 2)) as u64)
    { fail("guest_registers_not_preserved") }
    #[cfg(feature = "user-copy-smoke")]
    if stage == 2 {
        if number != 5 || frame.registers.rdx != 0 {
            fail("write_syscall_number_or_reserved_arg")
        }
        let mut buffer = [0u8; HELLO.len()];
        let result = crate::user_copy::copy_from(
            active, frame.registers.rdi, &mut buffer, private_pte, private_byte
        );
        if result.is_err() || buffer != *HELLO {
            fail("user_pointer_write_copy_invalid")
        }
        // Prove a user-controlled address cannot alias supervisor kernel
        // or write RX text; validate actual live four-level PTEs.
        let mut rejected = [0xa5u8; 1];
        if crate::user_copy::copy_from(
            active, crate::kmain as usize as u64, &mut rejected,
            private_pte, private_byte
        ) != Err(crate::user_copy::CopyError::InvalidRange)
            || rejected != [0xa5]
            || crate::user_copy::copy_to(
                active, base + symbols::HELLO_TEXT, b"corrupt",
                private_pte, private_rw_byte
            ) != Err(crate::user_copy::CopyError::ReadOnly)
        { fail("supervisor_or_readonly_copy_not_denied") }
        let scratch = user_top - 32;
        if crate::user_copy::copy_to(
            active, scratch, b"safe", private_pte, private_rw_byte
        ).is_err()
        { fail("user_stack_copy_to") }
        let mut proof = [0u8;4];
        if crate::user_copy::copy_from(
            active, scratch, &mut proof, private_pte, private_byte
        ).is_err() || &proof != b"safe"
        { fail("user_stack_copy_from") }
        STAGE.store(stage + 1, Ordering::Release);
        serial::write_fmt(format_args!("{}", core::str::from_utf8(&buffer).unwrap()));
        serial::write_line("WOLFOS_USERCOPY_WRITE_OK guest_pointer=1 user_cr3_walk=4 copied=19 kernel_denied=1 rx_write_denied=1 stack_copy_roundtrip=1");
        frame.registers.rax = HELLO.len() as u64;
        return raw;
    }
    let outcome = user_syscall_abi::dispatch(number, arg0, arg1);
    STAGE.store(stage + 1, Ordering::Release);
    match outcome {
        Outcome::Return(value) => {
            if stage == 0 && value != user_syscall_abi::WOLFOS_ID
                || stage == 1 && value != 42
                || stage >= 2
            { fail("bad_syscall_result") }
            frame.registers.rax = value;
            if stage == 0 {
                serial::write_line("WOLFOS_ELF_ID_OK cpl3=1 return_rax=0x574f4c46");
            } else {
                serial::write_line("WOLFOS_ELF_ADD_OK cpl3=1 return_rax=42");
            }
            raw
        }
        Outcome::WriteByte(c) => {
            if stage < 2 || stage >= RETURN_COUNT || c != HELLO[stage - 2]
            { fail("unexpected_guest_putc") }
            // One printable byte per valid user INT80; no pointers read.
            serial::write_fmt(format_args!("{}", c as char));
            frame.registers.rax = 1;
            if stage + 1 == RETURN_COUNT {
                serial::write_line("WOLFOS_ELF_HELLO_OK bytes=19 syscall_iretq=19");
            }
            raw
        }
        Outcome::ExitZero | Outcome::ExitStatus(_) => {
            let exit_status = match outcome {
                Outcome::ExitZero => 0,
                Outcome::ExitStatus(code) => code,
                _ => fail("wrong_exit_outcome"),
            };
            let expected_status = if cfg!(feature = "user-exit-status-smoke") { 42 } else { 0 };
            if exit_status != expected_status { fail("guest_exit_status_mismatch") }
            let pid = RUN_INDEX.load(Ordering::Acquire) as u64 + 1;
            if stage != RETURN_COUNT || STAGE.load(Ordering::Acquire) != TOTAL_CALLS
            { fail("unexpected_exit_stage") }
            let data = DATA_HHDM.load(Ordering::Acquire);
            if data == 0 { fail("missing_owned_elf_data") }
            // Validate the segment STILL matches genuine ELF file bytes and
            // all BSS bytes remain zero after user execution.
            let actual = unsafe { &*(data as *const [u8; 65]) };
            if actual[0] != 0x5a || actual[1..].iter().any(|b| *b != 0)
            { fail("guest_elf_data_or_bss_corrupted") }
            if !matches!(PROCESS_TABLE.with(|t| t.exit_with_status(pid, active, exit_status)), Ok(Ok(()))) {
                fail("process_exit_transition")
            }
            #[cfg(feature = "user-file-io-smoke")]
            crate::user_file_io_smoke::verify_exit(pid);
            if cfg!(feature = "user-exit-status-smoke") {
                serial::write_line("WOLFOS_ELF_EXIT_STATUS_OK code=42 cpl3=1 calls=22 saved_rdi=42");
            } else if cfg!(feature = "user-file-io-smoke") {
                serial::write_line("WOLFOS_FILE_IO_EXIT_OK code=0 cpl3=1 calls=12");
            } else if cfg!(feature = "user-copy-smoke") {
                serial::write_line("WOLFOS_USERCOPY_EXIT_OK code=0 cpl3=1 calls=4");
            } else {
                serial::write_line("WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=22");
            }

            finish_exited(pid, exit_status, active)
        }
    }
}
