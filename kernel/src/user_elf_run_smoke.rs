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
    process_lifecycle::{ProcessCell, ProcessState},
    user_ring_entry::{self, Ring3Entry},
    user_syscall_abi::{self, Outcome, UserSyscallFrame},
};

mod symbols {
    include!(concat!(env!("OUT_DIR"), "/wolfos_elf_symbols.rs"));
}
const ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wolfos-user-hello.elf"));
const HELLO: &[u8; 19] = b"Hello from WolfOS!\n";
const PAGE: u64 = 4096;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const USER: u64 = 4;
const NX: u64 = 1 << 63;
const SLOTS: usize = 512;
const FRAMES: usize = 7; // new PML4, PDPT, PD, PT, RX text, RW data/BSS, RW stack
const STACK_VA: u64 = 0x404000;
const RETURN_COUNT: usize = HELLO.len() + 2;
const EXTRA_FILE_CALLS: usize = if cfg!(feature = "user-file-io-smoke") { 5 } else { 0 };
const EXIT_STAGE: usize = RETURN_COUNT + EXTRA_FILE_CALLS;
const TOTAL_CALLS: usize = EXIT_STAGE + 1;
#[cfg(feature = "user-file-io-smoke")]
const FILE_BYTES: &[u8; 8] = b"FILE_OK\n";
#[cfg(feature = "user-file-io-smoke")]
static FILE_FD: AtomicU64 = AtomicU64::new(0);

static ENTRY: AtomicU64 = AtomicU64::new(0);
static STACK_TOP: AtomicU64 = AtomicU64::new(0);
static DATA_HHDM: AtomicU64 = AtomicU64::new(0);
static CR3_PHYS: AtomicU64 = AtomicU64::new(0);
static BOOT_CR3: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BEFORE: AtomicUsize = AtomicUsize::new(0);
static STAGE: AtomicUsize = AtomicUsize::new(0);
static OWNED: [AtomicU64; FRAMES] = [const { AtomicU64::new(0) }; FRAMES];
/// Common audited ownership record for the original ELF smoke and the
/// two-process lifecycle feature, with monotonic process generations.
static PROCESS: ProcessCell<FRAMES> = ProcessCell::new();
static RUN_INDEX: AtomicUsize = AtomicUsize::new(0);
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);
const MAX_RUNS: usize = if cfg!(feature = "user-process-smoke") { 2 } else { 1 };

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
    #[cfg(not(any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")))]
    let elf: &[u8] = ELF;
    if index == 0 {
        if !interrupts::verify_ring3_preconditions() { fail("gdt_tss") }
    } else {
        #[cfg(feature = "user-process-smoke")]
        {
            // Only allow the second user admission AFTER the first PID was
            // fully reaped and no PMM pages remain owned. CPU SS=0 is valid
            // here because the kernel arrived via a real CPL3 INT80 trap.
            let safely_reaped = matches!(
                PROCESS.with(|p| (p.pid, p.state, p.frames)),
                Ok((1, ProcessState::Reaped, frames)) if frames.iter().all(|f| *f == 0),
            );
            if !safely_reaped || OWNED.iter().any(|p| p.load(Ordering::Acquire) != 0)
                || !interrupts::verify_ring3_reentry_preconditions()
            { fail("second_user_kernel_reentry_preflight") }
        }
        #[cfg(not(feature = "user-process-smoke"))]
        fail("unreachable_user_reentry");
    }
    #[cfg(feature = "user-file-io-smoke")]
    if symbols::FILE_PATH_END != symbols::FILE_PATH + 13
        || symbols::AFTER_FILE_OPEN <= symbols::AFTER_PUTC
        || symbols::AFTER_FILE_READ <= symbols::AFTER_FILE_OPEN
        || symbols::AFTER_FILE_BAD_READ <= symbols::AFTER_FILE_READ
        || symbols::AFTER_FILE_CLOSE <= symbols::AFTER_FILE_BAD_READ
        || symbols::AFTER_FILE_BAD_OPEN <= symbols::AFTER_FILE_CLOSE
        || symbols::AFTER_EXIT <= symbols::AFTER_FILE_BAD_OPEN
        || symbols::FILE_PATH < symbols::HELLO_END
    { fail("file_elf_linker_contract") }

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
        for (at, phys) in frames.iter().copied().enumerate() {
            OWNED[at].store(phys, Ordering::Release);
        }
        if !matches!(PROCESS.with(|p| p.admit(pid, frames[0], frames)), Ok(Ok(()))) {
            fail("process_admission_or_frame_ownership")
        }
        compiler_fence(Ordering::SeqCst);
        asm!("mov cr3, {}", in(reg) frames[0],
            options(nostack, preserves_flags));
        let (now, _) = Cr3::read();
        if now.start_address().as_u64() != frames[0] { fail("new_cr3_not_active") }
        if !matches!(PROCESS.with(|p| p.mark_running(pid, frames[0])), Ok(Ok(()))) {
            fail("process_running_transition")
        }
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
    if stage >= RETURN_COUNT && stage < EXIT_STAGE {
        return handle_file_call(raw, frame, base, stage);
    }
    let expected_rip = if stage == 0 { symbols::AFTER_ID }
        else if stage == 1 { symbols::AFTER_ADD }
        else if stage < RETURN_COUNT { symbols::AFTER_PUTC }
        else { symbols::AFTER_EXIT };
    let number = if stage == 0 { user_syscall_abi::SYS_WOLFOS_ID }
        else if stage == 1 { user_syscall_abi::SYS_U32_ADD }
        else if stage < RETURN_COUNT { user_syscall_abi::SYS_PUTC }
        else { user_syscall_abi::SYS_EXIT_ZERO };
    let arg0 = if stage == 1 { 7 }
        else if stage < RETURN_COUNT && stage >= 2 {
            u64::from(HELLO[stage - 2])
        } else { 0 };
    let arg1 = if stage == 1 { 35 } else { 0 };
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
    if stage >= 2 && stage < RETURN_COUNT
        && (frame.registers.rbx != base + symbols::HELLO_TEXT + (stage - 2) as u64
            || frame.registers.rcx != (HELLO.len() - (stage - 2)) as u64)
    { fail("guest_registers_not_preserved") }
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
        Outcome::ExitZero => {
            let pid = RUN_INDEX.load(Ordering::Acquire) as u64 + 1;
            if stage != EXIT_STAGE || STAGE.load(Ordering::Acquire) != TOTAL_CALLS
            { fail("unexpected_exit_stage") }
            let data = DATA_HHDM.load(Ordering::Acquire);
            if data == 0 { fail("missing_owned_elf_data") }
            // Validate the segment STILL matches genuine ELF file bytes and
            // all BSS bytes remain zero after user execution.
            let actual = unsafe { &*(data as *const [u8; 65]) };
            if actual[0] != 0x5a { fail("guest_elf_data_or_bss_corrupted") }
            #[cfg(not(feature = "user-file-io-smoke"))]
            if actual[1..].iter().any(|b| *b != 0)
            { fail("guest_elf_bss_corrupted") }
            #[cfg(feature = "user-file-io-smoke")]
            {
                if &actual[1..9] != FILE_BYTES || actual[9..].iter().any(|b| *b != 0) {
                    fail("guest_file_read_did_not_write_bss_exactly")
                }
                crate::user_file_io_smoke::finish(pid);
            }
            if !matches!(PROCESS.with(|p| p.exit_zero(pid, active)), Ok(Ok(()))) {
                fail("process_exit_transition")
            }
            #[cfg(not(feature = "user-file-io-smoke"))]
            serial::write_line("WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=22");
            #[cfg(feature = "user-file-io-smoke")]
            serial::write_line("WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=27");

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
            let owned_by_pid = match PROCESS.with(|p| p.reap(pid, boot)) {
                Ok(Ok(frames)) => frames,
                _ => fail("process_reap_or_active_cr3"),
            };
            for i in (0..FRAMES).rev() {
                let owned = OWNED[i].swap(0, Ordering::AcqRel);
                if owned == 0 || owned != owned_by_pid[i]
                    || pmm::free_frame(owned).is_err()
                {
                    fail("owned_user_frame_free_failed")
                }
            }
            if !matches!(PROCESS.with(|p| p.state), Ok(ProcessState::Reaped)) {
                fail("process_not_reaped")
            }
            if pmm::statistics().allocated_frames != ALLOCATED_BEFORE.load(Ordering::Acquire)
            { fail("pmm_frame_leak") }
            serial::write_line("WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1");
            #[cfg(not(feature = "user-file-io-smoke"))]
            serial::write_line("WOLFOS_ELF_RUN_OK linked_elf=1 hardware_cpl3=1 user_console=1 int80_calls=22 exit=0 resources_released=1 real_process_manager=0");
            #[cfg(feature = "user-file-io-smoke")]
            serial::write_line("WOLFOS_ELF_RUN_OK linked_elf=1 hardware_cpl3=1 user_console=1 int80_calls=27 exit=0 resources_released=1 real_process_manager=0");
            #[cfg(feature = "user-process-smoke")]
            {
                serial::write_fmt(format_args!(
                    "WOLFOS_PROCESS_REAP_OK pid={} exited=1 restored_cr3=1 freed_frames=7 no_leak=1\n",
                    pid,
                ));
                if pid == 1 {
                    RUN_INDEX.store(1, Ordering::Release);
                    serial::write_line("WOLFOS_PROCESS_RELAUNCH pid=2 generation=2 first_reaped=1");
                    // No return to user kernel-stack frames from PID 1:
                    // only start a new independent root after full CR3
                    // restoration and prior PMM resources were reclaimed.
                    enter(HHDM_OFFSET.load(Ordering::Acquire));
                }
                if pid != 2 { fail("invalid_second_process_pid") }
                RUN_INDEX.store(2, Ordering::Release);
                serial::write_line("WOLFOS_PROCESS_LIFECYCLE_OK launched=2 exited=2 reaped=2 total_int80=44 restored_cr3=1 per_pid_owner=1 pmm_no_leak=1 concurrent=0");
            }
            #[cfg(feature = "user-ramfs-smoke")]
            crate::ramfs_smoke::report_elf_exit();
            #[cfg(feature = "user-vfs-smoke")]
            crate::vfs_smoke::report_exit();
            serial::qemu_exit_success()
        }
    }
}


/// Hardware-proven single-page user copy for the feature-isolated file ABI.
/// Every page-table ancestor MUST resolve to our seven PMM-owned frames.
/// Never borrow or dereference the untrusted virtual address directly.
#[cfg(feature = "user-file-io-smoke")]
fn user_pointer(address: u64, bytes: usize, writable: bool) -> Result<*mut u8, ()> {
    use crate::user_copy;
    let base = ENTRY.load(Ordering::Acquire)
        .checked_sub(symbols::ENTRY).ok_or(())?;
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let frame = |n: usize| OWNED[n].load(Ordering::Acquire);
    if hhdm == 0 || (0..FRAMES).any(|i| frame(i) == 0) {
        return Err(())
    }
    let (root, _) = Cr3::read();
    if root.start_address().as_u64() != frame(0) {
        return Err(())
    }
    let slot = ((base >> 39) & 511) as usize;
    if slot == 0 || slot >= 256 { return Err(()) }
    let page = address & !(PAGE - 1);
    let (leaf_idx, page_phys) = if page == base + 0x401000 {
        (1usize, frame(4))
    } else if page == base + 0x403000 {
        (3usize, frame(5))
    } else if page == base + STACK_VA {
        (4usize, frame(6))
    } else { return Err(()) };
    // SAFETY: Every table frame originated from PMM's independently
    // validated, live frame ownership ledger. HHDM remains mapped in
    // BOTH original and sanitized kernel high halves. Only read table
    // entries after live CR3 and all owner frame identities were checked.
    let table = |index: usize| unsafe {
        &*((hhdm + frame(index)) as *const [u64; SLOTS])
    };
    if table(0)[slot] != frame(1) | (PRESENT | WRITE | USER)
        || table(1)[0] != frame(2) | (PRESENT | WRITE | USER)
        || table(2)[2] != frame(3) | (PRESENT | WRITE | USER)
    { return Err(()) }
    let leaf = table(3)[leaf_idx];
    let offset = user_copy::admit(
        address, bytes, page, leaf, page_phys, writable
    ).map_err(|_| ())?;
    let vaddr = hhdm.checked_add(page_phys)
        .and_then(|p| p.checked_add(offset as u64)).ok_or(())?;
    let valid = VirtAddr::try_new(vaddr).map_err(|_| ())?;
    Ok(valid.as_mut_ptr())
}

/// Exact independent ELF instruction symbol -> syscall number, register
/// argument, and user-pointer-admission contract. These five calls are
/// NOT exposed in the old 22-call ABI smoke; they are a separate feature.
#[cfg(feature = "user-file-io-smoke")]
fn handle_file_call(
    raw: *mut UserSyscallFrame,
    frame: &mut UserSyscallFrame,
    base: u64,
    stage: usize,
) -> *mut UserSyscallFrame {
    let offset = stage - RETURN_COUNT;
    if offset >= 5 { fail("invalid_file_syscall_stage") }
    let expected_rip = [
        symbols::AFTER_FILE_OPEN,
        symbols::AFTER_FILE_READ,
        symbols::AFTER_FILE_BAD_READ,
        symbols::AFTER_FILE_CLOSE,
        symbols::AFTER_FILE_BAD_OPEN,
    ][offset] + base;
    let expected_num = [5, 6, 6, 7, 5][offset];
    let token = FILE_FD.load(Ordering::Acquire);
    let expected_rdi = match offset {
        0 => base + symbols::FILE_PATH,
        1..=3 => token,
        _ => 0xffff800000000000,
    };
    let expected_rsi = match offset {
        0 | 4 => 13,
        1 => base + symbols::BSS_START,
        2 => base + symbols::FILE_PATH,
        _ => 0,
    };
    let (user_cs, user_ss, _) = interrupts::ring3_cpu_state();
    if frame.hardware.cs != u64::from(user_cs)
        || frame.hardware.ss != u64::from(user_ss)
        || frame.hardware.rip != expected_rip
        || frame.hardware.rsp != STACK_TOP.load(Ordering::Acquire)
        || !user_syscall_abi::valid_user_rflags(frame.hardware.rflags)
        || frame.registers.rax != expected_num
        || frame.registers.rdi != expected_rdi
        || frame.registers.rsi != expected_rsi
        || ((offset == 1 || offset == 2) && frame.registers.rdx != 8)
        || ((offset == 1 || offset == 2 || offset == 3) && token == 0)
    {
        serial::write_fmt(format_args!(
            "WOLFOS_FILE_IO_ERROR trap index={} num={:#x} rdi={:#x} rsi={:#x} rdx={:#x} rip={:#x} exp_rip={:#x}\n",
            offset, frame.registers.rax, frame.registers.rdi,
            frame.registers.rsi, frame.registers.rdx,
            frame.hardware.rip, expected_rip
        ));
        crate::halt_forever()
    }
    const EFAULT: u64 = (-14i64) as u64;
    let pid = RUN_INDEX.load(Ordering::Acquire) as u64 + 1;
    if pid != 1 { fail("file_io_pid_owner") }
    let result = match offset {
        0 => {
            let ptr = user_pointer(expected_rdi, 13, false)
                .unwrap_or_else(|_| fail("valid_open_path_pointer_rejected"));
            let mut path = [0u8; 13];
            // SAFETY: pointer has been checked against current CR3
            // ancestors, read-only user text PTE, frame identity and
            // single-page 13-byte extent.
            unsafe { core::ptr::copy_nonoverlapping(ptr, path.as_mut_ptr(), 13) };
            if &path != crate::user_file_io_smoke::PATH {
                fail("untrusted_user_path_not_expected")
            }
            let fd = crate::user_file_io_smoke::open_read(pid, &path)
                .unwrap_or_else(|_| fail("file_open_failed"));
            FILE_FD.store(fd, Ordering::Release);
            serial::write_line("WOLFOS_FILE_OPEN_OK cpl3=1 pid=1 path_from_user=1 fd_owned=1");
            fd
        }
        1 => {
            let dest = user_pointer(expected_rsi, 8, true)
                .unwrap_or_else(|_| fail("valid_bss_destination_rejected"));
            let mut bytes = [0u8; 8];
            let count = crate::user_file_io_smoke::read(pid, token, &mut bytes)
                .unwrap_or_else(|_| fail("vfs_file_read_failed"));
            if count != 8 || &bytes != FILE_BYTES { fail("wrong_file_contents") }
            // SAFETY: independent RW+NX user leaf and PMM ownership
            // checked before writing to the HHDM alias; no guest threads.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dest, 8) };
            if crate::user_file_io_smoke::tell(pid, token) != Ok(8) {
                fail("vfs_read_cursor_incorrect")
            }
            serial::write_line("WOLFOS_FILE_READ_OK cpl3=1 bytes=8 copied_to_bss=1 cursor=8");
            count as u64
        }
        2 => {
            if user_pointer(expected_rsi, 8, true).is_ok()
                || crate::user_file_io_smoke::tell(pid, token) != Ok(8)
            { fail("writable_executable_text_or_cursor_corruption") }
            serial::write_line("WOLFOS_FILE_EFAULT_RX_OK denied_write_to_user_code=1 cursor_unchanged=1");
            EFAULT
        }
        3 => {
            if crate::user_file_io_smoke::close(pid, token).is_err() {
                fail("vfs_close_failed")
            }
            FILE_FD.store(0, Ordering::Release);
            serial::write_line("WOLFOS_FILE_CLOSE_OK pid=1 descriptor_released=1");
            0
        }
        _ => {
            if user_pointer(expected_rdi, 13, false).is_ok() {
                fail("kernel_half_user_pointer_accepted")
            }
            serial::write_line("WOLFOS_FILE_EFAULT_KERNEL_OK denied_kernel_pointer=1");
            EFAULT
        }
    };
    frame.registers.rax = result;
    STAGE.store(stage + 1, Ordering::Release);
    raw
}
