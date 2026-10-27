//! First *independently assembled and linked* static ET_EXEC ELF64 executed
//! in actual hardware CPL3 under a separate supervisor-protected CR3.
//!
//! The guest lives in user/hello.S + user/hello.ld, built by GNU as/ld into
//! a genuine ELF file by build.rs. The kernel consumes that binary ONLY via
//! strict existing elf64_preflight::preflight + elf64_page_image::materialize:
//! user text RX (optionally including read-only fixture/BSS), and a separate
//! RW/NX user stack. Multi-LOAD flavors retain their RW/NX ELF data page.
//! Two ordinary INT80 syscalls, 19 user-console PUTC syscalls, and EXIT(0)
//! are verified by saved GPRs, user RIP and real TSS.RSP0 stack bounds.
//! Upon exit, the BSP MUST restore boot CR3 and release every allocated
//! user/PML4/page-table frame without leaks before emitting success.
//!
//! This feature is single-BSP, IF=0, a fixed TEST ELF compiled with native
//! GNU binutils, NOT yet a general process or an untrusted executable loader.
//! Kernel high-half descendant page tables remain borrowed from Limine.

use core::arch::asm;
use core::cell::UnsafeCell;
#[cfg(any(feature = "user-invalid-opcode-retire-smoke", feature = "user-page-fault-retire-smoke"))]
use x86_64::structures::idt::InterruptStackFrame;
#[cfg(feature = "user-page-fault-retire-smoke")]
use x86_64::{registers::control::Cr2, structures::idt::PageFaultErrorCode};
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU64, AtomicUsize, Ordering};
use x86_64::{
    instructions::segmentation::{CS, Segment},
    registers::control::{Cr3, Cr4, Cr4Flags},
    VirtAddr,
};
use crate::{
    elf64_page_image::PAGE_SIZE,
    user_elf_launch_layout::plan_bounded_with_budget,
    user_elf_page_tables::TableBuffers,
    interrupts, kernel_half_shadow, pmm, serial,
    process_lifecycle::ProcessState,
    tlb_shootdown::ShootdownBarrier,
    process_table::{ProcessTableCell, TableError},
    user_ring_entry::{self, Ring3Entry},
    user_syscall_abi::{self, Outcome, UserSyscallFrame},
};
#[cfg(feature = "user-elf-two-pt-run-smoke")]
use crate::{user_vm_two_pt, user_image_admission::{self, BackingPage}};

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
const SLOTS: usize = 512;
const ONE_LOAD: bool = cfg!(feature = "user-elf-one-load-run-smoke");
const FRAMES: usize = if ONE_LOAD { 6 }
    else if cfg!(feature = "user-elf-three-load-run-smoke") { 9 }
    else if cfg!(feature = "user-elf-two-pt-run-smoke") { 8 } else { 7 };
/// Maximum resident record capacity, independent of the exact ELF-derived
/// 6/7/8/9-frame lease. Unused slots in a record must remain zero.
const PROCESS_FRAME_CAPACITY: usize = 9;
const TABLE_FRAMES: usize = if cfg!(feature = "user-elf-two-pt-run-smoke") { 5 } else { 4 };
const LOAD_LEAVES: usize = if ONE_LOAD { 1 }
    else if cfg!(feature = "user-elf-three-load-run-smoke") { 3 } else { 2 };
const DATA_VA: u64 = if cfg!(feature = "user-elf-two-pt-run-smoke") { 0x600000 } else { 0x403000 };
const STACK_VA: u64 = if ONE_LOAD { 0x402000 } else { DATA_VA + PAGE };
const RETURN_COUNT: usize = if cfg!(feature = "user-file-io-smoke") { 13 }
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
/// PID metadata mirrors the canonical LiveElf frame owner; it never frees
/// physical frames. Slots can be reused while PID generations increase.
static PROCESS_TABLE: ProcessTableCell<2, PROCESS_FRAME_CAPACITY> = ProcessTableCell::new();
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

/// This fixed IF=0 path is entered only by the BSP. APs never receive its
/// private root, and there is no scheduler, saved resumable context or DMA.
/// The provider borrow remains pinned in the active owner until reclamation.
struct PmmSource;
impl crate::pmm_frame_batch::FrameSource for PmmSource {
    fn allocate(&mut self) -> Option<u64> {
        pmm::allocate_frame()
    }
    fn release(&mut self, frame: u64) -> bool {
        pmm::free_frame(frame).is_ok()
    }
}
struct SourceCell(UnsafeCell<PmmSource>);
// SAFETY: SOURCE_BUSY forbids a second provider borrow until its prior owner
// is consumed, and only the BSP's non-reentrant IF=0 path uses this source.
unsafe impl Sync for SourceCell {}
static SOURCE: SourceCell = SourceCell(UnsafeCell::new(PmmSource));
static SOURCE_BUSY: AtomicBool = AtomicBool::new(false);
type ActiveElf =
    crate::active_address_space::ActiveAddressSpace<'static, PmmSource, PROCESS_FRAME_CAPACITY, 1>;
struct LiveElf {
    owner: ActiveElf,
    ticket: crate::address_space_retirement::Ticket,
}
struct OwnerCell(UnsafeCell<Option<LiveElf>>);
// SAFETY: only this BSP IF=0 launch/terminal-exit path accesses the slot.
// No reference escapes a slot access; retirement takes the owner permanently.
unsafe impl Sync for OwnerCell {}
static LIVE_ELF: OwnerCell = OwnerCell(UnsafeCell::new(None));

// Fallible ELF preparation has deeper stack use than a terminal trap. Never
// recursively prepare PID2 on the fixed 16-KiB TSS.RSP0 exception stack.
// The previous trap and all its return paths are terminal before this switch.
#[cfg(feature = "user-process-smoke")]
const RELAUNCH_STACK_BYTES: usize = 64 * 1024;
#[cfg(feature = "user-process-smoke")]
const RELAUNCH_CANARY: u64 = 0x574f_4c46_4c41_554e;
#[cfg(feature = "user-process-smoke")]
#[repr(C, align(16))]
struct RelaunchStack([u8; RELAUNCH_STACK_BYTES]);
#[cfg(feature = "user-process-smoke")]
static mut RELAUNCH_STACK: RelaunchStack = RelaunchStack([0; RELAUNCH_STACK_BYTES]);

#[cfg(feature = "user-process-smoke")]
fn relaunch_after_reap(hhdm: u64) -> ! {
    require_serial_bsp();
    if SOURCE_BUSY.load(Ordering::Acquire) || unsafe { (&*LIVE_ELF.0.get()).is_some() } {
        fail("relaunch_before_owner_retired")
    }
    let base = (&raw mut RELAUNCH_STACK).cast::<u8>() as u64;
    // SAFETY: BSP-only, no prior preparation on this stack is resumable.
    // All PID1 frames and return references have been retired. A fresh CALL
    // supplies the SysV entry alignment; this handoff can never return.
    unsafe {
        (base as *mut u64).write(RELAUNCH_CANARY);
        (base as *mut u64).add(1).write(!RELAUNCH_CANARY);
        asm!("mov rsp, {top}", "xor rbp, rbp", "call {launch}", "ud2",
            top = in(reg) base + RELAUNCH_STACK_BYTES as u64,
            launch = sym enter, in("rdi") hhdm, options(noreturn));
    }
}

fn require_serial_bsp() {
    let (apic_base, _high): (u32, u32);
    // SAFETY: x86-64 BSP/AP identity from IA32_APIC_BASE, never user data.
    unsafe {
        asm!("rdmsr", in("ecx") 0x1bu32, out("eax") apic_base,
            out("edx") _high, options(nostack, preserves_flags));
    }
    if x86_64::instructions::interrupts::are_enabled()
        || Cr4::read().contains(Cr4Flags::PCID)
        || apic_base & (1 << 8) == 0
    {
        fail("owner_requires_if_zero_and_no_pcid")
    }
}

fn verify_preparation_stacks(index: usize) {
    let valid = if index == 0 {
        // First publication keeps the strict initial SS selector admission.
        interrupts::verify_ring3_preconditions()
    } else {
        #[cfg(feature = "user-process-smoke")]
        {
            let base = (&raw const RELAUNCH_STACK).cast::<u64>();
            let rsp: u64;
            // SAFETY: reads this BSP's current preparation-stack pointer.
            unsafe {
                asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
            }
            interrupts::verify_ring3_reentry_preconditions()
                && unsafe {
                    base.read() == RELAUNCH_CANARY && base.add(1).read() == !RELAUNCH_CANARY
                }
                && rsp > base as u64 + 16
                && rsp < base as u64 + RELAUNCH_STACK_BYTES as u64
        }
        #[cfg(not(feature = "user-process-smoke"))]
        {
            false
        }
    };
    if !valid {
        fail("preparation_rsp0_or_relaunch_stack")
    }
}

/// Exercise failure and explicit rollback with actual disconnected PMM pages,
/// before admitting any PID. The normal launch then uses a fresh transaction.
#[inline(never)]
fn probe_launch_rollback(elf: &[u8], slot: usize, hhdm: u64, before: usize) {
    let mut source = PmmSource;
    let tx = crate::elf_launch_transaction::ElfLaunch::<
        _,
        PROCESS_FRAME_CAPACITY,
        crate::elf_launch_transaction::Reserved,
    >::reserve(&mut source, elf, slot)
    .unwrap_or_else(|_| fail("rollback_probe_reserve"));
    let mut ptrs = [core::ptr::null_mut::<u8>(); FRAMES];
    if tx.leased_frames().len() != FRAMES {
        fail("rollback_probe_budget")
    }
    for (i, frame) in tx.leased_frames().iter().copied().enumerate() {
        ptrs[i] = hhdm_ptr(hhdm, frame).unwrap_or_else(|| fail("rollback_probe_hhdm"));
        // SAFETY: exact freshly leased PMM frames, never published or aliased.
        unsafe {
            core::ptr::write_bytes(ptrs[i], 0, PAGE_SIZE);
        }
    }
    let tx = unsafe {
        let mut loads: [crate::user_elf_page_tables::OwnedLeafPage<'_>; LOAD_LEAVES] =
            core::array::from_fn(|i| crate::user_elf_page_tables::OwnedLeafPage {
                physical_frame: tx.leased_frames()[TABLE_FRAMES + i],
                bytes: &mut *ptrs[TABLE_FRAMES + i].cast::<[u8; PAGE_SIZE]>(),
            });
        let mut stack = crate::user_elf_page_tables::OwnedLeafPage {
            physical_frame: tx.leased_frames()[FRAMES - 1],
            bytes: &mut *ptrs[FRAMES - 1].cast::<[u8; PAGE_SIZE]>(),
        };
        loads[LOAD_LEAVES - 1].physical_frame = tx.leased_frames()[0];
        let tx = match tx.stage_payload(&mut loads, &mut stack) {
            Err((tx, crate::user_elf_page_tables::StageError::BackingFrameMismatch { index }))
                if index == LOAD_LEAVES - 1 =>
            {
                tx
            }
            _ => fail("rollback_probe_not_rejected"),
        };
        if ptrs
            .iter()
            .any(|ptr| (&*ptr.cast::<[u8; PAGE_SIZE]>()).iter().any(|b| *b != 0))
            || pmm::statistics().allocated_frames != before + FRAMES
            || !matches!(PROCESS_TABLE.with(|t| t.occupied()), Ok(0))
        {
            fail("rollback_probe_changed_backings_or_pid")
        }
        tx
    };
    // All physical-buffer views ended. No root, PID or return context was
    // published; explicit rollback must release exactly the derived prefix.
    let report = tx.abort();
    if report.released != FRAMES
        || report.failed != 0
        || pmm::statistics().allocated_frames != before
    {
        fail("rollback_probe_release")
    }
    serial::write_fmt(format_args!(
        "WOLFOS_ELF_TX_ROLLBACK_OK frames={} rejected=1 bytes_unchanged=1 pid_unpublished=1 pmm_no_leak=1\n",
        FRAMES,
    ));
}

pub extern "C" fn enter(hhdm: u64) -> ! {
    require_serial_bsp();
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
        && symbols::FILE_BAD_OPEN < symbols::FILE_PRIVATE_DENIED_OPEN
        && symbols::FILE_PRIVATE_DENIED_OPEN < symbols::FILE_OPEN
        && symbols::FILE_OPEN < symbols::FILE_BAD_READ
        && symbols::FILE_BAD_READ < symbols::FILE_READ
        && symbols::FILE_READ < symbols::FILE_POLICY_REVOKED_READ
        && symbols::FILE_POLICY_REVOKED_READ < symbols::FILE_WRONG_SCOPE_READ
        && symbols::FILE_WRONG_SCOPE_READ < symbols::FILE_EOF
        && symbols::FILE_EOF < symbols::FILE_CLOSE
        && symbols::FILE_CLOSE < symbols::FILE_STALE_CLOSE
        && symbols::FILE_STALE_CLOSE <= symbols::AFTER_PUTC
        && symbols::FILE_PATH >= symbols::HELLO_END
        && symbols::FILE_PATH_END - symbols::FILE_PATH == 12
        && symbols::PRIVATE_FILE_PATH >= symbols::FILE_PATH_END
        && symbols::PRIVATE_FILE_PATH_END - symbols::PRIVATE_FILE_PATH == 16
        && symbols::PRIVATE_FILE_PATH_END < 0x402000)
    { fail("independent_file_io_symbols") }
    #[cfg(feature = "user-copy-smoke")]
    if symbols::AFTER_WRITE <= symbols::AFTER_ADD
        || symbols::AFTER_WRITE >= symbols::AFTER_EXIT {
        fail("linked_user_write_return_address")
    }
    #[cfg(feature = "user-elf-three-load-run-smoke")]
    if symbols::SECOND_RX_PROBE != 0x402000 {
        fail("second_rx_independent_linker_symbol")
    }
    if symbols::ENTRY != 0x401000 || symbols::AFTER_ID <= symbols::ENTRY
        || symbols::AFTER_ADD <= symbols::AFTER_ID
        || symbols::AFTER_PUTC <= symbols::AFTER_ADD
        || symbols::AFTER_EXIT <= symbols::AFTER_PUTC
        || symbols::HELLO_TEXT <= symbols::AFTER_EXIT
        || symbols::HELLO_END != symbols::HELLO_TEXT + HELLO.len() as u64
        || (if ONE_LOAD {
            symbols::FIXTURE_MAGIC < symbols::HELLO_END
                || symbols::FIXTURE_MAGIC >= STACK_VA
                || symbols::BSS_START != symbols::FIXTURE_MAGIC + 1
                || symbols::BSS_START + 64 > STACK_VA
        } else {
            symbols::FIXTURE_MAGIC != DATA_VA
                || symbols::BSS_START != DATA_VA + 1
        })
        || elf.len() >= 32768
    { fail("unexpected_independent_elf_symbols") }

    // Unlike the old syscall proof, executable bytes are NEVER hardcoded in
    // the kernel's source or directly copied from a handbuilt instruction
    // array. They must pass the strict ELF64 ET_EXEC parser and PT_LOAD
    // data/BSS materialization path developed in PRs #62-#65.
    let Ok(prepared) = plan_bounded_with_budget(elf)
    else { fail("elf_launch_layout") };
    let launch = prepared.layout;
    // The source ELF determines the physical lease requirement. Each tested
    // ELF is still fixed-flavor by hardware preflight, but its resulting count
    // can be less than the process-record capacity without padding ownership.
    if !prepared.frames.matches_exact_lease(TABLE_FRAMES, FRAMES)
        || prepared.frames.total_frames > PROCESS_FRAME_CAPACITY
        || prepared.frames.load_frames != LOAD_LEAVES
        || prepared.frames.leaf_frames != launch.len
        || prepared.frames.stack_frames != 1
    { fail("elf_prelease_frame_budget") }
    let plan = launch.image;
    let right_elf_leaf_owners = if ONE_LOAD {
        launch.leaves[0].and_then(|page| page.source_segment) == Some(0)
            && launch.leaves[1].and_then(|page| page.source_segment).is_none()
    } else if cfg!(feature = "user-elf-three-load-run-smoke") {
        launch.leaves[0].and_then(|page| page.source_segment) == Some(0)
            && launch.leaves[1].and_then(|page| page.source_segment) == Some(0)
            && launch.leaves[2].and_then(|page| page.source_segment) == Some(1)
            && launch.leaves[3].and_then(|page| page.source_segment).is_none()
    } else {
        launch.leaves[0].and_then(|page| page.source_segment) == Some(0)
            && launch.leaves[1].and_then(|page| page.source_segment) == Some(1)
            && launch.leaves[2].and_then(|page| page.source_segment).is_none()
    };
    if plan.len != (if ONE_LOAD { 1 } else { 2 }) || plan.entry != symbols::ENTRY
        || launch.load_pages() != LOAD_LEAVES || launch.stack_page != STACK_VA
        || !right_elf_leaf_owners
    { fail("elf_entry_or_segments") }
    let Some(text) = plan.segments[0] else { fail("elf_missing_rx_load") };
    if text.page_start != 0x401000
        || text.page_end != (if cfg!(feature = "user-elf-three-load-run-smoke") {
            0x403000
        } else { 0x402000 })
        || text.virtual_address != 0x401000
        || text.writable || !text.executable
        || text.file_size < symbols::HELLO_END - text.virtual_address
        || symbols::AFTER_EXIT >= symbols::HELLO_TEXT
    { fail("elf_rx_permissions_or_layout") }
    if ONE_LOAD {
        // Independently linked RX PT_LOAD contains genuine file bytes and a
        // zero-filled BSS tail. Writable memory is the separate NX stack.
        if text.file_size < symbols::FIXTURE_MAGIC + 1 - text.virtual_address
            || text.memory_size < symbols::BSS_START + 64 - text.virtual_address
            || text.memory_size <= text.file_size
            || plan.segments[1].is_some()
        { fail("one_load_rx_bss_layout") }
    } else {
        let Some(data) = plan.segments[1] else { fail("elf_missing_rw_load") };
        if text.memory_size != text.file_size
            || data.page_start != DATA_VA || data.page_end != STACK_VA
            || data.virtual_address != DATA_VA
            || !data.writable || data.executable
            || data.file_size != 1 || data.memory_size != 65
        { fail("elf_rw_permissions_or_layout") }
    }
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
        let private_offset = usize::try_from(
            symbols::PRIVATE_FILE_PATH - text.virtual_address
        ).unwrap_or(usize::MAX);
        let private_from_file = usize::try_from(text.file_offset).ok()
            .and_then(|begin| begin.checked_add(private_offset))
            .and_then(|start| elf.get(start..start + 16));
        if private_from_file != Some(&b"/tmp/private.txt"[..]) {
            fail("independently_linked_private_file_path")
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
    let stack_va = base + launch.stack_page;
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
    if SOURCE_BUSY.load(Ordering::Acquire)
        || unsafe { (&*LIVE_ELF.0.get()).is_some() }
    { fail("live_owner_or_source_already_present") }
    probe_launch_rollback(elf, slot, hhdm, before);
    verify_preparation_stacks(index);
    if SOURCE_BUSY.swap(true, Ordering::AcqRel) { fail("source_reentry") }
    // SAFETY: exclusive provider borrow spans this staged/active owner only.
    // It is not borrowed again until successful terminal reclamation.
    let source_owner = unsafe { &mut *SOURCE.0.get() };
    let tx = crate::elf_launch_transaction::ElfLaunch::<_, PROCESS_FRAME_CAPACITY,
        crate::elf_launch_transaction::Reserved>::reserve(source_owner, elf, slot)
        .unwrap_or_else(|_| fail("counted_launch_reserve"));
    let mut frames = [0; PROCESS_FRAME_CAPACITY];
    frames[..tx.leased_frames().len()].copy_from_slice(tx.leased_frames());
    if frames[prepared.frames.total_frames..].iter().any(|frame| *frame != 0) {
        fail("pmm_owned_tail_not_zero")
    }
    let mut ptrs = [core::ptr::null_mut::<u8>(); FRAMES];
    for (i, phys) in frames[..prepared.frames.total_frames].iter().copied().enumerate() {
        let Some(ptr) = hhdm_ptr(hhdm, phys) else { fail("owned_frame_hhdm") };
        ptrs[i] = ptr;
    }
    if tx.recipe().launch() != &prepared || tx.recipe().entry() != code
        || tx.recipe().stack_page() != stack_va
    { fail("elf_table_plan_disagrees") }

    // SAFETY: all frames fresh and disjoint. No CR3 points to the new root
    // until AFTER segment copying and full source/destination root audit.
    unsafe {
        for ptr in ptrs { core::ptr::write_bytes(ptr, 0, PAGE as usize); }
        // Independent two-PT admission still rederives its page manifest;
        // payload copying for EVERY layout uses the sealed common recipe.
        #[cfg(feature = "user-elf-two-pt-run-smoke")]
        let table_frames = [frames[0], frames[1], frames[2], frames[3], frames[4]];
        #[cfg(feature = "user-elf-two-pt-run-smoke")]
        let manifest = user_vm_two_pt::derive_relocated_elf_pages(
            elf, slot, table_frames, &frames[TABLE_FRAMES..FRAMES],
        ).unwrap_or_else(|_| fail("two_pt_independent_manifest"));
        let (tx, copied) = {
            #[allow(unused_mut)]
            let mut tx = tx;
            let mut destinations:
                [crate::user_elf_page_tables::OwnedLeafPage<'_>; LOAD_LEAVES] =
                core::array::from_fn(|i| crate::user_elf_page_tables::OwnedLeafPage {
                    physical_frame: frames[TABLE_FRAMES + i],
                    bytes: &mut *ptrs[TABLE_FRAMES + i].cast::<[u8; PAGE_SIZE]>(),
                });
            let mut stack = crate::user_elf_page_tables::OwnedLeafPage {
                physical_frame: frames[FRAMES - 1],
                bytes: &mut *ptrs[FRAMES - 1].cast::<[u8; PAGE_SIZE]>(),
            };
            #[cfg(feature = "user-elf-two-pt-run-smoke")]
            {
                // Real disconnected PMM/HHDM buffers: reject a late claimed
                // LOAD/root alias before any payload or PTE can be changed.
                // The private root is NOT active and no frame is released.
                let last = LOAD_LEAVES - 1;
                destinations[last].physical_frame = frames[0];
                tx = match tx.stage_payload(&mut destinations, &mut stack) {
                    Err((tx, crate::user_elf_page_tables::StageError::BackingFrameMismatch { index }))
                        if index == last => tx,
                    _ => fail("two_pt_transaction_probe_not_refused"),
                };
                destinations[last].physical_frame = frames[TABLE_FRAMES + last];
                if destinations.iter().any(|page| page.bytes.iter().any(|b| *b != 0))
                    || stack.bytes.iter().any(|b| *b != 0)
                    || ptrs[..TABLE_FRAMES].iter().any(|ptr|
                        (&*ptr.cast::<[u64; SLOTS]>()).iter().any(|entry| *entry != 0))
                    || pmm::statistics().allocated_frames != before + prepared.frames.total_frames
                { fail("two_pt_rejected_stage_mutated_memory_or_ownership") }
                serial::write_line(
                    "WOLFOS_ELF_TWO_PT_STAGE_REJECT_OK wrong_last_frame=1 tables_unchanged=1 loads_unchanged=1 stack_unchanged=1 pmm_unchanged=1",
                );
            }
            tx.stage_payload(&mut destinations, &mut stack)
                .unwrap_or_else(|_| fail("common_bound_elf_payload_stage"))
        };
        let Some(t) = copied[0] else { fail("no_text_page") };
        let text_page = &*ptrs[TABLE_FRAMES].cast::<[u8; PAGE_SIZE]>();
        if !t.executable || t.writable
            || t.copied != (text.file_size as usize).min(PAGE_SIZE)
        { fail("elf_rx_leaf_incorrect") }
        if ONE_LOAD {
            let fixture = usize::try_from(symbols::FIXTURE_MAGIC - text.page_start)
                .unwrap_or(usize::MAX);
            let bss = usize::try_from(symbols::BSS_START - text.page_start)
                .unwrap_or(usize::MAX);
            if text_page.get(fixture) != Some(&0x5a)
                || text_page.get(bss..bss.saturating_add(64))
                    != Some(&[0u8; 64][..])
            { fail("one_load_rx_fixture_or_bss") }
        } else {
            let Some(d) = copied[LOAD_LEAVES - 1] else { fail("no_data_page") };
            let data_page = &*ptrs[TABLE_FRAMES + LOAD_LEAVES - 1]
                .cast::<[u8; PAGE_SIZE]>();
            if d.executable || !d.writable || d.copied != 1
                || data_page[0] != 0x5a
                || data_page[1..65].iter().any(|b| *b != 0)
            { fail("elf_rw_data_or_bss_incorrect") }
        }
        #[cfg(feature = "user-elf-three-load-run-smoke")]
        {
            let Some(second) = copied[1] else { fail("missing_second_elf_rx_page") };
            let second_page = &*ptrs[TABLE_FRAMES + 1].cast::<[u8; PAGE_SIZE]>();
            // Real guest CALL crosses from the first RX leaf into these
            // independently materialized opcode bytes; RET reaches its CMP.
            if !second.executable || second.writable
                || second.copied != text.file_size as usize - PAGE_SIZE
                || second_page[0..6] != [0xb8, 0x4f, 0x43, 0x45, 0x53, 0xc3]
                || text_page[0] != 0xe8
            { fail("second_rx_materialized_code") }
        }
        #[cfg(not(feature = "user-elf-three-load-run-smoke"))]
        if text_page[0..2] != [0xb8, 0x01] { fail("first_rx_code") }
        let root = &mut *ptrs[0].cast::<[u64; SLOTS]>();
        let pdpt = &mut *ptrs[1].cast::<[u64; SLOTS]>();
        let pd = &mut *ptrs[2].cast::<[u64; SLOTS]>();
        let tx = {
            let mut tables = TableBuffers {
                pml4: &mut *root, pdpt: &mut *pdpt, pd: &mut *pd,
                pt0: &mut *ptrs[3].cast::<[u64; SLOTS]>(),
                pt1: if tx.recipe().launch().frames.table_frames == 5 {
                    Some(&mut *ptrs[4].cast::<[u64; SLOTS]>())
                } else { None },
            };
            tx.build_tables(&mut tables)
                .unwrap_or_else(|_| fail("elf_derived_table_population_or_audit"))
        };
        // Independent final read-only admission covers every LOAD byte,
        // BSS/padding byte and the entire separate stack for ALL layouts.
        let requests = core::array::from_fn(|i| {
            let leaf = launch.leaves[i].unwrap_or_else(|| fail("final_missing_leaf"));
            let segment = leaf.source_segment.unwrap_or_else(|| fail("final_missing_segment"));
            (plan.segments[segment].as_ref().unwrap_or_else(|| fail("final_missing_load")),
             leaf.virtual_address)
        });
        let backings: [&[u8; PAGE_SIZE]; LOAD_LEAVES] = core::array::from_fn(|i|
            &*ptrs[TABLE_FRAMES + i].cast::<[u8; PAGE_SIZE]>());
        if crate::elf64_page_image::audit_materialized_batch(elf, requests, backings).is_err()
            || crate::elf64_page_image::audit_zeroed_stack(
                &*ptrs[FRAMES - 1].cast::<[u8; PAGE_SIZE]>()).is_err()
        { fail("final_complete_payload_or_stack_audit") }
        #[cfg(feature = "user-elf-two-pt-run-smoke")]
        {
            let pt0 = &mut *ptrs[3].cast::<[u64; SLOTS]>();
            let pt1 = &mut *ptrs[4].cast::<[u64; SLOTS]>();
            let pages = manifest.pages();
            if manifest.layout.source != launch || manifest.load_pages() != LOAD_LEAVES
                || manifest.layout.entry != code || pages.len() != LOAD_LEAVES + 1
            { fail("two_pt_manifest_elf_mismatch") }
            let file_backings: [BackingPage<'_>; LOAD_LEAVES] =
                core::array::from_fn(|i| BackingPage {
                    virtual_address: pages[i].virtual_address,
                    physical_frame: pages[i].physical_frame,
                    bytes: &*ptrs[TABLE_FRAMES + i].cast::<[u8; PAGE_SIZE]>(),
                });
            let stack_backing = BackingPage {
                virtual_address: pages[LOAD_LEAVES].virtual_address,
                physical_frame: pages[LOAD_LEAVES].physical_frame,
                bytes: &*ptrs[FRAMES - 1].cast::<[u8; PAGE_SIZE]>(),
            };
            let Ok(admitted) = user_image_admission::audit_relocated_two_pt_staged_image(
                elf, slot, table_frames, pages,
                root, pdpt, pd, pt0, pt1, &file_backings, stack_backing,
            ) else { fail("two_pt_exact_elf_and_frame_admission") };
            if admitted.entry != code || admitted.stack_page != stack_va
                || admitted.source != launch
                || user_image_admission::audit_hhdm_backings(
                    hhdm, &file_backings, stack_backing,
                ).is_err()
            { fail("two_pt_entry_or_hhdm_provenance") }
            // Both 2-MiB regions MUST be reached via separate actual PTs.
            if pd.iter().filter(|entry| **entry != 0).count() != 2
                || pt0.iter().filter(|entry| **entry != 0).count()
                    != LOAD_LEAVES - 1
                || pt1.iter().filter(|entry| **entry != 0).count() != 2
                || pdpt.iter().filter(|entry| **entry != 0).count() != 1
            { fail("two_pt_cardinality") }
        }
        let entry = frames[1] | PRESENT | WRITE | USER;
        if root[slot] == 0 { root[slot] = entry; }
        if root[slot] != entry { fail("incorrect_user_pml4_entry") }
        let inherited = kernel_half_shadow::graft_kernel_half(
            source, root, slot, entry, &frames[..FRAMES]
        );
        if !matches!(inherited, Ok(count) if count >= 1)
            || kernel_half_shadow::audit_kernel_half(
                source, root, slot, entry, &frames[..FRAMES]
            ) != inherited
            || root[256..].iter().any(|e| e & USER != 0)
            || root[..256].iter().filter(|e| **e != 0).count() != 1
        { fail("sanitized_root_or_permissions") }

        BOOT_CR3.store(boot_cr3, Ordering::Release);
        ALLOCATED_BEFORE.store(before, Ordering::Release);
        ENTRY.store(code, Ordering::Release);
        STACK_TOP.store(user_top, Ordering::Release);
        let data_ptr = if ONE_LOAD {
            // This byte is in the materialized RX LOAD page; never grant write.
            (ptrs[TABLE_FRAMES] as u64)
                .checked_add(symbols::FIXTURE_MAGIC - text.page_start)
                .unwrap_or_else(|| fail("one_load_fixture_hhdm"))
        } else {
            ptrs[TABLE_FRAMES + LOAD_LEAVES - 1] as u64
        };
        DATA_HHDM.store(data_ptr, Ordering::Release);
        CR3_PHYS.store(frames[0], Ordering::Release);
        STAGE.store(0, Ordering::Release);
        #[cfg(feature = "user-file-io-smoke")]
        FILE_FD.store(0, Ordering::Release);
        for (at, phys) in frames[..FRAMES].iter().copied().enumerate() {
            OWNED[at].store(phys, Ordering::Release);
        }
        if !matches!(PROCESS_TABLE.with(|t| t.reserve_counted(
            frames[0], frames, prepared.frames.total_frames,
        )), Ok(Ok(issued)) if issued == pid
        ) { fail("process_table_admission_or_pid_generation") }
        verify_preparation_stacks(index);
        #[cfg(feature = "user-process-smoke")]
        if index != 0 {
            serial::write_line("WOLFOS_ELF_RELAUNCH_STACK_OK pid=2 preparation_stack_kib=64 rsp0_stack_kib=16 canary=1 terminal_handoff=1");
        }
        // SAFETY: exact PMM/HHDM provenance, complete bytes/stack/PTE and
        // kernel graft audits above precede the FIRST exposure to a CPU.
        // All private leaves are non-global; PCID and interrupts are off.
        // Borrowed kernel tables remain pinned under Limine's boot root.
        let mut owner = match tx.publish::<1>(pid, boot_cr3) {
            Ok(owner) => owner,
            Err((tx, _)) => {
                // Revoke the unpublished READY registry before rollback.
                if !matches!(PROCESS_TABLE.with(|t| t.cancel_ready_counted(pid, boot_cr3)),
                    Ok(Ok(lease)) if lease.as_slice() == tx.leased_frames())
                { fail("publish_refusal_ready_rollback") }
                for frame in &OWNED { frame.store(0, Ordering::Release); }
                ENTRY.store(0, Ordering::Release);
                STACK_TOP.store(0, Ordering::Release);
                DATA_HHDM.store(0, Ordering::Release);
                CR3_PHYS.store(0, Ordering::Release);
                let report = tx.abort();
                if report.released != FRAMES || report.failed != 0
                    || pmm::statistics().allocated_frames != before
                { fail("publish_refusal_frame_rollback") }
                SOURCE_BUSY.store(false, Ordering::Release);
                fail("counted_launch_publish_refused")
            }
        };
        let ticket = owner.reserve_cpu(0).unwrap_or_else(|_| fail("launch_cpu_reservation"));
        *LIVE_ELF.0.get() = Some(LiveElf { owner, ticket });
        compiler_fence(Ordering::SeqCst);
        asm!("mov cr3, {}", in(reg) frames[0],
            options(nostack, preserves_flags));
        let (now, _) = Cr3::read();
        let actual = now.start_address().as_u64();
        let live = (&mut *LIVE_ELF.0.get()).as_mut().unwrap_or_else(|| fail("missing_active_owner"));
        if actual != frames[0] || live.owner.confirm_active(live.ticket, actual).is_err()
            || !live.owner.matches_process_lease_counted(pid, actual, &frames[..FRAMES])
        { fail("new_cr3_not_active_or_owned") }
        serial::write_fmt(format_args!(
            "WOLFOS_ELF_TX_ACTIVE_OK pid={} frames={} transferred_before_cr3=1 cpu_reserved=1 actual_cr3=1 full_bytes=1 pcid_off=1 bsp_only=1\n",
            pid, FRAMES,
        ));
        if !matches!(PROCESS_TABLE.with(|t| t.mark_running(pid, frames[0])), Ok(Ok(()))) {
            fail("process_table_running_transition")
        }
        // Read the actual hardware CR3 above; this table check must reject
        // freeing a RUNNING user root or any of its own PMM frames.
        if !matches!(PROCESS_TABLE.with(|t| (
            t.snapshot(pid), t.occupied(), t.running(),
            t.reap_with_status_counted(pid, frames[0]),
        )), Ok((Some(record), 1, 1, Err(TableError::Process(
            crate::process_lifecycle::ProcessError::ActiveCr3
        )))) if record.state == ProcessState::Running
            && record.cr3_root == frames[0]
            && record.frame_count == prepared.frames.total_frames
            && record.owned_frames() == &frames[..FRAMES]
            && record.frames[FRAMES..].iter().all(|frame| *frame == 0)
        ) { fail("process_table_active_cr3_guard") }
        serial::write_fmt(format_args!(
            "WOLFOS_ELF_TABLE_PLAN_OK source=elf tables={} loads={} stack=1 total={} exact_audit=1\n",
            prepared.frames.table_frames, prepared.frames.load_frames,
            prepared.frames.total_frames,
        ));
        serial::write_fmt(format_args!(
            "WOLFOS_ELF_PAYLOAD_PLAN_OK source=recipe loads={} stack=1 total={}\n",
            prepared.frames.load_frames, prepared.frames.total_frames,
        ));
        #[cfg(feature = "user-process-smoke")]
        serial::write_fmt(format_args!(
            "WOLFOS_PROCESS_START pid={} state=running private_cr3=1 owned_frames=7\n",
            pid,
        ));
        serial::write_fmt(format_args!(
            "WOLFOS_ELF_RUN_ENTER elf64=1 et_exec=1 pt_load={} rx=1 rw_nx={} bss_zero=1 cr3_new=1 root_slot={} user_entry={:#x}\n",
            plan.len, if ONE_LOAD { 1 } else { 2 }, slot, plan.entry,
        ));
        if ONE_LOAD {
            serial::write_fmt(format_args!(
                "WOLFOS_ELF_ONE_LOAD_ENTER hardware_cr3=1 load_segments=1 rx_leaves=1 nx_stack=1 owned_frames=6 root_slot={}\n",
                slot,
            ));
        }
        #[cfg(all(feature = "user-elf-two-pt-run-smoke",
                  not(feature = "user-elf-three-load-run-smoke")))]
        serial::write_fmt(format_args!(
            "WOLFOS_ELF_TWO_PT_ENTER hardware_cr3=1 root_slot={} pd_regions=2 pt_frames=2 rx=1 rw_nx=2 elf_admitted=1 hhdm_checked=1 derived_pages=1 owned_frames=8\n",
            slot,
        ));
        #[cfg(feature = "user-elf-three-load-run-smoke")]
        serial::write_fmt(format_args!(
            "WOLFOS_ELF_THREE_LOAD_ENTER hardware_cr3=1 root_slot={} pd_regions=2 pt_frames=2 rx_leaves=2 data_nx=1 stack_nx=1 elf_admitted=1 derived_pages=1 owned_frames=9\n",
            slot,
        ));
        #[cfg(feature = "user-file-io-smoke")]
        crate::user_file_io_smoke::attest_running_image(pid, elf);
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
    require_serial_bsp();
    let mut live = unsafe { (&mut *LIVE_ELF.0.get()).take() }
        .unwrap_or_else(|| fail("retire_missing_active_owner"));
    let (actual, _) = Cr3::read();
    if actual.start_address().as_u64() != active
        || !matches!(PROCESS_TABLE.with(|t| t.snapshot(pid)), Ok(Some(record))
            if record.state == ProcessState::Exited
                && live.owner.matches_process_lease_counted(pid, active, record.owned_frames()))
        || live.owner.begin_retirement().is_err()
        || live.owner.finish_retirement() != Err(crate::address_space_retirement::Error::OutstandingCpus)
        || live.owner.acknowledge_quiescent(live.ticket, actual.start_address().as_u64())
            != Err(crate::address_space_retirement::Error::WrongCr3)
        || pmm::statistics().allocated_frames != ALLOCATED_BEFORE.load(Ordering::Acquire) + FRAMES
    { fail("retirement_must_pin_actual_active_cr3") }
    serial::write_fmt(format_args!(
        "WOLFOS_ELF_TX_RETIRE_BLOCKED_OK pid={} cpu_outstanding=1 active_ack_denied=1 frames_pinned=1\n", pid,
    ));
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
    if now.start_address().as_u64() != boot
        || live.owner.acknowledge_quiescent(live.ticket, now.start_address().as_u64()).is_err()
    { fail("boot_cr3_not_restored_or_acknowledged") }
    // The audited PID ledger authorizes release ONLY after CR3
    // restoration, only for this exact owning PID, exactly once.
    let owned_by_pid = match PROCESS_TABLE.with(|t| t.reap_with_status_counted(pid, boot)) {
        Ok(Ok((code, lease))) if code == exit_status && lease.count == FRAMES => lease,
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
    for i in (0..owned_by_pid.count).rev() {
        let owned = OWNED[i].swap(0, Ordering::AcqRel);
        if owned == 0 || owned != owned_by_pid.as_slice()[i]
            || live.owner.leased_frames().get(i) != Some(&owned)
        {
            fail("owned_user_frame_free_failed")
        }
    }
    ENTRY.store(0, Ordering::Release);
    STACK_TOP.store(0, Ordering::Release);
    DATA_HHDM.store(0, Ordering::Release);
    CR3_PHYS.store(0, Ordering::Release);
    if live.owner.leased_frames() != owned_by_pid.as_slice()
        || live.owner.context_snapshot().pending != 0
    { fail("retire_live_reference_or_lease_mismatch") }

    // Bind *real* terminal CPL3 retirement to the exact owner's historical
    // BSP CPU mask. This IF=0 process had one authenticated private CR3 user
    // and cannot be resumed: its PID, cached user pointers and IRET path
    // were revoked above. A mere prior CR3 switch is not a post-publication
    // TLB acknowledgment.
    let mut barrier = ShootdownBarrier::<1>::new(pid)
        .unwrap_or_else(|_| fail("retire_tlb_barrier_identity"));
    let round = live.owner.begin_retirement_shootdown(&mut barrier, 1)
        .unwrap_or_else(|_| fail("retire_tlb_owner_publication"));
    if barrier.completed(round)
        || barrier.snapshot().pending != 1
        || live.owner.finish_retirement()
            != Err(crate::address_space_retirement::Error::OutstandingShootdown)
        || pmm::statistics().allocated_frames
            != ALLOCATED_BEFORE.load(Ordering::Acquire) + FRAMES
    { fail("retire_tlb_pending_must_pin_all_frames") }

    let (supervisor_frame, flags) = Cr3::read();
    if supervisor_frame.start_address().as_u64() != boot {
        fail("retire_tlb_supervisor_root_mismatch")
    }
    // SAFETY: actual BSP only, IF=0, PCID=0; this resident trusted boot
    // frame is still active. All former private pages are non-global and
    // no AP, DMA device or future Ring3 dispatch can use this root.
    // Re-loading the boot root *after* publishing the shootdown round
    // invalidates the BSP's non-global private translations.
    unsafe { Cr3::write(supervisor_frame, flags); }
    compiler_fence(Ordering::SeqCst);
    if Cr3::read().0.start_address().as_u64() != boot
        // SAFETY: authenticated BSP just completed its post-publication
        // local CR3 reload for this exact opaque round and CPU index.
        || unsafe { barrier.acknowledge_after_local_flush(round, 0) }.is_err()
        || !barrier.completed(round)
        || live.owner.finish_retirement_after_shootdown(&barrier, round).is_err()
        || pmm::statistics().allocated_frames
            != ALLOCATED_BEFORE.load(Ordering::Acquire) + FRAMES
    { fail("retire_tlb_bsp_flush_or_close") }
    serial::write_fmt(format_args!(
        "WOLFOS_ELF_TX_TLB_OK pid={} cpus=1 real_cpl3=1 post_publish_cr3_reload=1 owner_round_complete=1 frames_pinned=1\\n",
        pid,
    ));
    // SAFETY: this authenticated BSP restored boot CR3 with PCID off,
    // completing local non-global invalidation. No AP ever received this root.
    // Terminal EXIT/#UD/#PF never IRET to the old TSS-stack trap frame; this
    // path has no saved scheduler contexts, queued resumes, walkers or DMA.
    // The PID record and user-copy/return caches are revoked above. All raw
    // staging HHDM views ended at the noreturn entry. Shared boot tables stay
    // resident and are excluded from the exact private lease.
    let report = unsafe { live.owner.reclaim() }
        .unwrap_or_else(|_| fail("retired_owner_reclaim_refused"));
    if report.released != FRAMES || report.failed != 0 {
        fail("retired_owner_release_report")
    }
    SOURCE_BUSY.store(false, Ordering::Release);
    serial::write_fmt(format_args!(
        "WOLFOS_ELF_TX_RECLAIM_OK pid={} frames={} actual_boot_cr3=1 cpu_drained=1 pid_revoked=1 returns_revoked=1 failed=0\n",
        pid, report.released,
    ));
    // The exact former PID must be absent, its slot free, and an attempted
    // second reap must fail. No other live table entry may remain.
    if !matches!(PROCESS_TABLE.with(|t| (
        t.snapshot(pid), t.occupied(), t.running(),
        t.reap_with_status_counted(pid, boot),
    )), Ok((None, 0, 0, Err(TableError::UnknownPid)))) {
        fail("process_table_stale_pid_or_double_reap")
    }
    if pmm::statistics().allocated_frames != ALLOCATED_BEFORE.load(Ordering::Acquire)
    { fail("pmm_frame_leak") }
    serial::write_fmt(format_args!(
        "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed={} pmm_no_leak=1\n",
        FRAMES,
    ));
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
        serial::write_line("WOLFOS_FILE_IO_RUN_OK linked_elf=1 hardware_cpl3=1 real_file_syscalls=3 int80_calls=14 exit=0 resources_released=1 persistent=0 production=0");
    } else if cfg!(feature = "user-copy-smoke") {
        serial::write_line("WOLFOS_USERCOPY_RUN_OK linked_elf=1 hardware_cpl3=1 real_user_pointer=1 int80_calls=4 exit=0 resources_released=1 production_user_copy=0");
    } else if ONE_LOAD {
        serial::write_line("WOLFOS_ELF_ONE_LOAD_RUN_OK linked_elf=1 hardware_cpl3=1 one_pt_load=1 rx_leaves=1 stack_rw_nx=1 int80_calls=22 exit=0 restored_cr3=1 frames_freed=6 pmm_no_leak=1");
    } else if cfg!(feature = "user-elf-three-load-run-smoke") {
        serial::write_line("WOLFOS_ELF_THREE_LOAD_RUN_OK linked_elf=1 hardware_cpl3=1 pt_frames=2 rx_leaves=2 second_rx_called=1 int80_calls=22 exit=0 restored_cr3=1 frames_freed=9 pmm_no_leak=1");
    } else if cfg!(feature = "user-elf-two-pt-run-smoke") {
        serial::write_line("WOLFOS_ELF_TWO_PT_RUN_OK linked_elf=1 hardware_cpl3=1 pt_frames=2 user_console=1 int80_calls=22 exit=0 restored_cr3=1 frames_freed=8 pmm_no_leak=1");
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
            relaunch_after_reap(HHDM_OFFSET.load(Ordering::Acquire));
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
    {
        serial::write_fmt(format_args!(
            "WOLFOS_ELF_TRAP_DIAGNOSTIC actual={:#x} expected={:#x} entry={:#x} cs={:#x} frame={:#x} rsp0={:#x}\n",
            root.start_address().as_u64(), active, user_entry, CS::get_reg().0, frame_addr, rsp0,
        ));
        fail("trap_cr3_rsp0_or_privilege")
    }
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
            4 => (symbols::FILE_PRIVATE_DENIED_OPEN, 6,
                  base + symbols::PRIVATE_FILE_PATH, 16, 0,
                  crate::user_file_io::EACCES as u64),
            5 => (symbols::FILE_OPEN, 6, base + symbols::FILE_PATH,
                  12, 0, 256),
            6 => (symbols::FILE_BAD_READ, 7, fd,
                  base + symbols::HELLO_TEXT, 8, crate::user_file_io::EFAULT as u64),
            7 => (symbols::FILE_READ, 7, fd, user_top - 32, 8, 8),
            8 => (symbols::FILE_POLICY_REVOKED_READ, 7, fd,
                  user_top - 32, 8, crate::user_file_io::EACCES as u64),
            9 => (symbols::FILE_WRONG_SCOPE_READ, 7, fd,
                  user_top - 32, 8, crate::user_file_io::EACCES as u64),
            10 => (symbols::FILE_EOF, 7, fd, user_top - 32, 8, 0),
            11 => (symbols::FILE_CLOSE, 8, fd, 0, 0, 0),
            12 => (symbols::FILE_STALE_CLOSE, 8, fd, 0, 0,
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
            || (stage >= 6 && frame.registers.r12 != fd)
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
            4 => crate::user_file_io_smoke::prove_private_open_denied(pid),
            5 => {
                FILE_FD.store(result, Ordering::Release);
                serial::write_line("WOLFOS_FILE_IO_OPEN_OK path_user_rx=1 fd=256");
            },
            6 => serial::write_line("WOLFOS_FILE_IO_BAD_READ_OK rx_write_denied=1 cursor_rollback=1"),
            7 => {
                let mut proof = [0u8;8];
                if crate::user_copy::copy_from(
                    active, user_top - 32, &mut proof, private_pte, private_byte
                ).is_err() || proof != *b"FILE_OK\n"
                { fail("user_stack_file_contents") }
                serial::write_line("WOLFOS_FILE_IO_READ_OK bytes=8 user_stack=1 payload=FILE_OK");
                crate::user_file_io_smoke::revoke_file_read(pid);
            },
            8 => {
                crate::user_file_io_smoke::prove_revoked_read(pid);
                crate::user_file_io_smoke::scope_private_file_read(pid);
            },
            9 => {
                crate::user_file_io_smoke::prove_wrong_scope_read(pid);
                crate::user_file_io_smoke::restore_file_read_scope(pid);
            },
            10 => serial::write_line("WOLFOS_FILE_IO_EOF_OK read=0"),
            11 => serial::write_line("WOLFOS_FILE_IO_CLOSE_OK released=1"),
            12 => serial::write_line("WOLFOS_FILE_IO_STALE_OK ebadf=1"),
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
                serial::write_line("WOLFOS_FILE_IO_EXIT_OK code=0 cpl3=1 calls=14");
            } else if cfg!(feature = "user-copy-smoke") {
                serial::write_line("WOLFOS_USERCOPY_EXIT_OK code=0 cpl3=1 calls=4");
            } else {
                serial::write_line("WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=22");
            }

            finish_exited(pid, exit_status, active)
        }
    }
}
