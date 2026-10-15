//! First ACTUAL x86-64 hardware CPL3 -> CPL0 -> CPL3 -> CPL0 proof.
//!
//! This isolated one-vCPU QEMU feature installs three newly PMM-owned
//! 4-KiB PTE leaves into an UNUSED lower-half PML4 slot of the BOOT CR3,
//! using a private PDPT, PD and PT. It copies a tiny immutable hand-encoded
//! x86-64 user payload: write nonce 0x11, INT 0x80, write nonce 0x22,
//! INT 0x80, UD2. The first x86-interrupt handler returns via IRETQ.
//! The second INT proves the CPU resumed execution as CPL3.
//!
//! This deliberately uses Limine's existing CR3 and does NOT provide
//! complete kernel isolation: inherited Limine high-half mappings have
//! not been sanitized; there are no processes, syscall ABI, userfault
//! recovery, ELF image entry, or per-process page-table roots. Do not run
//! untrusted code in this proof. Successful second trap exits the VM.

use core::arch::asm;
use core::sync::atomic::{compiler_fence, AtomicU64, AtomicUsize, Ordering};
use x86_64::{registers::control::Cr3, instructions::segmentation::{CS, Segment},
    structures::idt::InterruptStackFrame, VirtAddr};
use crate::{interrupts, pmm, serial, user_ring_entry::{self, Ring3Entry}};

const PAGE: u64 = 4096;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const USER: u64 = 4;
const NX: u64 = 1 << 63;
const ROOT_SLOTS: usize = 512;
const FRAMES: usize = 6; // PDPT, PD, PT, user RX, user RW+NX, user stack RW+NX
const LEAF_CODE: u64 = 0x401000;
const LEAF_DATA: u64 = 0x402000;
const LEAF_STACK: u64 = 0x403000;
const SEGMENT_OFFSET: u64 = 0x400000;
const FIRST_RETURN: u64 = 9;
const SECOND_RETURN: u64 = 18;
const STAGE_ONE: u8 = 0x11;
const STAGE_TWO: u8 = 0x22;

// Relative instruction displacements are from the END of the current
// 7-byte MOV [RIP+disp32],imm8 opcode. Both writes target DATA page byte 0.
// An INT instruction is two bytes and must be allowed to IRETQ back to CPL3.
const USER_TEXT: [u8; 20] = [
    0xc6, 0x05, 0xf9, 0x0f, 0x00, 0x00, STAGE_ONE,
    0xcd, 0x80,
    0xc6, 0x05, 0xf0, 0x0f, 0x00, 0x00, STAGE_TWO,
    0xcd, 0x80,
    0x0f, 0x0b, // UD2 only reachable if the second handler wrongly returns
];

static USER_BASE: AtomicU64 = AtomicU64::new(0);
static USER_STACK_TOP: AtomicU64 = AtomicU64::new(0);
static USER_DATA_HHDM: AtomicU64 = AtomicU64::new(0);
static TRAPS: AtomicUsize = AtomicUsize::new(0);

fn fail(reason: &str) -> ! {
    serial::write_fmt(format_args!("WOLFOS_RING3_ERROR {reason}\n"));
    crate::halt_forever()
}

fn physical_hhdm(hhdm: u64, phys: u64) -> Option<*mut u8> {
    VirtAddr::try_new(hhdm.checked_add(phys)?).ok()
        .map(|addr| addr.as_mut_ptr::<u8>())
}

fn prepared_frames() -> Option<[u64; FRAMES]> {
    let mut frames = [0u64; FRAMES];
    for at in 0..FRAMES {
        let Some(phys) = pmm::allocate_frame() else {
            for old in frames[..at].iter().copied().rev() {
                let _ = pmm::free_frame(old);
            }
            return None;
        };
        if phys == 0 || phys & (PAGE - 1) != 0
            || frames[..at].contains(&phys) || phys >= (1 << 52)
        {
            let _ = pmm::free_frame(phys);
            for old in frames[..at].iter().copied().rev() {
                let _ = pmm::free_frame(old);
            }
            return None;
        }
        frames[at] = phys;
    }
    Some(frames)
}

/// Returns only when setup validation fails; success transfers to ring 3.
/// Must be invoked exactly once on BSP with IF=0, AFTER GDT/TSS/IDT setup
/// and normal kernel boot checks, BEFORE enabling any SMP workload.
pub fn enter(hhdm: u64) -> ! {
    if !interrupts::verify_ring3_preconditions() {
        fail("gdt_tss_preflight");
    }
    let (user_cs, user_ss, rsp0) = interrupts::ring3_cpu_state();
    let (root_frame, _) = Cr3::read();
    let Some(root_ptr) = physical_hhdm(hhdm, root_frame.start_address().as_u64())
    else { fail("no_root_hhdm") };

    // Reserve an unused PML4 slot; never replace Limine boot mappings.
    // Skip zero and anything outside canonical lower-half user memory.
    let mut selected = 0usize;
    unsafe {
        let root = root_ptr.cast::<[u64; ROOT_SLOTS]>();
        for i in 1..256 {
            if (*root)[i] == 0 {
                selected = i;
                break;
            }
        }
    }
    if selected == 0 { fail("no_unused_user_pml4") }
    let base = ((selected as u64) << 39) + LEAF_CODE;
    let text = base;
    let data = ((selected as u64) << 39) + LEAF_DATA;
    let stack = ((selected as u64) << 39) + LEAF_STACK;
    let stack_top = stack + PAGE;
    if user_ring_entry::validate(Ring3Entry {
        rip: text, user_rsp: stack_top, kernel_rsp0: rsp0,
        user_cs, user_ss, rflags: 2,
    }).is_err() { fail("user_entry_contract") }

    // Require EFER.NXE active: otherwise NX PTE bits are reserved and any
    // guarantee about writable data/stack being nonexecutable is false.
    let (lo, _hi): (u32, u32);
    unsafe {
        asm!("rdmsr", in("ecx") 0xc000_0080u32,
            out("eax") lo, out("edx") _hi,
            options(nostack, preserves_flags));
    }
    if lo & (1 << 11) == 0 { fail("cpu_efer_nxe_disabled") }

    let Some(frames) = prepared_frames() else { fail("pmm_frames") };
    let mut ptrs = [core::ptr::null_mut::<u8>(); FRAMES];
    for (at, physical) in frames.iter().copied().enumerate() {
        let Some(ptr) = physical_hhdm(hhdm, physical) else { fail("bad_frame_hhdm") };
        ptrs[at] = ptr;
    }

    // SAFETY: all six frames are fresh disjoint PMM allocations, accessible
    // by Limine HHDM and owned exclusively by the serialized BSP. Nothing
    // points to the new page tables from active CR3 until final publication.
    unsafe {
        for ptr in ptrs { core::ptr::write_bytes(ptr, 0, PAGE as usize); }
        core::ptr::copy_nonoverlapping(
            USER_TEXT.as_ptr(), ptrs[3], USER_TEXT.len(),
        );
        let pdpt = &mut *ptrs[0].cast::<[u64; ROOT_SLOTS]>();
        let pd = &mut *ptrs[1].cast::<[u64; ROOT_SLOTS]>();
        let pt = &mut *ptrs[2].cast::<[u64; ROOT_SLOTS]>();
        let pdpt_idx = ((text >> 30) & 511) as usize;
        let pd_idx = ((text >> 21) & 511) as usize;
        let pt_idx = ((text >> 12) & 511) as usize;
        if pdpt_idx != 0 || pd_idx != 2 || pt_idx != 1 { fail("wrong_page_indices") }
        pdpt[pdpt_idx] = frames[1] | PRESENT | WRITE | USER;
        pd[pd_idx] = frames[2] | PRESENT | WRITE | USER;
        pt[pt_idx] = frames[3] | PRESENT | USER;
        pt[pt_idx + 1] = frames[4] | PRESENT | WRITE | USER | NX;
        pt[pt_idx + 2] = frames[5] | PRESENT | WRITE | USER | NX;
        if pt.iter().filter(|p| **p != 0).count() != 3
            || pd.iter().filter(|p| **p != 0).count() != 1
            || pdpt.iter().filter(|p| **p != 0).count() != 1
        { fail("dirty_page_tables") }

        USER_BASE.store(text, Ordering::Release);
        USER_STACK_TOP.store(stack_top, Ordering::Release);
        USER_DATA_HHDM.store(ptrs[4] as u64, Ordering::Release);
        TRAPS.store(0, Ordering::Release);
        let root = root_ptr.cast::<[u64; ROOT_SLOTS]>();
        if (*root)[selected] != 0 { fail("root_was_modified") }
        compiler_fence(Ordering::SeqCst);
        (*root)[selected] = frames[0] | PRESENT | WRITE | USER;
        asm!("invlpg [{}]", in(reg) text, options(nostack, preserves_flags));
        asm!("invlpg [{}]", in(reg) data, options(nostack, preserves_flags));
        asm!("invlpg [{}]", in(reg) stack, options(nostack, preserves_flags));

        serial::write_fmt(format_args!(
            "WOLFOS_RING3_ENTER root_slot={} user_pages=3 rx=1 rw_nx=2 rsp0=1 nxe=1 if=0\n",
            selected,
        ));

        // SAFETY: dedicated user IDT gate 0x80 DPL3, GDT selectors and
        // TSS.RSP0 have been verified. Code+data+stack are mapped U/S=1.
        // IF=0 and no AP runs in the single-vCPU smoke. Only hardcoded
        // user code can execute. INT0x80 transfers to a checked kernel
        // handler; first return is the CPU's real IRETQ to CPL3.
        asm!(
            "push {user_ss}",
            "push {user_rsp}",
            "push {rflags}",
            "push {user_cs}",
            "push {user_rip}",
            "iretq",
            user_ss = in(reg) u64::from(user_ss),
            user_rsp = in(reg) stack_top,
            rflags = in(reg) 2u64,
            user_cs = in(reg) u64::from(user_cs),
            user_rip = in(reg) text,
            options(noreturn),
        );
    }
}

/// The ONLY user-invocable gate in this flavor.
/// It executes at CPL0 using the TSS.RSP0 stack; first invocation must
/// return normally to CPL3. Only second invocation may exit the QEMU VM.
pub extern "x86-interrupt" fn interrupt_80(frame: InterruptStackFrame) {
    let base = USER_BASE.load(Ordering::Acquire);
    let top = USER_STACK_TOP.load(Ordering::Acquire);
    let data = USER_DATA_HHDM.load(Ordering::Acquire);
    let (user_cs, user_ss, rsp0) = interrupts::ring3_cpu_state();
    let mut kernel_rsp: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) kernel_rsp,
            options(nomem, nostack, preserves_flags));
    }
    // SAFETY: pointer addresses an exclusively owned PMM frame through
    // HHDM. Only the single BSP handles this interrupt, with IF=0.
    let current = if data != 0 {
        unsafe { (data as *const u8).read_volatile() }
    } else { 0 };
    let phase = TRAPS.load(Ordering::Acquire);
    let expected_rip = base + if phase == 0 { FIRST_RETURN } else { SECOND_RETURN };
    let expected_nonce = if phase == 0 { STAGE_ONE } else { STAGE_TWO };
    if base == 0 || data == 0
        || phase > 1 || current != expected_nonce
        || CS::get_reg().0 != 0x8
        || frame.code_segment.0 != user_cs
        || frame.stack_segment.0 != user_ss
        || frame.instruction_pointer.as_u64() != expected_rip
        || frame.stack_pointer.as_u64() != top
        || kernel_rsp < rsp0 - (16 * 1024) || kernel_rsp >= rsp0
    {
        serial::write_fmt(format_args!(
            "WOLFOS_RING3_ERROR bad_int80 phase={} data={:#x} cs={:#x} ss={:#x} rip={:?} rsp={:?} krsp={:#x} rsp0={:#x}\n",
            phase, current, frame.code_segment.0, frame.stack_segment.0,
            frame.instruction_pointer, frame.stack_pointer, kernel_rsp, rsp0,
        ));
        crate::halt_forever();
    }

    if phase == 0 {
        TRAPS.store(1, Ordering::Release);
        serial::write_line("WOLFOS_RING3_INT80_FIRST from_cpl=3 kernel_cpl=0 rsp0_switch=1 nonce=0x11");
        return; // compiler interrupt ABI issues real IRETQ, returning to CPL3
    }
    serial::write_line("WOLFOS_RING3_INT80_SECOND from_cpl=3 kernel_cpl=0 rsp0_switch=1 nonce=0x22");
    serial::write_line("WOLFOS_RING3_OK cpl3_executed=1 kernel_entries=2 user_iret_return=1 rsp0_switch=1 user_rw=1 user_rx=1 nxe=1 processes=0");
    serial::qemu_exit_success(); // clean QEMU exit ONLY after actual second trap
}
