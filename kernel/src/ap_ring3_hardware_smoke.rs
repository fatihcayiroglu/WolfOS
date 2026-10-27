//! Feature-isolated first genuine AP CPL3 -> CPL0 -> CPL3 -> CPL0 QEMU proof.
//!
//! Exactly one non-BSP processor executes a fixed, trusted two-INT80 payload
//! using its OWN GDT, TSS.RSP0 stack and IDT DPL3 gate. BSP exclusively
//! allocates/publishes three lower-half user leaves in an unused boot PML4
//! slot BEFORE any AP starts. No ELF process, scheduler, private root,
//! TLB retirement or complete kernel isolation is claimed. The six PMM
//! frames stay pinned until QEMU exits, since the boot root is shared.
use core::arch::{asm, x86_64::__cpuid};
use core::sync::atomic::{compiler_fence, AtomicBool, AtomicU32, AtomicU64,
                         AtomicUsize, Ordering};
use limine::mp::MpInfo;
use x86_64::{
    instructions::segmentation::{CS, Segment},
    registers::control::{Cr3, Cr4, Cr4Flags},
    structures::idt::InterruptStackFrame,
    VirtAddr,
};
use crate::{interrupts, pmm, serial, smp::MAX_BOOT_CPUS,
            user_ring_entry::{self, Ring3Entry}};

const CPUS: usize = 4;
const SPINS: usize = 400_000_000;
const FRAMES: usize = 6;
const PAGE: u64 = 4096;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const USER: u64 = 4;
const NX: u64 = 1 << 63;
const CODE_OFF: u64 = 0x401000;
const DATA_OFF: u64 = 0x402000;
const STACK_OFF: u64 = 0x403000;
const FIRST_NEXT: u64 = 9;
const SECOND_NEXT: u64 = 18;
const RSP0_BYTES: usize = 16 * 1024;
const RSP0_CANARY: u64 = 0x574f_4c46_4150_5253;

// RIP-relative stores both address the private user data byte 0.
// Two hardware INT80s prove IRETQ returned to genuine AP CPL3.
const CODE: [u8; 20] = [
    0xc6, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0x11,
    0xcd, 0x80,
    0xc6, 0x05, 0xf0, 0x0f, 0x00, 0x00, 0x22,
    0xcd, 0x80,
    0x0f, 0x0b,
];

#[repr(C, align(16))]
struct ApRsp0([u8; RSP0_BYTES]);
static mut AP_RSP0_STACK: ApRsp0 = ApRsp0([0; RSP0_BYTES]);

static PREPARED: AtomicBool = AtomicBool::new(false);
static BAD: AtomicBool = AtomicBool::new(false);
static TARGET: AtomicUsize = AtomicUsize::new(MAX_BOOT_CPUS);
static TARGET_LAPIC: AtomicU32 = AtomicU32::new(u32::MAX);
static BSP_LAPIC: AtomicU32 = AtomicU32::new(u32::MAX);
static BOOT_ROOT: AtomicU64 = AtomicU64::new(0);
static USER_RIP: AtomicU64 = AtomicU64::new(0);
static USER_STACK_TOP: AtomicU64 = AtomicU64::new(0);
static DATA_HHDM: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BEFORE: AtomicUsize = AtomicUsize::new(0);
static TRAPS: AtomicUsize = AtomicUsize::new(0);
static FINISHED: AtomicBool = AtomicBool::new(false);

pub(crate) fn target_index() -> usize { TARGET.load(Ordering::Acquire) }

pub(crate) fn rsp0_bounds() -> (u64, u64) {
    let base = (&raw const AP_RSP0_STACK).cast::<u8>() as u64;
    (base, base + RSP0_BYTES as u64)
}

pub(crate) fn rsp0_guard_ok() -> bool {
    let (base, top) = rsp0_bounds();
    base & 15 == 0 && top & 15 == 0
        && unsafe { (base as *const u64).read() } == RSP0_CANARY
        && unsafe { (base as *const u64).add(1).read() } == !RSP0_CANARY
}

fn current_lapic() -> u32 {
    // SAFETY: CPUID leaf 1 reports the hardware initial xAPIC ID in EBX.
    (unsafe { __cpuid(1) }.ebx >> 24) & 255
}
fn root_phys() -> u64 { Cr3::read().0.start_address().as_u64() }
fn local_ok() -> bool {
    !x86_64::instructions::interrupts::are_enabled()
        && !Cr4::read().contains(Cr4Flags::PCID)
}
fn hhdm_ptr(hhdm: u64, phys: u64) -> Option<*mut u8> {
    VirtAddr::try_new(hhdm.checked_add(phys)?).ok()
        .map(|v| v.as_mut_ptr::<u8>())
}
fn fail_ap() -> ! {
    BAD.store(true, Ordering::Release);
    crate::halt_forever()
}

/// BSP-only: all PML4/PT mutations and PMM allocation are complete before
/// Limine releases secondary processors. There is no concurrent PT writer.
pub(crate) fn prepare_bsp(hhdm: u64, bsp_lapic: u32, cpus: &[&MpInfo]) -> bool {
    if cpus.len() != CPUS || !local_ok() || hhdm == 0
        || PREPARED.load(Ordering::Relaxed)
        || current_lapic() != bsp_lapic || bsp_lapic > 255
    { return false; }
    let Some((target, cpu)) = cpus.iter().enumerate()
        .find(|(_, c)| c.lapic_id != bsp_lapic) else { return false; };
    if target >= MAX_BOOT_CPUS || cpu.lapic_id > 255
        || !cpus.iter().any(|c| c.lapic_id == bsp_lapic)
        || cpus.iter().enumerate().any(|(i, c)| cpus[..i].iter()
            .any(|prior| prior.lapic_id == c.lapic_id))
    { return false; }

    let boot = root_phys();
    let Some(root_ptr) = hhdm_ptr(hhdm, boot) else { return false; };
    // Require NXE before creating nonexecutable user data/stack mappings.
    let (lo, _hi): (u32, u32);
    unsafe {
        asm!("rdmsr", in("ecx") 0xc000_0080u32,
             out("eax") lo, out("edx") _hi,
             options(nostack, preserves_flags));
    }
    if lo & (1 << 11) == 0 { return false; }

    // Reject touching any occupied boot PML4 entry (including slot zero).
    let mut slot = 0usize;
    let pml4 = root_ptr.cast::<[u64; 512]>();
    unsafe {
        for i in 1..256 {
            if (*pml4)[i] == 0 { slot = i; break; }
        }
    }
    if slot == 0 { return false; }
    let base = (slot as u64) << 39;
    let text = base + CODE_OFF;
    let data = base + DATA_OFF;
    let stack = base + STACK_OFF;

    let before = pmm::statistics().allocated_frames;
    let mut frames = [0u64; FRAMES];
    for i in 0..FRAMES {
        let Some(phys) = pmm::allocate_frame() else {
            for old in frames[..i].iter().copied().rev() { let _ = pmm::free_frame(old); }
            return false;
        };
        if phys == 0 || phys & (PAGE - 1) != 0
            || phys >= 1u64 << 52 || frames[..i].contains(&phys)
        {
            let _ = pmm::free_frame(phys);
            for old in frames[..i].iter().copied().rev() { let _ = pmm::free_frame(old); }
            return false;
        }
        frames[i] = phys;
    }
    let mut ptrs = [core::ptr::null_mut::<u8>(); FRAMES];
    for i in 0..FRAMES {
        let Some(ptr) = hhdm_ptr(hhdm, frames[i]) else { return false; };
        ptrs[i] = ptr;
    }
    // SAFETY: fresh distinct PMM-owned physical buffers are unpublished,
    // accessible in HHDM and exclusively writable by this BSP.
    unsafe {
        for ptr in ptrs { core::ptr::write_bytes(ptr, 0, PAGE as usize); }
        core::ptr::copy_nonoverlapping(CODE.as_ptr(), ptrs[3], CODE.len());
        let pdpt = &mut *ptrs[0].cast::<[u64; 512]>();
        let pd = &mut *ptrs[1].cast::<[u64; 512]>();
        let pt = &mut *ptrs[2].cast::<[u64; 512]>();
        if ((text >> 30) & 511) != 0 || ((text >> 21) & 511) != 2
            || ((text >> 12) & 511) != 1
        { return false; }
        pdpt[0] = frames[1] | PRESENT | WRITE | USER;
        pd[2] = frames[2] | PRESENT | WRITE | USER;
        pt[1] = frames[3] | PRESENT | USER;
        pt[2] = frames[4] | PRESENT | WRITE | USER | NX;
        pt[3] = frames[5] | PRESENT | WRITE | USER | NX;
        if pt.iter().filter(|p| **p != 0).count() != 3 { return false; }
        let (rsp0_base, _) = rsp0_bounds();
        (rsp0_base as *mut u64).write(RSP0_CANARY);
        (rsp0_base as *mut u64).add(1).write(!RSP0_CANARY);
        if !rsp0_guard_ok() { return false; }
        // Publish all software state before exposing this root mapping.
        BOOT_ROOT.store(boot, Ordering::Relaxed);
        USER_RIP.store(text, Ordering::Relaxed);
        USER_STACK_TOP.store(stack + PAGE, Ordering::Relaxed);
        DATA_HHDM.store(ptrs[4] as u64, Ordering::Relaxed);
        ALLOCATED_BEFORE.store(before, Ordering::Relaxed);
        TARGET.store(target, Ordering::Relaxed);
        TARGET_LAPIC.store(cpu.lapic_id, Ordering::Relaxed);
        BSP_LAPIC.store(bsp_lapic, Ordering::Relaxed);
        if (*pml4)[slot] != 0 { return false; }
        compiler_fence(Ordering::SeqCst);
        (*pml4)[slot] = frames[0] | PRESENT | WRITE | USER;
        // BSP's local TLB is invalidated before releasing any AP.
        asm!("invlpg [{}]", in(reg) text, options(nostack, preserves_flags));
        asm!("invlpg [{}]", in(reg) data, options(nostack, preserves_flags));
        asm!("invlpg [{}]", in(reg) stack, options(nostack, preserves_flags));
    }
    if pmm::statistics().allocated_frames != before + FRAMES { return false; }
    PREPARED.store(true, Ordering::Release);
    true
}

/// Executed only by the first non-BSP AP after completing its ordinary
/// boot context/scheduler work. On success this never returns.
pub(crate) fn secondary(index: usize) {
    if index != target_index() { return; }
    let Some((user_cs, user_ss, rsp0)) =
        interrupts::ap_ring3_cpu_state(index) else { fail_ap(); };
    let text = USER_RIP.load(Ordering::Acquire);
    let stack = USER_STACK_TOP.load(Ordering::Acquire);
    if !PREPARED.load(Ordering::Acquire) || BAD.load(Ordering::Acquire)
        || !local_ok() || root_phys() != BOOT_ROOT.load(Ordering::Acquire)
        || current_lapic() != TARGET_LAPIC.load(Ordering::Acquire)
        || !rsp0_guard_ok()
        || user_ring_entry::validate(Ring3Entry {
            rip: text, user_rsp: stack, kernel_rsp0: rsp0,
            user_cs, user_ss, rflags: 2,
        }).is_err()
    { fail_ap(); }
    // SAFETY: target AP alone has the DPL3 INT80 gate and its own verified
    // TSS.RSP0. Only the immutable trusted code page is executable at CPL3.
    // No interruptible Ring3, user threads or untrusted inputs exist here.
    unsafe {
        asm!(
            "push {ss}", "push {rsp}", "push {flags}", "push {cs}",
            "push {rip}", "iretq",
            ss = in(reg) u64::from(user_ss), rsp = in(reg) stack,
            flags = in(reg) 2u64, cs = in(reg) u64::from(user_cs),
            rip = in(reg) text, options(noreturn),
        );
    }
}

/// Real CPL3-originated INT80 on the target AP, landing on its own
/// TSS.RSP0. The first handler must IRETQ; the second is terminal.
pub extern "x86-interrupt" fn interrupt_80(frame: InterruptStackFrame) {
    let index = target_index();
    let Some((cs, ss, rsp0)) = interrupts::ap_ring3_cpu_state(index)
    else { fail_ap(); };
    let phase = TRAPS.load(Ordering::Acquire);
    let text = USER_RIP.load(Ordering::Acquire);
    let stack = USER_STACK_TOP.load(Ordering::Acquire);
    let data = DATA_HHDM.load(Ordering::Acquire);
    let kernel_rsp: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) kernel_rsp,
             options(nomem, nostack, preserves_flags));
    }
    let nonce = if data != 0 { unsafe { (data as *const u8).read_volatile() } }
                else { 0 };
    let expected_nonce = if phase == 0 { 0x11 } else { 0x22 };
    let expected_rip = text + if phase == 0 { FIRST_NEXT } else { SECOND_NEXT };
    if !PREPARED.load(Ordering::Acquire)
        || index >= MAX_BOOT_CPUS || phase >= 2
        || current_lapic() != TARGET_LAPIC.load(Ordering::Acquire)
        || TARGET_LAPIC.load(Ordering::Acquire) == BSP_LAPIC.load(Ordering::Acquire)
        || root_phys() != BOOT_ROOT.load(Ordering::Acquire)
        || CS::get_reg().0 != 8 || frame.code_segment.0 != cs
        || frame.stack_segment.0 != ss
        || frame.instruction_pointer.as_u64() != expected_rip
        || frame.stack_pointer.as_u64() != stack
        || nonce != expected_nonce
        || kernel_rsp < rsp0 - RSP0_BYTES as u64 || kernel_rsp >= rsp0
        || !rsp0_guard_ok()
    { fail_ap(); }
    if phase == 0 {
        TRAPS.store(1, Ordering::Release);
        return; // compiler ISR ABI performs the first real IRETQ to AP CPL3
    }
    TRAPS.store(2, Ordering::Release);
    FINISHED.store(true, Ordering::Release);
    // No RETURN to a finished user context. AP stays parked; no concurrent
    // unmap or PMM release while this boot root is shared.
    crate::halt_forever();
}

/// BSP-only result attestation; no AP prints serial logs or manipulates PMM.
pub(crate) fn verify_bsp() -> bool {
    if !PREPARED.load(Ordering::Acquire) || !local_ok()
        || current_lapic() != BSP_LAPIC.load(Ordering::Acquire)
        || root_phys() != BOOT_ROOT.load(Ordering::Acquire)
    { return false; }
    for _ in 0..SPINS {
        if BAD.load(Ordering::Acquire) { return false; }
        if FINISHED.load(Ordering::Acquire) { break; }
        core::hint::spin_loop();
    }
    let index = target_index();
    if !FINISHED.load(Ordering::Acquire) || TRAPS.load(Ordering::Acquire) != 2
        || index >= CPUS || BAD.load(Ordering::Acquire)
        || !rsp0_guard_ok()
        || pmm::statistics().allocated_frames
            != ALLOCATED_BEFORE.load(Ordering::Acquire) + FRAMES
    { return false; }
    serial::write_fmt(format_args!(
        "WOLFOS_AP_RING3_OK cpus=4 target_index={} bsp_lapic={} ap_lapic={} ap_cpl3=1 int80=2 iret_to_cpl3=1 private_tss_rsp0=1 actual_tr=1 rw_nx=2 rx=1 frames_pinned=6\n",
        index, BSP_LAPIC.load(Ordering::Acquire),
        TARGET_LAPIC.load(Ordering::Acquire),
    ));
    true
}
