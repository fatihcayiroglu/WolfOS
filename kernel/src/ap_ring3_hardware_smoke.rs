//! Feature-isolated first genuine AP CPL3 -> CPL0 -> CPL3 -> CPL0 QEMU proof.
//!
//! Exactly one non-BSP processor executes a fixed, trusted two-INT80 payload
//! using its OWN GDT, TSS.RSP0 stack and IDT DPL3 gate. BSP exclusively
//! allocates/publishes three lower-half user leaves in an unused boot PML4
//! slot BEFORE any AP starts. The opt-in private-CR3 flavor instead places
//! all user leaves under a new supervisor-sanitized PML4, leaving the boot
//! root's low half unchanged. No ELF process, scheduler, TLB retirement or
//! full production isolation is claimed. The ELF flavor builds independent
//! ELF64 bytes and materializes two derived PT_LOAD pages, with the same
//! real AP CR3/INT80/IRETQ checks. An opt-in one-owner terminal flavor
//! proves AP CR3 departure before BSP scrubs/releases all seven pages.
//! The multi-owner flavor additionally requires two other APs to load the
//! same root in CPL0 and physically depart before ANY frame is freed.
//! Other flavors deliberately leave their 6/7 PMM pages pinned.
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
use crate::{interrupts, kernel_half_shadow, pmm, serial, smp::MAX_BOOT_CPUS,
            user_ring_entry::{self, Ring3Entry}};

const CPUS: usize = 4;
const SPINS: usize = 400_000_000;
const FRAMES: usize = if cfg!(feature = "ap-ring3-private-cr3-smoke") { 7 } else { 6 };
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
#[cfg(not(feature = "ap-ring3-elf-smoke"))]
const CODE: [u8; 20] = [
    0xc6, 0x05, 0xf9, 0x0f, 0x00, 0x00, 0x11,
    0xcd, 0x80,
    0xc6, 0x05, 0xf0, 0x0f, 0x00, 0x00, 0x22,
    0xcd, 0x80,
    0x0f, 0x0b,
];

#[cfg(feature = "ap-ring3-elf-smoke")]
const ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wolfos-ap-ring3.elf"));

#[repr(C, align(16))]
struct ApRsp0([u8; RSP0_BYTES]);
static mut AP_RSP0_STACK: ApRsp0 = ApRsp0([0; RSP0_BYTES]);

static PREPARED: AtomicBool = AtomicBool::new(false);
static BAD: AtomicBool = AtomicBool::new(false);
static TARGET: AtomicUsize = AtomicUsize::new(MAX_BOOT_CPUS);
static TARGET_LAPIC: AtomicU32 = AtomicU32::new(u32::MAX);
static BSP_LAPIC: AtomicU32 = AtomicU32::new(u32::MAX);
static BOOT_ROOT: AtomicU64 = AtomicU64::new(0);
static PRIVATE_ROOT: AtomicU64 = AtomicU64::new(0);
static HHDM_BASE: AtomicU64 = AtomicU64::new(0);
static PRIVATE_RESTORED: AtomicBool = AtomicBool::new(false);
static USER_SLOT: AtomicUsize = AtomicUsize::new(0);
static KERNEL_GRAFTS: AtomicUsize = AtomicUsize::new(0);
static USER_RIP: AtomicU64 = AtomicU64::new(0);
static USER_STACK_TOP: AtomicU64 = AtomicU64::new(0);
static DATA_HHDM: AtomicU64 = AtomicU64::new(0);
static ALLOCATED_BEFORE: AtomicUsize = AtomicUsize::new(0);
static TRAPS: AtomicUsize = AtomicUsize::new(0);
static FINISHED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "ap-ring3-elf-reclaim-smoke")]
static OWNED: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];

#[cfg(feature = "ap-ring3-elf-multi-owner-smoke")]
static BORROWER_MASK: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "ap-ring3-elf-multi-owner-smoke")]
static BORROWER_LAPICS: [AtomicU32; CPUS] = [const { AtomicU32::new(u32::MAX) }; CPUS];
#[cfg(feature = "ap-ring3-elf-multi-owner-smoke")]
static BORROWED_ENTERED: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "ap-ring3-elf-multi-owner-smoke")]
static BORROWED_LEFT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "ap-ring3-elf-multi-owner-smoke")]
static BORROWER_RELEASE: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "ap-ring3-elf-missing-borrower-smoke")]
static BORROWER_WITHHELD: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "ap-ring3-elf-missing-borrower-smoke")]
static RECLAIM_REFUSED_LIVE_BORROWER: AtomicBool = AtomicBool::new(false);

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
    // Never allow the private root or its leaves to alias the live boot PML4.
    if frames.contains(&boot) { return false; }
    let mut ptrs = [core::ptr::null_mut::<u8>(); FRAMES];
    for i in 0..FRAMES {
        let Some(ptr) = hhdm_ptr(hhdm, frames[i]) else { return false; };
        ptrs[i] = ptr;
    }
    // SAFETY: fresh distinct PMM-owned physical buffers are unpublished,
    // accessible in HHDM and exclusively writable by this BSP.
    unsafe {
        for ptr in ptrs { core::ptr::write_bytes(ptr, 0, PAGE as usize); }
        #[cfg(feature = "ap-ring3-elf-smoke")]
        {
            // Do not interpret ELF bytes as structs or execute the text
            // before strict ET_EXEC PT_LOAD preflight and complete audit.
            let Ok(plan) = crate::elf64_preflight::preflight(ELF)
                else { return false; };
            if plan.len != 2 || plan.entry != CODE_OFF
                || plan.segments[0].is_none()
                || plan.segments[1].is_none()
            { return false; }
            let rx = plan.segments[0].unwrap();
            let rw = plan.segments[1].unwrap();
            if !rx.executable || rx.writable || rw.executable || !rw.writable
                || rx.page_start != CODE_OFF || rx.page_end != CODE_OFF + PAGE
                || rw.page_start != DATA_OFF || rw.page_end != DATA_OFF + PAGE
                || rx.file_size != 20 || rx.memory_size != 20
                || rw.file_size != 1 || rw.memory_size != 1
                || rx.virtual_address != CODE_OFF
                || rw.virtual_address != DATA_OFF
            { return false; }
            let text_leaf = &mut *ptrs[3].cast::<[u8; 4096]>();
            let data_leaf = &mut *ptrs[4].cast::<[u8; 4096]>();
            let Ok(outcomes) = crate::elf64_page_image::materialize_batch(
                ELF, [(&rx, CODE_OFF), (&rw, DATA_OFF)],
                [&mut *text_leaf, &mut *data_leaf],
            ) else { return false; };
            if !outcomes[0].executable || outcomes[0].writable
                || outcomes[0].copied != 20
                || outcomes[1].executable || !outcomes[1].writable
                || outcomes[1].copied != 1
                || crate::elf64_page_image::audit_materialized_batch(
                    ELF, [(&rx, CODE_OFF), (&rw, DATA_OFF)],
                    [&*text_leaf, &*data_leaf],
                ) != Ok(outcomes)
                || data_leaf[0] != 0
            { return false; }
        }
        #[cfg(not(feature = "ap-ring3-elf-smoke"))]
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
        // Private root is staged on a fresh PMM frame. In this flavor the
        // live boot PML4 never acquires a lower-half user entry.
        let private_root = if cfg!(feature = "ap-ring3-private-cr3-smoke") {
            let shadow = &mut *ptrs[FRAMES - 1].cast::<[u64; 512]>();
            let entry = frames[0] | PRESENT | WRITE | USER;
            shadow[slot] = entry;
            let graft = kernel_half_shadow::graft_kernel_half(
                &*pml4, shadow, slot, entry, &frames,
            );
            if !matches!(graft, Ok(count) if count >= 1)
                || kernel_half_shadow::audit_kernel_half(
                    &*pml4, shadow, slot, entry, &frames,
                ) != graft
                || shadow[256..].iter().any(|e| e & USER != 0)
                || shadow[..256].iter().filter(|e| **e != 0).count() != 1
                || (*pml4)[slot] != 0
            { return false; }
            KERNEL_GRAFTS.store(graft.unwrap_or(0), Ordering::Relaxed);
            frames[FRAMES - 1]
        } else { 0 };
        // Publish all software state before exposing this root mapping.
        BOOT_ROOT.store(boot, Ordering::Relaxed);
        HHDM_BASE.store(hhdm, Ordering::Relaxed);
        PRIVATE_ROOT.store(private_root, Ordering::Relaxed);
        USER_SLOT.store(slot, Ordering::Relaxed);
        USER_RIP.store(text, Ordering::Relaxed);
        USER_STACK_TOP.store(stack + PAGE, Ordering::Relaxed);
        DATA_HHDM.store(ptrs[4] as u64, Ordering::Relaxed);
        ALLOCATED_BEFORE.store(before, Ordering::Relaxed);
        TARGET.store(target, Ordering::Relaxed);
        TARGET_LAPIC.store(cpu.lapic_id, Ordering::Relaxed);
        BSP_LAPIC.store(bsp_lapic, Ordering::Relaxed);
        if (*pml4)[slot] != 0 { return false; }
        compiler_fence(Ordering::SeqCst);
        if !cfg!(feature = "ap-ring3-private-cr3-smoke") {
            (*pml4)[slot] = frames[0] | PRESENT | WRITE | USER;
            // Legacy shared-root proof requires invalidating BSP TLB leaves.
            asm!("invlpg [{}]", in(reg) text, options(nostack, preserves_flags));
            asm!("invlpg [{}]", in(reg) data, options(nostack, preserves_flags));
            asm!("invlpg [{}]", in(reg) stack, options(nostack, preserves_flags));
        }
    }
    if pmm::statistics().allocated_frames != before + FRAMES { return false; }
    #[cfg(feature = "ap-ring3-elf-reclaim-smoke")]
    for (i, frame) in frames.iter().copied().enumerate() {
        OWNED[i].store(frame, Ordering::Release);
    }
    #[cfg(feature = "ap-ring3-elf-multi-owner-smoke")]
    {
        let mask = cpus.iter().enumerate().filter(|(i, cpu)|
            *i != target && cpu.lapic_id != bsp_lapic
        ).fold(0u64, |mask, (i, _)| mask | (1u64 << i));
        if mask.count_ones() != 2 || mask & (1u64 << target) != 0
            || BORROWER_MASK.load(Ordering::Relaxed) != 0
        { return false; }
        for (i, cpu) in cpus.iter().enumerate() {
            BORROWER_LAPICS[i].store(cpu.lapic_id, Ordering::Relaxed);
        }
        BORROWER_MASK.store(mask, Ordering::Release);
    }
    PREPARED.store(true, Ordering::Release);
    true
}

/// Two additional APs borrow the same REAL private root in CPL0. Both
/// independently load and later depart CR3; neither executes user ELF, and
/// neither may free PMM frames or issue a coordinator-side fake ack.
#[cfg(feature = "ap-ring3-elf-multi-owner-smoke")]
fn borrow_secondary(index: usize) {
    if index >= CPUS || BORROWER_MASK.load(Ordering::Acquire) & (1u64 << index) == 0
        || !PREPARED.load(Ordering::Acquire) || BAD.load(Ordering::Acquire)
        || !local_ok() || current_lapic() != BORROWER_LAPICS[index].load(Ordering::Acquire)
    { fail_ap(); }
    let boot = BOOT_ROOT.load(Ordering::Acquire);
    let private = PRIVATE_ROOT.load(Ordering::Acquire);
    if boot == 0 || private == 0 || boot == private
        || private & (PAGE - 1) != 0 || root_phys() != boot
    { fail_ap(); }
    // SAFETY: shared HIGH-HALF supervisor mappings were audited by BSP
    // before AP launch; these APs run only trusted CPL0 code on pinned
    // kernel stacks and cannot modify PMM or user leaves.
    unsafe { asm!("mov cr3, {}", in(reg) private, options(nostack, preserves_flags)); }
    if root_phys() != private { fail_ap(); }
    BORROWED_ENTERED.fetch_or(1u64 << index, Ordering::Release);

    for _ in 0..SPINS {
        if BORROWER_RELEASE.load(Ordering::Acquire) { break; }
        if BAD.load(Ordering::Acquire) { break; }
        core::hint::spin_loop();
    }
    let authorized = BORROWER_RELEASE.load(Ordering::Acquire)
        && !BAD.load(Ordering::Acquire);
    // Isolated *negative* hardware proof: one actual AP remains on the
    // private CR3 after release. It NEVER publishes a fictitious exit ack.
    // This is safe only in the no-reclaim QEMU diagnostic feature.
    #[cfg(feature = "ap-ring3-elf-missing-borrower-smoke")]
    if authorized {
        let mask = BORROWER_MASK.load(Ordering::Acquire);
        let held_bit = 1u64 << (63 - mask.leading_zeros());
        if (1u64 << index) == held_bit {
            if root_phys() != private { fail_ap(); }
            BORROWER_WITHHELD.store(true, Ordering::Release);
            crate::halt_forever();
        }
    }
    // Even a timed-out normal borrower restores its own CR3. It never
    // pretends to have completed the owner-bound release on an error.
    unsafe { asm!("mov cr3, {}", in(reg) boot, options(nostack, preserves_flags)); }
    if root_phys() != boot || !authorized { fail_ap(); }
    BORROWED_LEFT.fetch_or(1u64 << index, Ordering::Release);
}

/// BSP never releases or scrubs leases until BOTH other APs have published
/// real private CR3 observations, then both have switched back themselves.
#[cfg(feature = "ap-ring3-elf-multi-owner-smoke")]
fn release_borrowers_after_target() -> bool {
    let mask = BORROWER_MASK.load(Ordering::Acquire);
    if mask.count_ones() != 2 || BAD.load(Ordering::Acquire)
        || !FINISHED.load(Ordering::Acquire) || !PRIVATE_RESTORED.load(Ordering::Acquire)
        || BORROWER_RELEASE.load(Ordering::Acquire)
        || current_lapic() != BSP_LAPIC.load(Ordering::Acquire)
        || root_phys() != BOOT_ROOT.load(Ordering::Acquire)
    { return false; }
    for _ in 0..SPINS {
        if BAD.load(Ordering::Acquire) { return false; }
        if BORROWED_ENTERED.load(Ordering::Acquire) == mask { break; }
        core::hint::spin_loop();
    }
    if BORROWED_ENTERED.load(Ordering::Acquire) != mask
        || BORROWED_LEFT.load(Ordering::Acquire) != 0
    { return false; }
    BORROWER_RELEASE.store(true, Ordering::Release);
    #[cfg(feature = "ap-ring3-elf-missing-borrower-smoke")]
    {
        // The highest-indexed real borrower remains physically in the
        // private root. The OTHER borrower must actually depart its CR3.
        let held_bit = 1u64 << (63 - mask.leading_zeros());
        let expected_left = mask ^ held_bit;
        for _ in 0..SPINS {
            if BAD.load(Ordering::Acquire) { return false; }
            if BORROWER_WITHHELD.load(Ordering::Acquire)
                && BORROWED_LEFT.load(Ordering::Acquire) == expected_left
            { break; }
            core::hint::spin_loop();
        }
        return BORROWER_WITHHELD.load(Ordering::Acquire)
            && BORROWED_ENTERED.load(Ordering::Acquire) == mask
            && BORROWED_LEFT.load(Ordering::Acquire) == expected_left
            && !BAD.load(Ordering::Acquire);
    }
    #[cfg(not(feature = "ap-ring3-elf-missing-borrower-smoke"))]
    {
        for _ in 0..SPINS {
            if BAD.load(Ordering::Acquire) { return false; }
            if BORROWED_LEFT.load(Ordering::Acquire) == mask { break; }
            core::hint::spin_loop();
        }
        BORROWED_LEFT.load(Ordering::Acquire) == mask
            && BORROWED_ENTERED.load(Ordering::Acquire) == mask
            && !BAD.load(Ordering::Acquire)
    }
}

/// Executed only by the first non-BSP AP after completing its ordinary
/// boot context/scheduler work. On success this never returns.
pub(crate) fn secondary(index: usize) {
    if index != target_index() {
        #[cfg(feature = "ap-ring3-elf-multi-owner-smoke")]
        if index < CPUS
            && BORROWER_MASK.load(Ordering::Acquire) & (1u64 << index) != 0
        {
            borrow_secondary(index);
        }
        return;
    }
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
    // SAFETY: no PCID, no interruptible Ring3, new audited PML4 shares
    // supervisor-only high-half tables and holds exclusively owned user PTs.
    // The AP alone switches roots; BSP remains on unchanged boot CR3.
    if cfg!(feature = "ap-ring3-private-cr3-smoke") {
        let private = PRIVATE_ROOT.load(Ordering::Acquire);
        if private == 0 || private == BOOT_ROOT.load(Ordering::Acquire)
            || private & (PAGE - 1) != 0
        { fail_ap(); }
        unsafe {
            asm!("mov cr3, {}", in(reg) private, options(nostack, preserves_flags));
        }
        if root_phys() != private { fail_ap(); }
    }
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
    let expected_root = if cfg!(feature = "ap-ring3-private-cr3-smoke") {
        PRIVATE_ROOT.load(Ordering::Acquire)
    } else { BOOT_ROOT.load(Ordering::Acquire) };
    if !PREPARED.load(Ordering::Acquire)
        || index >= MAX_BOOT_CPUS || phase >= 2
        || current_lapic() != TARGET_LAPIC.load(Ordering::Acquire)
        || TARGET_LAPIC.load(Ordering::Acquire) == BSP_LAPIC.load(Ordering::Acquire)
        || expected_root == 0 || root_phys() != expected_root
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
    if cfg!(feature = "ap-ring3-private-cr3-smoke") {
        let boot = BOOT_ROOT.load(Ordering::Acquire);
        // Terminal syscall is NOT returning to user mode: the AP may
        // restore its supervisor root while still on its mapped RSP0 stack.
        unsafe {
            asm!("mov cr3, {}", in(reg) boot, options(nostack, preserves_flags));
        }
        if root_phys() != boot { fail_ap(); }
        PRIVATE_RESTORED.store(true, Ordering::Release);
    }
    FINISHED.store(true, Ordering::Release);
    // No IRETQ to the completed user context. Physical leases stay pinned
    // until QEMU exits, including the private inactive root if configured.
    crate::halt_forever();
}


/// BSP-only, AFTER terminal AP hardware CR3 restoration and completion
/// acknowledgment. No CPU is permitted to be executing/borrowing this root:
/// only target AP ever loaded it, BSP stayed on boot, other APs never
/// received the private CR3. Its final MOV CR3 flushed non-global user TLB
/// translations. This is a SINGLE-OWNER proof, not general SMP shootdown.
///
/// A first failure is terminal/fail-closed: no attempt to disguise partial
/// reclamation as a clean exit. The AP's kernel TSS.RSP0 is static BSS and
/// stays mapped in the borrowed high-half during its permanent parked loop.
// x86-64 hardware may set Accessed in each PRESENT paging level and
// Dirty on writable leaves during actual CPL3 reads/writes. These are the
// ONLY guest-generated bit changes tolerated by terminal retirement.
#[cfg(feature = "ap-ring3-elf-reclaim-smoke")]
const ACCESSED: u64 = 1 << 5;
#[cfg(feature = "ap-ring3-elf-reclaim-smoke")]
const RW_HW_BITS: u64 = ACCESSED | (1 << 6);

/// This root was genuinely active on the target AP. The pre-activation
/// kernel_half_shadow::audit_kernel_half requires byte-identical entries,
/// so it must not be reapplied to hardware-dirtied live page tables.
#[cfg(feature = "ap-ring3-elf-reclaim-smoke")]
fn audit_high_half_after_ap(
    source: &[u64; 512], shadow: &[u64; 512], owned: &[u64], expected: usize,
) -> bool {
    if expected == 0
        || source[256..].iter().filter(|entry| **entry != 0).count() != expected
    { return false; }
    for (boot_entry, private_entry) in source[256..].iter().zip(shadow[256..].iter()) {
        if *boot_entry == 0 {
            if *private_entry != 0 { return false; }
            continue;
        }
        let phys = *boot_entry & kernel_half_shadow::PHYS_MASK;
        if *boot_entry & PRESENT == 0 || *boot_entry & (1 << 7) != 0
            || phys == 0 || owned.contains(&phys)
            || *private_entry & USER != 0
            || (*private_entry & !ACCESSED)
                != ((*boot_entry & !USER) & !ACCESSED)
        { return false; }
    }
    true
}

#[cfg(feature = "ap-ring3-elf-reclaim-smoke")]
fn reclaim_fail(stage: &str) -> bool {
    serial::write_fmt(format_args!(
        "WOLFOS_AP_RING3_RECLAIM_FAIL stage={}\n", stage,
    ));
    false
}

#[cfg(feature = "ap-ring3-elf-reclaim-smoke")]
fn reclaim_completed_ap() -> bool {
    if !local_ok() || !PREPARED.load(Ordering::Acquire)
        || !FINISHED.load(Ordering::Acquire)
        || TRAPS.load(Ordering::Acquire) != 2
        || BAD.load(Ordering::Acquire)
        || !PRIVATE_RESTORED.load(Ordering::Acquire)
        || current_lapic() != BSP_LAPIC.load(Ordering::Acquire)
    { return reclaim_fail("state"); }
    let boot = BOOT_ROOT.load(Ordering::Acquire);
    let private = PRIVATE_ROOT.load(Ordering::Acquire);
    let hhdm = HHDM_BASE.load(Ordering::Acquire);
    let slot = USER_SLOT.load(Ordering::Acquire);
    let lease: [u64; 7] = core::array::from_fn(|i| OWNED[i].load(Ordering::Acquire));
    if root_phys() != boot || private == 0 || private == boot
        || slot == 0 || slot >= 256 || lease[6] != private
        || pmm::statistics().allocated_frames
            != ALLOCATED_BEFORE.load(Ordering::Acquire) + 7
        || lease.iter().enumerate().any(|(i, frame)|
            *frame == 0 || (*frame & (PAGE - 1)) != 0
            || *frame >= (1u64 << 52) || *frame == boot
            || lease[..i].contains(frame))
    { return reclaim_fail("lease"); }
    let Some(boot_ptr) = hhdm_ptr(hhdm, boot) else { return reclaim_fail("boot_hhdm"); };
    let mut pointers = [core::ptr::null_mut::<u8>(); 7];
    for (i, frame) in lease.iter().copied().enumerate() {
        let Some(ptr) = hhdm_ptr(hhdm, frame) else { return reclaim_fail("frame_hhdm"); };
        pointers[i] = ptr;
    }
    // All page-table and final nonce observations happen BEFORE any free.
    let mapping_ok = unsafe {
        let source = &*boot_ptr.cast::<[u64; 512]>();
        let shadow = &*pointers[6].cast::<[u64; 512]>();
        let pdpt = &*pointers[0].cast::<[u64; 512]>();
        let pd = &*pointers[1].cast::<[u64; 512]>();
        let pt = &*pointers[2].cast::<[u64; 512]>();
        let user_entry = lease[0] | PRESENT | WRITE | USER;
        source[slot] == 0
            && shadow[slot] & !ACCESSED == user_entry
            && shadow[..256].iter().filter(|entry| **entry != 0).count() == 1
            && audit_high_half_after_ap(
                source, shadow, &lease, KERNEL_GRAFTS.load(Ordering::Acquire),
            )
            && pdpt[0] & !ACCESSED == lease[1] | PRESENT | WRITE | USER
            && pdpt.iter().filter(|e| **e != 0).count() == 1
            && pd[2] & !ACCESSED == lease[2] | PRESENT | WRITE | USER
            && pd.iter().filter(|e| **e != 0).count() == 1
            && pt[1] & !ACCESSED == lease[3] | PRESENT | USER
            && pt[2] & !RW_HW_BITS == lease[4] | PRESENT | WRITE | USER | NX
            && pt[3] & !RW_HW_BITS == lease[5] | PRESENT | WRITE | USER | NX
            && pt.iter().filter(|e| **e != 0).count() == 3
            && pointers[4] as u64 == DATA_HHDM.load(Ordering::Acquire)
            && pointers[4].read_volatile() == 0x22
    };
    if !mapping_ok {
        // Fail-only bitmask: root, page-table and post-trap nonce audit.
        let faults = unsafe {
            let source = &*boot_ptr.cast::<[u64; 512]>();
            let shadow = &*pointers[6].cast::<[u64; 512]>();
            let pdpt = &*pointers[0].cast::<[u64; 512]>();
            let pd = &*pointers[1].cast::<[u64; 512]>();
            let pt = &*pointers[2].cast::<[u64; 512]>();
            let entry = lease[0] | PRESENT | WRITE | USER;
            let mut bits = 0u32;
            if source[slot] != 0 { bits |= 1; }
            if shadow[slot] & !ACCESSED != entry { bits |= 2; }
            if shadow[..256].iter().filter(|e| **e != 0).count() != 1 { bits |= 4; }
            if !audit_high_half_after_ap(
                source, shadow, &lease, KERNEL_GRAFTS.load(Ordering::Acquire),
            ) { bits |= 8; }
            if pdpt[0] & !ACCESSED != lease[1] | PRESENT | WRITE | USER { bits |= 16; }
            if pdpt.iter().filter(|e| **e != 0).count() != 1 { bits |= 32; }
            if pd[2] & !ACCESSED != lease[2] | PRESENT | WRITE | USER { bits |= 64; }
            if pd.iter().filter(|e| **e != 0).count() != 1 { bits |= 128; }
            if pt[1] & !ACCESSED != lease[3] | PRESENT | USER { bits |= 256; }
            if pt[2] & !RW_HW_BITS != lease[4] | PRESENT | WRITE | USER | NX { bits |= 512; }
            if pt[3] & !RW_HW_BITS != lease[5] | PRESENT | WRITE | USER | NX { bits |= 1024; }
            if pt.iter().filter(|e| **e != 0).count() != 3 { bits |= 2048; }
            if pointers[4] as u64 != DATA_HHDM.load(Ordering::Acquire) { bits |= 4096; }
            if pointers[4].read_volatile() != 0x22 { bits |= 8192; }
            bits
        };
        serial::write_fmt(format_args!(
            "WOLFOS_AP_RING3_RECLAIM_FAIL stage=mapping fault_mask={}\n", faults,
        ));
        return false;
    }
    #[cfg(feature = "ap-ring3-elf-multi-owner-smoke")]
    {
        let mask = BORROWER_MASK.load(Ordering::Acquire);
        if mask.count_ones() != 2 || !BORROWER_RELEASE.load(Ordering::Acquire)
            || BORROWED_ENTERED.load(Ordering::Acquire) != mask
            || BORROWED_LEFT.load(Ordering::Acquire) != mask
        {
            #[cfg(feature = "ap-ring3-elf-missing-borrower-smoke")]
            RECLAIM_REFUSED_LIVE_BORROWER.store(true, Ordering::Release);
            return reclaim_fail("borrowers_still_live");
        }
    }
    // No guest may re-enter: AP has already retired from this root.
    // Revoke all lease references before the FIRST physical-frame free.
    PREPARED.store(false, Ordering::SeqCst);
    USER_RIP.store(0, Ordering::SeqCst);
    USER_STACK_TOP.store(0, Ordering::SeqCst);
    DATA_HHDM.store(0, Ordering::SeqCst);
    PRIVATE_ROOT.store(0, Ordering::SeqCst);
    compiler_fence(Ordering::SeqCst);
    for i in (0..7).rev() {
        // SAFETY: exclusive PMM lease, authenticated pages and no CPU
        // referencing the private CR3. HHDM remains supervisor-mapped.
        unsafe { core::ptr::write_bytes(pointers[i], 0, PAGE as usize); }
        if pmm::free_frame(lease[i]).is_err() { return reclaim_fail("pmm_free"); }
        OWNED[i].store(0, Ordering::Release);
    }
    if pmm::free_frame(lease[0]) != Err(pmm::FreeError::DoubleFree)
        || pmm::statistics().allocated_frames
            != ALLOCATED_BEFORE.load(Ordering::Acquire)
        || OWNED.iter().any(|p| p.load(Ordering::Acquire) != 0)
        || PREPARED.load(Ordering::Acquire)
        || PRIVATE_ROOT.load(Ordering::Acquire) != 0
        || DATA_HHDM.load(Ordering::Acquire) != 0
        || root_phys() != boot
    { return reclaim_fail("final"); }
    true
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
    #[cfg(feature = "ap-ring3-elf-multi-owner-smoke")]
    if !release_borrowers_after_target() { return false; }
    #[cfg(feature = "ap-ring3-elf-missing-borrower-smoke")]
    {
        // Exercise the SAME production candidate reclamation gate while a
        // known real AP still holds private CR3. All mapping audits must pass;
        // only the borrower-liveness gate may refuse reclamation.
        if reclaim_completed_ap() { return false; }
        let mask = BORROWER_MASK.load(Ordering::Acquire);
        let held_bit = 1u64 << (63 - mask.leading_zeros());
        if !RECLAIM_REFUSED_LIVE_BORROWER.load(Ordering::Acquire)
            || !BORROWER_WITHHELD.load(Ordering::Acquire)
            || BORROWED_ENTERED.load(Ordering::Acquire) != mask
            || BORROWED_LEFT.load(Ordering::Acquire) != (mask ^ held_bit)
            || !PREPARED.load(Ordering::Acquire)
            || PRIVATE_ROOT.load(Ordering::Acquire) == 0
            || OWNED.iter().any(|f| f.load(Ordering::Acquire) == 0)
            || pmm::statistics().allocated_frames
                != ALLOCATED_BEFORE.load(Ordering::Acquire) + 7
            || root_phys() != BOOT_ROOT.load(Ordering::Acquire)
        { return false; }
        serial::write_fmt(format_args!(
            "WOLFOS_AP_RING3_ELF_MISSING_BORROWER_OK cpus=4 target_index={} bsp_lapic={} ap_lapic={} linked_elf=1 et_exec=1 pt_load=2 ap_cpl3=1 int80=2 iret_to_cpl3=1 ap_private_cr3=1 ap_restored_boot_cr3=1 cpl0_borrowers=2 borrower_cr3_entered=2 borrower_cr3_departed=1 borrower_held_private_cr3=1 all_user_cr3_departed=0 reclaim_refused=1 frames_pinned=7 frames_freed=0 pmm_held_lease=1 bsp_boot_cr3=1\n",
            index, BSP_LAPIC.load(Ordering::Acquire),
            TARGET_LAPIC.load(Ordering::Acquire),
        ));
        return true;
    }
    #[cfg(not(feature = "ap-ring3-elf-missing-borrower-smoke"))]
    if cfg!(feature = "ap-ring3-private-cr3-smoke") {
        let slot = USER_SLOT.load(Ordering::Acquire);
        let boot = BOOT_ROOT.load(Ordering::Acquire);
        let private = PRIVATE_ROOT.load(Ordering::Acquire);
        let hhdm = HHDM_BASE.load(Ordering::Acquire);
        let Some(boot_ptr) = hhdm_ptr(hhdm, boot) else { return false; };
        let Some(private_ptr) = hhdm_ptr(hhdm, private) else { return false; };
        let source = unsafe { &*boot_ptr.cast::<[u64; 512]>() };
        let shadow = unsafe { &*private_ptr.cast::<[u64; 512]>() };
        if slot == 0 || slot >= 256 || source[slot] != 0
            || private == 0 || private == boot
            || !PRIVATE_RESTORED.load(Ordering::Acquire)
            || KERNEL_GRAFTS.load(Ordering::Acquire) < 1
            || (shadow[slot] & (PRESENT | USER)) != (PRESENT | USER)
            || shadow[256..].iter().any(|e| e & USER != 0)
        { return false; }
        if cfg!(feature = "ap-ring3-elf-reclaim-smoke") {
            #[cfg(feature = "ap-ring3-elf-reclaim-smoke")]
            if !reclaim_completed_ap() { return false; }
            if cfg!(feature = "ap-ring3-elf-multi-owner-smoke") {
                serial::write_fmt(format_args!(
                    "WOLFOS_AP_RING3_ELF_MULTI_REAP_OK cpus=4 target_index={} bsp_lapic={} ap_lapic={} linked_elf=1 et_exec=1 pt_load=2 ap_cpl3=1 int80=2 iret_to_cpl3=1 ap_private_cr3=1 ap_restored_boot_cr3=1 cpl0_borrowers=2 borrower_cr3_entered=2 borrower_cr3_departed=2 all_user_cr3_departed=1 cr3_flushes=3 bsp_boot_cr3=1 root_exclusive_after_departure=1 high_half_supervisor=1 boot_user_slot_empty=1 scrubbed=7 frames_freed=7 pmm_no_leak=1 stale_root_revoked=1 double_free_denied=1\n",
                    index, BSP_LAPIC.load(Ordering::Acquire),
                    TARGET_LAPIC.load(Ordering::Acquire),
                ));
            } else {
                serial::write_fmt(format_args!(
                    "WOLFOS_AP_RING3_ELF_REAP_OK cpus=4 target_index={} bsp_lapic={} ap_lapic={} linked_elf=1 et_exec=1 pt_load=2 ap_cpl3=1 int80=2 iret_to_cpl3=1 ap_private_cr3=1 ap_restored_boot_cr3=1 bsp_boot_cr3=1 root_exclusive=1 cr3_flush=1 high_half_supervisor=1 boot_user_slot_empty=1 scrubbed=7 frames_freed=7 pmm_no_leak=1 stale_root_revoked=1 double_free_denied=1\n",
                    index, BSP_LAPIC.load(Ordering::Acquire),
                    TARGET_LAPIC.load(Ordering::Acquire),
                ));
            }
        } else if cfg!(feature = "ap-ring3-elf-smoke") {
            serial::write_fmt(format_args!(
                "WOLFOS_AP_RING3_ELF_OK cpus=4 target_index={} bsp_lapic={} ap_lapic={} ap_cpl3=1 linked_elf=1 et_exec=1 pt_load=2 derived_pages=1 int80=2 iret_to_cpl3=1 private_tss_rsp0=1 actual_tr=1 ap_private_cr3=1 bsp_boot_cr3=1 kernel_supervisor_pml4=1 boot_user_slot_empty=1 ap_restored_boot_cr3=1 rx=1 rw_nx=2 frames_pinned=7\n",
                index, BSP_LAPIC.load(Ordering::Acquire),
                TARGET_LAPIC.load(Ordering::Acquire),
            ));
        } else {
            serial::write_fmt(format_args!(
                "WOLFOS_AP_RING3_PRIVATE_CR3_OK cpus=4 target_index={} bsp_lapic={} ap_lapic={} ap_cpl3=1 int80=2 iret_to_cpl3=1 private_tss_rsp0=1 actual_tr=1 ap_private_cr3=1 bsp_boot_cr3=1 kernel_supervisor_pml4=1 boot_user_slot_empty=1 ap_restored_boot_cr3=1 rx=1 rw_nx=2 frames_pinned=7\n",
                index, BSP_LAPIC.load(Ordering::Acquire),
                TARGET_LAPIC.load(Ordering::Acquire),
            ));
        }
    } else {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_RING3_OK cpus=4 target_index={} bsp_lapic={} ap_lapic={} ap_cpl3=1 int80=2 iret_to_cpl3=1 private_tss_rsp0=1 actual_tr=1 rw_nx=2 rx=1 frames_pinned=6\n",
            index, BSP_LAPIC.load(Ordering::Acquire),
            TARGET_LAPIC.load(Ordering::Acquire),
        ));
    }
    #[cfg(not(feature = "ap-ring3-elf-missing-borrower-smoke"))]
    true
}
