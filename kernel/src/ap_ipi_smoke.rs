//! Isolated 4-vCPU QEMU proof: BSP-directed xAPIC fixed IPIs.
//! BSP maps one writable uncached APIC page before AP bootstrap. Each AP
//! loads its own IDT, receives exactly three directed IPIs, EOI-acks on
//! its local APIC, then disables interrupts and parks again. No scheduler,
//! x2APIC, production device driver or page-table unmap/TLB shootdown.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use limine::{memmap::Entry, mp::MpInfo};
use x86_64::registers::control::Cr3;
use x86_64::structures::idt::InterruptStackFrame;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags,
    PhysFrame, Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};
use crate::{ipi_layout, lapic_irq_layout, lapic_mmio, lapic_probe, pmm, serial,
            smp::MAX_BOOT_CPUS};

pub const VECTOR: u8 = ipi_layout::AP_IPI_VECTOR;
pub const SPURIOUS: u8 = ipi_layout::SPURIOUS_VECTOR;
pub(crate) const VA: u64 = 0x0000_4000_0000_3000;
#[cfg(feature = "tlb-shootdown-hardware-smoke")]
pub(crate) const PROBE_VA: u64 = VA + 4096;
#[cfg(feature = "tlb-shootdown-hardware-smoke")]
pub(crate) const PROBE_A_MARKER: u64 = 0x574f_4c46_4f53_4131;
#[cfg(feature = "tlb-shootdown-hardware-smoke")]
pub(crate) const PROBE_B_MARKER: u64 = 0x574f_4c46_4f53_4232;
#[cfg(feature = "tlb-shootdown-hardware-smoke")]
static PROBE_A_FRAME: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "tlb-shootdown-hardware-smoke")]
static PROBE_B_FRAME: AtomicU64 = AtomicU64::new(0);
const TIMER_LVT: usize = 0x320;
const TIMER_MASK: u32 = 1 << 16;
const PER_AP: u64 = 3;
const WAIT_SPINS: usize = 200_000_000;
const DELIVERY_SPINS: usize = 1_000_000;
const INVALID_ID: u32 = u32::MAX;
static PREPARED: AtomicBool = AtomicBool::new(false);
static STOP: AtomicBool = AtomicBool::new(false);
static COUNT: AtomicUsize = AtomicUsize::new(0);
static BSP_ID: AtomicU32 = AtomicU32::new(INVALID_ID);
static IDS: [AtomicU32; MAX_BOOT_CPUS] =
    [const { AtomicU32::new(INVALID_ID) }; MAX_BOOT_CPUS];
static READY: [AtomicBool; MAX_BOOT_CPUS] =
    [const { AtomicBool::new(false) }; MAX_BOOT_CPUS];
static OFFLINE: [AtomicBool; MAX_BOOT_CPUS] =
    [const { AtomicBool::new(false) }; MAX_BOOT_CPUS];
static SEEN: [AtomicU64; MAX_BOOT_CPUS] =
    [const { AtomicU64::new(0) }; MAX_BOOT_CPUS];
static EOIS: [AtomicU64; MAX_BOOT_CPUS] =
    [const { AtomicU64::new(0) }; MAX_BOOT_CPUS];
static BAD: AtomicU64 = AtomicU64::new(0);
static SPURIOUS_COUNT: AtomicU64 = AtomicU64::new(0);

struct TableAllocator;
// SAFETY: BSP is the sole page-table writer before all AP bootstraps.
unsafe impl FrameAllocator<Size4KiB> for TableAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        Some(PhysFrame::containing_address(PhysAddr::new(pmm::allocate_frame()?)))
    }
}
#[cfg(feature = "tlb-shootdown-hardware-smoke")]
struct NoTableAllocator;
#[cfg(feature = "tlb-shootdown-hardware-smoke")]
unsafe impl FrameAllocator<Size4KiB> for NoTableAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> { None }
}

/// Two real PMM frames remain pinned for the entire isolated QEMU proof.
/// No AP exists yet, so the BSP can install the first probe PTE exclusively.
#[cfg(feature = "tlb-shootdown-hardware-smoke")]
fn prepare_probe_page(mapper: &mut OffsetPageTable<'_>, hhdm: u64) -> bool {
    let Some(a) = pmm::allocate_frame() else { return false; };
    let Some(b) = pmm::allocate_frame() else { return false; };
    if a == b || a == 0 || b == 0 { return false; }
    let Some(a_virtual) = hhdm.checked_add(a).and_then(|v| VirtAddr::try_new(v).ok())
    else { return false; };
    let Some(b_virtual) = hhdm.checked_add(b).and_then(|v| VirtAddr::try_new(v).ok())
    else { return false; };
    // SAFETY: exclusive allocated 4-KiB RAM frames; the HHDM gives a
    // supervisor-only mapping of each and these two words fit in one page.
    unsafe {
        a_virtual.as_mut_ptr::<u64>().write_volatile(PROBE_A_MARKER);
        b_virtual.as_mut_ptr::<u64>().write_volatile(PROBE_B_MARKER);
    }
    let va = VirtAddr::new(PROBE_VA);
    if mapper.translate_addr(va).is_some() { return false; }
    let page = Page::<Size4KiB>::containing_address(va);
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE;
    // SAFETY: fresh unused supervisor-only test VA and an exclusive PMM
    // frame. Newly allocated page-table frames stay pinned for this boot.
    let Ok(flush) = (unsafe { mapper.map_to(
        page, PhysFrame::containing_address(PhysAddr::new(a)),
        flags, &mut TableAllocator,
    ) }) else { return false; };
    flush.flush();
    if mapper.translate_addr(va).map(|p| p.as_u64()) != Some(a) {
        return false;
    }
    PROBE_A_FRAME.store(a, Ordering::Release);
    PROBE_B_FRAME.store(b, Ordering::Release);
    true
}

/// BSP-only between completed IPI epochs; each AP previously observed the
/// old PTE, and may retain its stale TLB entry until its next local INVLPG.
/// Both old and new frames stay allocated; NO hardware quiescence is inferred.
#[cfg(feature = "tlb-shootdown-hardware-smoke")]
fn remap_probe_page(hhdm: u64, target: u64) -> bool {
    if x86_64::instructions::interrupts::are_enabled() { return false; }
    let a = PROBE_A_FRAME.load(Ordering::Acquire);
    let b = PROBE_B_FRAME.load(Ordering::Acquire);
    if a == 0 || b == 0 || a == b || (target != a && target != b) {
        return false;
    }
    let expected_old = if target == b { a } else { b };
    let (cr3, _) = Cr3::read();
    let Some(pml4_virtual) = hhdm.checked_add(cr3.start_address().as_u64())
        .and_then(|v| VirtAddr::try_new(v).ok()) else { return false; };
    let Ok(hhdm_virtual) = VirtAddr::try_new(hhdm) else { return false; };
    // SAFETY: only the BSP modifies this single test PTE, with IF=0.
    // APs are alive but do not access the probe except inside directed IPI
    // handlers; no IPI is sent until this remap is fully published.
    let table = unsafe { &mut *pml4_virtual.as_mut_ptr::<PageTable>() };
    let mut mapper = unsafe { OffsetPageTable::new(table, hhdm_virtual) };
    let va = VirtAddr::new(PROBE_VA);
    let page = Page::<Size4KiB>::containing_address(va);
    let Ok((old, flush)) = mapper.unmap(page) else { return false; };
    flush.flush();
    if old.start_address().as_u64() != expected_old { return false; }
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE;
    // SAFETY: exact formerly-owned test VA, target is the other pinned
    // unique PMM frame. No new paging hierarchy may be allocated.
    let Ok(flush) = (unsafe { mapper.map_to(
        page, PhysFrame::containing_address(PhysAddr::new(target)),
        flags, &mut NoTableAllocator,
    ) }) else { return false; };
    flush.flush();
    mapper.translate_addr(va).map(|p| p.as_u64()) == Some(target)
}

#[inline]
pub(crate) unsafe fn read(offset: usize) -> u32 {
    unsafe { ((VA as usize + offset) as *const u32).read_volatile() }
}
#[inline]
pub(crate) unsafe fn write(offset: usize, value: u32) {
    unsafe { ((VA as usize + offset) as *mut u32).write_volatile(value) }
}
pub(crate) fn local_id() -> u32 {
    (unsafe { read(ipi_layout::APIC_ID_OFFSET) } >> 24) & 0xff
}
pub(crate) fn ap_slot(id: u32) -> Option<usize> {
    let count = COUNT.load(Ordering::Acquire);
    if id == BSP_ID.load(Ordering::Relaxed) || count > MAX_BOOT_CPUS {
        return None;
    }
    (0..count).find(|i| IDS[*i].load(Ordering::Relaxed) == id)
}

/// Read-only BSP observation after an AP publishes its offline state.
#[cfg(any(feature = "ap-local-timer-smoke", feature = "ap-smp-preempt-smoke",
           feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
pub(crate) fn is_offline(index: usize) -> bool {
    index < MAX_BOOT_CPUS && OFFLINE[index].load(Ordering::Acquire)
}
/// Reject any accidental directed IPI or spurious APIC interrupt during
/// the standalone AP-local periodic timer test.
#[cfg(any(feature = "ap-local-timer-smoke", feature = "ap-smp-preempt-smoke",
           feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
pub(crate) fn ipi_count() -> u64 {
    (0..COUNT.load(Ordering::Acquire))
        .map(|i| SEEN[i].load(Ordering::Acquire))
        .sum()
}
#[cfg(any(feature = "ap-local-timer-smoke", feature = "ap-smp-preempt-smoke",
           feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
pub(crate) fn spurious_count() -> u64 {
    SPURIOUS_COUNT.load(Ordering::Acquire)
}

#[cfg(any(feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
pub(crate) fn ipi_received(index: usize) -> u64 {
    if index < MAX_BOOT_CPUS { SEEN[index].load(Ordering::Acquire) } else { 0 }
}
#[cfg(any(feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
pub(crate) fn ipi_eois(index: usize) -> u64 {
    if index < MAX_BOOT_CPUS { EOIS[index].load(Ordering::Acquire) } else { 0 }
}
#[cfg(any(feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
pub(crate) fn bad_count() -> u64 { BAD.load(Ordering::Acquire) }

/// Called on receiving AP, by its independent IDT and with IF=0. No
/// serial output, heap allocation or BSP context is touched here.
pub extern "x86-interrupt" fn irq(_frame: InterruptStackFrame) {
    let slot = ap_slot(local_id());
    if let Some(i) = slot {
        #[cfg(feature = "tlb-shootdown-hardware-smoke")]
        crate::tlb_shootdown_hardware_smoke::on_ipi(i);
        #[cfg(feature = "ap-remote-work-smoke")]
        crate::ap_remote_work_smoke::on_ipi(i);
        #[cfg(feature = "ap-handoff-smoke")]
        crate::ap_handoff_smoke::on_ipi(i);
        #[cfg(feature = "ap-stack-migrate-smoke")]
        crate::ap_stack_migrate_smoke::on_ipi(i);
        #[cfg(feature = "ap-irq-migrate-smoke")]
        crate::ap_irq_migrate_smoke::on_ipi(i);
        #[cfg(feature = "ap-runqueue-smoke")]
        crate::ap_runqueue_smoke::on_ipi(i);
        SEEN[i].fetch_add(1, Ordering::Relaxed);
    } else {
        BAD.fetch_add(1, Ordering::Relaxed);
    }
    // SAFETY: the directed FIXED IPI creates an in-service entry on this
    // processor; exactly one local EOI must precede interrupt return.
    unsafe { write(lapic_irq_layout::EOI_OFFSET, 0); }
    if let Some(i) = slot {
        EOIS[i].fetch_add(1, Ordering::Release);
    }
}
/// Unlike a fixed IPI, spurious interrupt has no in-service entry.
pub extern "x86-interrupt" fn spurious(_frame: InterruptStackFrame) {
    SPURIOUS_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// BSP IF=0, BEFORE releasing any AP. One shared UC MMIO mapping is
/// intentionally kept until QEMU smoke exit, avoiding AP TLB shootdowns.
pub fn prepare_bsp(bsp_id: u32, hhdm: u64, entries: &[&Entry], cpus: &[&MpInfo]) -> bool {
    if x86_64::instructions::interrupts::are_enabled()
        || PREPARED.load(Ordering::Acquire)
        || cpus.len() < 2 || cpus.len() > MAX_BOOT_CPUS || bsp_id > 255
        || cpus.iter().filter(|c| c.lapic_id == bsp_id).count() != 1
    {
        return false;
    }
    for (i, cpu) in cpus.iter().enumerate() {
        if cpu.lapic_id > 255 || cpus[..i].iter().any(|c| c.lapic_id == cpu.lapic_id) {
            return false;
        }
    }
    let Some(base) = lapic_probe::bsp_mmio_base(bsp_id) else { return false; };
    if !lapic_mmio::safe_mmio_region(base, entries) { return false; }
    let (cr3, _) = Cr3::read();
    let Some(pml4) = hhdm.checked_add(cr3.start_address().as_u64())
        .and_then(|a| VirtAddr::try_new(a).ok()) else { return false; };
    let Ok(hhdm_va) = VirtAddr::try_new(hhdm) else { return false; };
    // SAFETY: exclusive page-table access on BSP with APs not yet started.
    let table = unsafe { &mut *pml4.as_mut_ptr::<PageTable>() };
    let mut mapper = unsafe { OffsetPageTable::new(table, hhdm_va) };
    let address = VirtAddr::new(VA);
    if mapper.translate_addr(address).is_some() { return false; }
    let page = Page::<Size4KiB>::containing_address(address);
    let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(base));
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE
        | PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH
        | PageTableFlags::NO_EXECUTE;
    // SAFETY: page is unused and base from enabled xAPIC MSR was checked
    // not to overlap any managed RAM or reserved firmware allocation.
    let Ok(flush) = (unsafe { mapper.map_to(page, frame, flags, &mut TableAllocator) })
    else { return false; };
    flush.flush();
    if mapper.translate_addr(address).map(|a| a.as_u64()) != Some(base)
        || local_id() != bsp_id { return false; }
    #[cfg(feature = "tlb-shootdown-hardware-smoke")]
    if !prepare_probe_page(&mut mapper, hhdm) { return false; }
    for (i, cpu) in cpus.iter().enumerate() {
        IDS[i].store(cpu.lapic_id, Ordering::Relaxed);
        READY[i].store(false, Ordering::Relaxed);
        OFFLINE[i].store(false, Ordering::Relaxed);
        SEEN[i].store(0, Ordering::Relaxed);
        EOIS[i].store(0, Ordering::Relaxed);
    }
    COUNT.store(cpus.len(), Ordering::Relaxed);
    BSP_ID.store(bsp_id, Ordering::Relaxed);
    STOP.store(false, Ordering::Relaxed);
    PREPARED.store(true, Ordering::Release);
    true
}

/// AP-only: after CPU work and private IDT setup, enable its local APIC
/// software bit and mask its timer. IF=1 solely to accept directed IPIs.
pub fn secondary_wait(index: usize, expected_id: u32) -> bool {
    if !PREPARED.load(Ordering::Acquire)
        || index >= COUNT.load(Ordering::Acquire)
        || IDS[index].load(Ordering::Relaxed) != expected_id
        || expected_id == BSP_ID.load(Ordering::Relaxed)
        || x86_64::instructions::interrupts::are_enabled()
        || local_id() != expected_id { return false; }
    let old_svr = unsafe { read(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET) };
    let old_timer = unsafe { read(TIMER_LVT) };
    let Ok(enabled) = lapic_irq_layout::enabled_svr(old_svr, SPURIOUS, VECTOR)
    else { return false; };
    // SAFETY: AP writes only ITS OWN local APIC through a preinstalled UC VA.
    unsafe {
        write(TIMER_LVT, old_timer | TIMER_MASK);
        write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, enabled);
    }
    #[cfg(feature = "ap-irq-migrate-smoke")]
    {
        // On this AP only, local timer captures FULL IRQ frame + x87/SSE
        // state and escapes to its coordinator. Later APs resume by IRETQ.
        let result = crate::ap_irq_migrate_smoke::secondary_run(index);
        x86_64::instructions::interrupts::disable();
        unsafe {
            write(TIMER_LVT, old_timer | TIMER_MASK);
            write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, old_svr);
        }
        OFFLINE[index].store(true, Ordering::Release);
        return result;
    }
    #[cfg(feature = "ap-stack-migrate-smoke")]
    {
        // Resume a single REAL kernel stack on the new AP after the IPI
        // claim returns. The old AP must have saved its RSP and FX state.
        let result = crate::ap_stack_migrate_smoke::secondary_run(index);
        x86_64::instructions::interrupts::disable();
        unsafe {
            write(TIMER_LVT, old_timer | TIMER_MASK);
            write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, old_svr);
        }
        OFFLINE[index].store(true, Ordering::Release);
        return result;
    }
    #[cfg(feature = "ap-handoff-smoke")]
    {
        // Claim a directed IPI inside AP's own IDT, but run the
        // quiesced logical continuation only AFTER returning from IRQ.
        let result = crate::ap_handoff_smoke::secondary_run(index);
        x86_64::instructions::interrupts::disable();
        unsafe {
            write(TIMER_LVT, old_timer | TIMER_MASK);
            write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, old_svr);
        }
        OFFLINE[index].store(true, Ordering::Release);
        return result;
    }
    #[cfg(feature = "ap-runqueue-smoke")]
    {
        // One directed IPI wakes a bounded four-job AP-local FIFO wave.
        // All work executes after IRETQ on that AP's own kernel stack.
        let result = crate::ap_runqueue_smoke::secondary_run(index);
        x86_64::instructions::interrupts::disable();
        unsafe {
            write(TIMER_LVT, old_timer | TIMER_MASK);
            write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, old_svr);
        }
        OFFLINE[index].store(true, Ordering::Release);
        return result;
    }
    #[cfg(feature = "ap-remote-work-smoke")]
    {
        // Hardware IPI IRQ only claims one CPU-owned mailbox; this AP runs
        // the new work AFTER IRETQ, on its ordinary permanent MP stack.
        let result = crate::ap_remote_work_smoke::secondary_run(index);
        x86_64::instructions::interrupts::disable();
        unsafe {
            write(TIMER_LVT, old_timer | TIMER_MASK);
            write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, old_svr);
        }
        OFFLINE[index].store(true, Ordering::Release);
        return result;
    }
    #[cfg(feature = "ap-smp-preempt-smoke")]
    {
        // Timer-driven task switching stays strictly on this AP. The outer
        // MP worker/coordinator returns only after its two tasks stop with
        // IF=0 and restore their private FXSAVE64 context.
        let result = crate::ap_smp_preempt_smoke::secondary_run(index);
        x86_64::instructions::interrupts::disable();
        unsafe {
            write(TIMER_LVT, old_timer | TIMER_MASK);
            write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, old_svr);
        }
        OFFLINE[index].store(true, Ordering::Release);
        return result;
    }
    #[cfg(feature = "ap-local-timer-smoke")]
    {
        // The AP-only timer proof controls IF, its own SVR/LVT/divide/count,
        // masks+stops its timer and reparks. It deliberately sends NO IPI.
        // The caller already masked the original AP timer and enabled SVR.
        let result = crate::ap_local_timer_smoke::secondary_run(index);
        x86_64::instructions::interrupts::disable();
        unsafe {
            write(TIMER_LVT, old_timer | TIMER_MASK);
            write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, old_svr);
        }
        OFFLINE[index].store(true, Ordering::Release);
        return result;
    }
    #[cfg(not(any(feature = "ap-local-timer-smoke", feature = "ap-smp-preempt-smoke",
               feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke")))]
    x86_64::instructions::interrupts::enable();
    #[cfg(not(any(feature = "ap-local-timer-smoke", feature = "ap-smp-preempt-smoke",
               feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke")))]
    READY[index].store(true, Ordering::Release);
    #[cfg(not(any(feature = "ap-local-timer-smoke", feature = "ap-smp-preempt-smoke",
               feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke")))]
    {
        // Spin rather than HLT to avoid a lost STOP wake-up race.
        while !STOP.load(Ordering::Acquire) { core::hint::spin_loop(); }
        x86_64::instructions::interrupts::disable();
        unsafe {
            write(TIMER_LVT, old_timer);
            write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, old_svr);
        }
        OFFLINE[index].store(true, Ordering::Release);
        true
    }
}
fn wait(mut f: impl FnMut() -> bool, limit: usize) -> bool {
    for _ in 0..limit {
        if f() { return true; }
        core::hint::spin_loop();
    }
    f()
}
fn icr_idle() -> bool {
    wait(|| unsafe { read(ipi_layout::ICR_LOW_OFFSET) }
        & ipi_layout::DELIVERY_PENDING == 0, DELIVERY_SPINS)
}
pub(crate) fn send(bsp: u32, target: u32) -> bool {
    if !icr_idle() { return false; }
    let icr = unsafe { read(ipi_layout::ICR_LOW_OFFSET) };
    let Ok(plan) = ipi_layout::directed_fixed_ipi(bsp, target, VECTOR, icr)
    else { return false; };
    // SAFETY: only BSP writes its ICR, IF=0. High destination is written
    // BEFORE low word triggers a physical fixed directed IPI.
    unsafe {
        write(ipi_layout::ICR_HIGH_OFFSET, plan.high);
        write(ipi_layout::ICR_LOW_OFFSET, plan.low);
    }
    icr_idle()
}

/// BSP IF=0, after smp::boot_aps() and all previously tested AP work.
pub fn verify_bsp(bsp_id: u32, cpus: &[&MpInfo]) -> bool {
    if !PREPARED.load(Ordering::Acquire)
        || x86_64::instructions::interrupts::are_enabled()
        || COUNT.load(Ordering::Acquire) != cpus.len()
        || local_id() != bsp_id { return false; }
    if !wait(|| cpus.iter().enumerate().all(|(i,c)|
        c.lapic_id == bsp_id || READY[i].load(Ordering::Acquire)
    ), WAIT_SPINS) {
        STOP.store(true, Ordering::Release);
        return false;
    }
    let old_svr = unsafe { read(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET) };
    let Ok(enabled) = lapic_irq_layout::enabled_svr(old_svr, SPURIOUS, VECTOR)
    else {
        STOP.store(true, Ordering::Release);
        return false;
    };
    unsafe { write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, enabled); }
    let mut sends = 0u64;
    let mut good = true;
    'outer: for round in 1..=PER_AP {
        for (i, cpu) in cpus.iter().enumerate() {
            if cpu.lapic_id == bsp_id { continue; }
            if !send(bsp_id, cpu.lapic_id) {
                good = false;
                break 'outer;
            }
            sends += 1;
            if !wait(|| EOIS[i].load(Ordering::Acquire) >= round, WAIT_SPINS)
                || SEEN[i].load(Ordering::Acquire) != round
                || EOIS[i].load(Ordering::Acquire) != round
            {
                good = false;
                break 'outer;
            }
        }
    }
    unsafe { write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, old_svr); }
    STOP.store(true, Ordering::Release);
    let offline = wait(|| cpus.iter().enumerate().all(|(i,c)|
        c.lapic_id == bsp_id || OFFLINE[i].load(Ordering::Acquire)
    ), WAIT_SPINS);
    let (mut received, mut eois) = (0u64, 0u64);
    for (i,c) in cpus.iter().enumerate() {
        if c.lapic_id == bsp_id { continue; }
        received += SEEN[i].load(Ordering::Acquire);
        eois += EOIS[i].load(Ordering::Acquire);
        if SEEN[i].load(Ordering::Acquire) != PER_AP
            || EOIS[i].load(Ordering::Acquire) != PER_AP { good = false; }
    }
    let aps = cpus.len() - 1;
    let bad = BAD.load(Ordering::Acquire);
    let spurious = SPURIOUS_COUNT.load(Ordering::Acquire);
    if good && offline && sends == aps as u64 * PER_AP
        && received == sends && eois == sends && bad == 0 && spurious == 0
    {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_IPI_OK cpus={} aps={} per_ap={} sends={} received={} eois={} bad={} spurious={} offline={} vector={} bsp_if=0\n",
            cpus.len(), aps, PER_AP, sends, received, eois, bad, spurious,
            aps, VECTOR,
        ));
        true
    } else {
        serial::write_fmt(format_args!(
            "WOLFOS_AP_IPI_ERROR cpus={} aps={} sends={} received={} eois={} bad={} spurious={} offline={} good={}\n",
            cpus.len(), aps, sends, received, eois, bad, spurious, offline, good,
        ));
        false
    }
}

/// Three genuine four-CPU IPI epochs. The last AP is deliberately withheld
/// in epoch 3 to prove the barrier cannot complete or begin a new epoch.
/// Every actual acknowledgement follows recipient-local INVLPG.
#[cfg(feature = "tlb-shootdown-hardware-smoke")]
pub fn verify_tlb_shootdown_bsp(bsp_id: u32, cpus: &[&MpInfo], hhdm: u64) -> bool {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    use crate::tlb_shootdown_hardware_smoke as hw;

    if !PREPARED.load(Ordering::Acquire)
        || x86_64::instructions::interrupts::are_enabled()
        || COUNT.load(Ordering::Acquire) != 4 || cpus.len() != 4
        || local_id() != bsp_id || Cr4::read().contains(Cr4Flags::PCID)
    { return false; }
    if !wait(|| cpus.iter().enumerate().all(|(i, cpu)|
        cpu.lapic_id == bsp_id || READY[i].load(Ordering::Acquire)
    ), WAIT_SPINS) {
        STOP.store(true, Ordering::Release);
        return false;
    }

    let mut targets = 0u64;
    for (i, cpu) in cpus.iter().enumerate() {
        if cpu.lapic_id != bsp_id { targets |= 1u64 << i; }
    }
    let (root, _) = Cr3::read();
    if !hw::arm(targets, root.start_address().as_u64()) {
        STOP.store(true, Ordering::Release);
        return false;
    }

    let old_svr = unsafe { read(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET) };
    let Ok(enabled) = lapic_irq_layout::enabled_svr(old_svr, SPURIOUS, VECTOR)
    else {
        STOP.store(true, Ordering::Release);
        return false;
    };
    unsafe { write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, enabled); }
    let mut good = true;
    let mut sends = 0u64;
    let mut withheld_verified = false;
    'rounds: for round in 1..=3u64 {
        if hw::completed() { good = false; break; }
        let mut sent_this_round = 0u64;
        for (i, cpu) in cpus.iter().enumerate() {
            if cpu.lapic_id == bsp_id { continue; }
            if round == 3 && sent_this_round == 2 {
                // No IPI has been sent to this final AP yet. A missing
                // hardware ack must leave its exact target bit pending and
                // prevent the coordinator from beginning another epoch.
                let Some(before) = hw::evidence() else {
                    good = false;
                    break 'rounds;
                };
                let missing = 1u64 << i;
                if before.epoch != 3 || before.pending != missing
                    || before.completed || before.acks != 8
                    || before.invlpg != 8 || before.probe_invlpg != 8
                    || before.probe_reads != 8 || before.per_cpu[i] != 2
                    || hw::begin_next() || hw::completed()
                {
                    good = false;
                    break 'rounds;
                }
                let Some(after) = hw::evidence() else {
                    good = false;
                    break 'rounds;
                };
                if after.epoch != before.epoch || after.pending != missing
                    || after.acks != before.acks || after.invlpg != before.invlpg
                {
                    good = false;
                    break 'rounds;
                }
                withheld_verified = true;
            }
            if !send(bsp_id, cpu.lapic_id) {
                good = false;
                break 'rounds;
            }
            sends += 1;
            sent_this_round += 1;
            if !wait(|| EOIS[i].load(Ordering::Acquire) >= round, WAIT_SPINS)
                || SEEN[i].load(Ordering::Acquire) != round
                || EOIS[i].load(Ordering::Acquire) != round
                || hw::completed() != (sent_this_round == 3)
            {
                good = false;
                break 'rounds;
            }
        }
        if !hw::completed() { good = false; break; }
        if round < 3 {
            let target = if round == 1 {
                PROBE_B_FRAME.load(Ordering::Acquire)
            } else {
                PROBE_A_FRAME.load(Ordering::Acquire)
            };
            if !remap_probe_page(hhdm, target) || !hw::begin_next() {
                good = false;
                break;
            }
        }
    }
    unsafe { write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, old_svr); }
    STOP.store(true, Ordering::Release);
    let offline = wait(|| cpus.iter().enumerate().all(|(i, cpu)|
        cpu.lapic_id == bsp_id || OFFLINE[i].load(Ordering::Acquire)
    ), WAIT_SPINS);
    let mut received = 0u64;
    let mut eois = 0u64;
    let mut per_ap_ok = true;
    for (i, cpu) in cpus.iter().enumerate() {
        if cpu.lapic_id == bsp_id { continue; }
        received += SEEN[i].load(Ordering::Acquire);
        eois += EOIS[i].load(Ordering::Acquire);
        if SEEN[i].load(Ordering::Acquire) != 3
            || EOIS[i].load(Ordering::Acquire) != 3
        { per_ap_ok = false; }
    }
    let bad = BAD.load(Ordering::Acquire);
    let spurious = SPURIOUS_COUNT.load(Ordering::Acquire);
    let Some(e) = hw::evidence() else { return false; };
    let flush_ok = cpus.iter().enumerate().all(|(i,cpu)|
        e.per_cpu[i] == if cpu.lapic_id == bsp_id { 0 } else { 3 }
    );
    if good && offline && per_ap_ok && flush_ok && withheld_verified
        && sends == 9 && received == 9 && eois == 9
        && e.acks == 9 && e.invlpg == 9
        && e.probe_invlpg == 9 && e.probe_reads == 9
        && e.epoch == 3 && e.targets == targets && e.pending == 0
        && e.completed && !e.bad && bad == 0 && spurious == 0
    {
        serial::write_fmt(format_args!(
            "WOLFOS_TLB_SHOOTDOWN_HW_OK cpus=4 aps=3 rounds=3 sends=9 invlpg=9 acks=9 eois=9 bad=0 spurious=0 offline=3 epoch=3 pending=0 withheld=1 blocked=1 pcid=0 freed=0 remaps=2 probe_invlpg=9 probe_reads=9\n"
        ));
        true
    } else {
        serial::write_fmt(format_args!(
            "WOLFOS_TLB_SHOOTDOWN_HW_ERROR good={} offline={} per_ap={} flush_ok={} withheld={} sends={} seen={} eois={} acks={} invlpg={} probe_invlpg={} probe_reads={} epoch={} pending={} completed={} bad={} gate_bad={} spurious={}\n",
            good, offline, per_ap_ok, flush_ok, withheld_verified, sends, received, eois,
            e.acks, e.invlpg, e.probe_invlpg, e.probe_reads, e.epoch,
            e.pending, e.completed, bad, e.bad, spurious,
        ));
        false
    }
}
