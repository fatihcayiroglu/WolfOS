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
const VA: u64 = 0x0000_4000_0000_3000;
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
           feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke"))]
pub(crate) fn is_offline(index: usize) -> bool {
    index < MAX_BOOT_CPUS && OFFLINE[index].load(Ordering::Acquire)
}
/// Reject any accidental directed IPI or spurious APIC interrupt during
/// the standalone AP-local periodic timer test.
#[cfg(any(feature = "ap-local-timer-smoke", feature = "ap-smp-preempt-smoke",
           feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke"))]
pub(crate) fn ipi_count() -> u64 {
    (0..COUNT.load(Ordering::Acquire))
        .map(|i| SEEN[i].load(Ordering::Acquire))
        .sum()
}
#[cfg(any(feature = "ap-local-timer-smoke", feature = "ap-smp-preempt-smoke",
           feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke"))]
pub(crate) fn spurious_count() -> u64 {
    SPURIOUS_COUNT.load(Ordering::Acquire)
}

#[cfg(any(feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke"))]
pub(crate) fn ipi_received(index: usize) -> u64 {
    if index < MAX_BOOT_CPUS { SEEN[index].load(Ordering::Acquire) } else { 0 }
}
#[cfg(any(feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke"))]
pub(crate) fn ipi_eois(index: usize) -> u64 {
    if index < MAX_BOOT_CPUS { EOIS[index].load(Ordering::Acquire) } else { 0 }
}
#[cfg(any(feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke"))]
pub(crate) fn bad_count() -> u64 { BAD.load(Ordering::Acquire) }

/// Called on receiving AP, by its independent IDT and with IF=0. No
/// serial output, heap allocation or BSP context is touched here.
pub extern "x86-interrupt" fn irq(_frame: InterruptStackFrame) {
    let slot = ap_slot(local_id());
    if let Some(i) = slot {
        #[cfg(feature = "ap-remote-work-smoke")]
        crate::ap_remote_work_smoke::on_ipi(i);
        #[cfg(feature = "ap-handoff-smoke")]
        crate::ap_handoff_smoke::on_ipi(i);
        #[cfg(feature = "ap-stack-migrate-smoke")]
        crate::ap_stack_migrate_smoke::on_ipi(i);
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
               feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke")))]
    x86_64::instructions::interrupts::enable();
    #[cfg(not(any(feature = "ap-local-timer-smoke", feature = "ap-smp-preempt-smoke",
               feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke")))]
    READY[index].store(true, Ordering::Release);
    #[cfg(not(any(feature = "ap-local-timer-smoke", feature = "ap-smp-preempt-smoke",
               feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke")))]
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
