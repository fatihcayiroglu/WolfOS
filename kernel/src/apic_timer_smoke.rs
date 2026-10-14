//! Isolated, BSP-only xAPIC periodic-timer IRQ smoke test in QEMU.
//! NOT preemptive scheduling, a production timer driver or calibrated timekeeping.
//! APs have completed work and parked with IF=0. The BSP owns the writable
//! page-table alias and all MMIO writes. No interrupt-time allocations/logging.

use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};
use limine::memmap::Entry;
use x86_64::registers::control::Cr3;
use x86_64::structures::idt::InterruptStackFrame;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags,
    PhysFrame, Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::{lapic_irq_layout, lapic_mmio, lapic_mmio_layout, lapic_probe,
    lapic_timer_layout, lapic_timer_plan, pmm, serial};

pub const TIMER_VECTOR: u8 = 0xe0;
pub const SPURIOUS_VECTOR: u8 = 0xff;
const VIRTUAL_ADDRESS: u64 = lapic_mmio::XAPIC_TEST_VIRTUAL_ADDRESS;
const TICKS_REQUIRED: u64 = 4;
const MAX_SPINS: u64 = 300_000_000;
// The counter is intentionally NOT treated as a calibrated frequency.
const INITIAL_COUNT: u32 = 65_536;
const DIVISOR: u32 = 16;
const PIC_MASTER_DATA: u16 = 0x21;
const PIC_SLAVE_DATA: u16 = 0xa1;

static TICKS: AtomicU64 = AtomicU64::new(0);
static ACKS: AtomicU64 = AtomicU64::new(0);
static SPURIOUS: AtomicU64 = AtomicU64::new(0);

struct TableAllocator;
// SAFETY: BSP allocates unique physical page-table frames from the PMM;
// frames stay permanently owned by the active page-table tree.
unsafe impl FrameAllocator<Size4KiB> for TableAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        Some(PhysFrame::containing_address(PhysAddr::new(pmm::allocate_frame()?)))
    }
}

#[inline]
fn outb(port: u16, value: u8) {
    // SAFETY: smoke-only QEMU legacy PIC ports, BSP kernel privilege.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value,
            options(nomem, nostack, preserves_flags));
    }
}

#[inline]
fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: smoke-only QEMU legacy PIC data ports, BSP kernel privilege.
    unsafe {
        asm!("in al, dx", in("dx") port, lateout("al") value,
            options(nomem, nostack, preserves_flags));
    }
    value
}

#[inline]
unsafe fn apic_read(offset: usize) -> u32 {
    // SAFETY: caller owns the mapped writable/uncached xAPIC page,
    // checks 16-byte register alignment and stays on the BSP.
    unsafe { ((VIRTUAL_ADDRESS as usize + offset) as *const u32).read_volatile() }
}

#[inline]
unsafe fn apic_write(offset: usize, value: u32) {
    // SAFETY: caller owns the mapped writable/uncached xAPIC page.
    unsafe { ((VIRTUAL_ADDRESS as usize + offset) as *mut u32).write_volatile(value); }
}

/// The only non-spurious APIC interrupt accepted by this isolated test.
/// EOI must be written once per delivered timer interrupt, BEFORE IRETQ.
pub extern "x86-interrupt" fn irq(_frame: InterruptStackFrame) {
    TICKS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the BSP installs the fixed MMIO alias before enabling IF,
    // and disables IF before tearing it down. Only the BSP enables IRQs.
    unsafe { apic_write(lapic_irq_layout::EOI_OFFSET, lapic_irq_layout::EOI_VALUE); }
    ACKS.fetch_add(1, Ordering::Relaxed);
}

/// APIC spurious interrupt has NO in-service entry and must not receive EOI.
pub extern "x86-interrupt" fn spurious(_frame: InterruptStackFrame) {
    SPURIOUS.fetch_add(1, Ordering::Relaxed);
}

fn run_mapped_test(expected_id: u32) -> bool {
    // Enter with IF=0, and leave with IF=0 on every path.
    let plan = match lapic_timer_plan::periodic_timer_plan(
        TIMER_VECTOR, DIVISOR, INITIAL_COUNT
    ) {
        Ok(plan) => plan,
        Err(_) => return false,
    };

    // SAFETY: called only after the alias exists and is verified to point
    // to the BSP's enabled xAPIC MMIO base.
    let id = unsafe { apic_read(lapic_mmio_layout::XAPIC_ID_OFFSET) };
    let version = unsafe { apic_read(lapic_mmio_layout::XAPIC_VERSION_OFFSET) };
    if lapic_mmio_layout::decode_version(version).is_err()
        || lapic_mmio_layout::verify_identity(id, expected_id).is_err()
    {
        return false;
    }

    let original_svr = unsafe { apic_read(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET) };
    let Ok(svr) = lapic_irq_layout::enabled_svr(
        original_svr, SPURIOUS_VECTOR, TIMER_VECTOR
    ) else {
        return false;
    };
    let original_master = inb(PIC_MASTER_DATA);
    let original_slave = inb(PIC_SLAVE_DATA);
    // Mask both PICs before IF=1, so only the local APIC timer can deliver.
    outb(PIC_MASTER_DATA, 0xff);
    outb(PIC_SLAVE_DATA, 0xff);
    TICKS.store(0, Ordering::Relaxed);
    ACKS.store(0, Ordering::Relaxed);
    SPURIOUS.store(0, Ordering::Relaxed);

    // First mask the timer, then set divide/initial count. Only after
    // installing the SVR and IDT do we explicitly unmask the LVT.
    unsafe {
        apic_write(plan.preparation[0].offset, plan.preparation[0].value);
        apic_write(plan.preparation[1].offset, plan.preparation[1].value);
        apic_write(plan.preparation[2].offset, plan.preparation[2].value);
        apic_write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, svr);
        apic_write(plan.activation.offset, plan.activation.value);
    }
    serial::write_fmt(format_args!(
        "WOLFOS_APIC_TIMER_BEGIN vector={} count={} divisor={} required={}\n",
        TIMER_VECTOR, INITIAL_COUNT, DIVISOR, TICKS_REQUIRED
    ));
    x86_64::instructions::interrupts::enable();
    let mut delivered = false;
    for _ in 0..MAX_SPINS {
        if TICKS.load(Ordering::Relaxed) >= TICKS_REQUIRED {
            delivered = true;
            break;
        }
        core::hint::spin_loop();
    }
    x86_64::instructions::interrupts::disable();
    // Every timer handler has returned and EOI'd before this BSP proceeds.
    unsafe {
        apic_write(plan.mask.offset, plan.mask.value);
        apic_write(lapic_timer_layout::INITIAL_COUNT_OFFSET, 0);
        apic_write(lapic_irq_layout::SPURIOUS_VECTOR_OFFSET, original_svr);
    }
    outb(PIC_MASTER_DATA, original_master);
    outb(PIC_SLAVE_DATA, original_slave);

    let ticks = TICKS.load(Ordering::Relaxed);
    let acks = ACKS.load(Ordering::Relaxed);
    let spurious = SPURIOUS.load(Ordering::Relaxed);
    if delivered && ticks >= TICKS_REQUIRED && ticks == acks {
        serial::write_fmt(format_args!(
            "WOLFOS_APIC_TIMER_IRQ_OK vector={} ticks={} eoi={} spurious={} preemptive=0\n",
            TIMER_VECTOR, ticks, acks, spurious
        ));
        true
    } else {
        serial::write_fmt(format_args!(
            "WOLFOS_APIC_TIMER_ERROR no_irq_or_eoi ticks={} eoi={} spurious={}\n",
            ticks, acks, spurious
        ));
        false
    }
}

/// BSP only, after APs finish their one-shot smoke tasks and park.
/// No other core may enable IF while this temporary mapping exists.
pub fn verify(expected_id: u32, hhdm: u64, entries: &[&Entry]) -> bool {
    x86_64::instructions::interrupts::disable();
    let Some(base) = lapic_probe::bsp_mmio_base(expected_id) else {
        serial::write_line("WOLFOS_APIC_TIMER_ERROR no_xapic");
        return false;
    };
    if !lapic_mmio::safe_mmio_region(base, entries) {
        serial::write_line("WOLFOS_APIC_TIMER_ERROR invalid_mmio_region");
        return false;
    }

    let (cr3_frame, _) = Cr3::read();
    let Some(pml4_addr) = hhdm.checked_add(cr3_frame.start_address().as_u64())
        .and_then(|a| VirtAddr::try_new(a).ok())
    else {
        serial::write_line("WOLFOS_APIC_TIMER_ERROR bad_cr3_hhdm");
        return false;
    };
    let Ok(hhdm_addr) = VirtAddr::try_new(hhdm) else {
        serial::write_line("WOLFOS_APIC_TIMER_ERROR bad_hhdm");
        return false;
    };
    // SAFETY: the BSP is the sole page-table writer; APs completed their
    // smoke work and parked with IF=0. This unused VA was unmapped before
    // AP boot by lapic_mmio::verify_bsp.
    let pml4 = unsafe { &mut *pml4_addr.as_mut_ptr::<PageTable>() };
    let mut mapper = unsafe { OffsetPageTable::new(pml4, hhdm_addr) };
    let virtual_addr = VirtAddr::new(VIRTUAL_ADDRESS);
    if mapper.translate_addr(virtual_addr).is_some() {
        serial::write_line("WOLFOS_APIC_TIMER_ERROR slot_occupied");
        return false;
    }
    let page = Page::<Size4KiB>::containing_address(virtual_addr);
    let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(base));
    // Writable only for this short smoke, never USER_ACCESSIBLE or executable.
    // PCD/PWT keep device register accesses uncached.
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE
        | PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH
        | PageTableFlags::NO_EXECUTE;
    // SAFETY: the page is free and targets a validated device MMIO frame.
    let Ok(flush) = (unsafe { mapper.map_to(page, frame, flags, &mut TableAllocator) }) else {
        serial::write_line("WOLFOS_APIC_TIMER_ERROR map_failed");
        return false;
    };
    flush.flush();
    let correct_mapping = mapper.translate_addr(virtual_addr)
        .map(|a| a.as_u64()) == Some(base);
    let result = if correct_mapping {
        run_mapped_test(expected_id)
    } else {
        serial::write_line("WOLFOS_APIC_TIMER_ERROR map_mismatch");
        false
    };
    x86_64::instructions::interrupts::disable();
    let Ok((unmapped, flush)) = mapper.unmap(page) else {
        serial::write_line("WOLFOS_APIC_TIMER_ERROR unmap_failed");
        return false;
    };
    flush.flush();
    if unmapped.start_address().as_u64() != base ||
        mapper.translate_addr(virtual_addr).is_some()
    {
        serial::write_line("WOLFOS_APIC_TIMER_ERROR stale_mapping");
        return false;
    }
    result
}
