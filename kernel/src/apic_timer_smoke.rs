//! Isolated, BSP-only xAPIC periodic-timer IRQ smoke test in QEMU.
//! NOT preemptive scheduling, a production timer driver or calibrated timekeeping.
//! APs have completed work and parked with IF=0. The BSP owns the writable
//! page-table alias and all MMIO writes. No interrupt-time allocations/logging.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use limine::memmap::Entry;
use x86_64::registers::control::Cr3;
use x86_64::structures::idt::InterruptStackFrame;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags,
    PhysFrame, Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::{lapic_irq_layout, lapic_mmio, lapic_mmio_layout, lapic_probe,
    lapic_timer_layout, lapic_timer_plan, irq_frame_observation, pmm, serial};

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

#[cfg(feature = "apic-calibration-smoke")]
const PIT_CLOCK_HZ: u64 = 1_193_182;
#[cfg(feature = "apic-calibration-smoke")]
const PIT_CHANNEL2: u16 = 0x42;
#[cfg(feature = "apic-calibration-smoke")]
const PIT_COMMAND: u16 = 0x43;
#[cfg(feature = "apic-calibration-smoke")]
const SPEAKER_CONTROL: u16 = 0x61;
#[cfg(feature = "apic-calibration-smoke")]
const PIT_INTERVAL_TICKS: u16 = 23_864; // approximately 20 ms; not a precision clock
#[cfg(feature = "apic-calibration-smoke")]
const CALIBRATION_MAX_SPINS: u64 = 300_000_000;

static TICKS: AtomicU64 = AtomicU64::new(0);
static ACKS: AtomicU64 = AtomicU64::new(0);
static SPURIOUS: AtomicU64 = AtomicU64::new(0);

// Read-only first-IRQ observations of non-yielding BSP work; NOT a saved task
// context. GPR/SIMD, CR3, TLS and FPU state are deliberately NOT captured.
static BUSY_ACTIVE: AtomicBool = AtomicBool::new(false);
static BUSY_STEPS: AtomicU64 = AtomicU64::new(0);
static BUSY_STEPS_AT_IRQ: AtomicU64 = AtomicU64::new(0);
static BUSY_IRQS: AtomicU64 = AtomicU64::new(0);
static BUSY_RIP: AtomicU64 = AtomicU64::new(0);
static BUSY_RSP: AtomicU64 = AtomicU64::new(0);
static BUSY_CS: AtomicU64 = AtomicU64::new(0);
static BUSY_RFLAGS: AtomicU64 = AtomicU64::new(0);


/// IRQ-published BSP epoch; read by a worker with IRQs enabled.
/// No timer frequency or wall-clock accuracy is implied.
pub fn ticks() -> u64 { TICKS.load(Ordering::Relaxed) }

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
pub extern "x86-interrupt" fn irq(frame: InterruptStackFrame) {
    // Single BSP: capture architectural fields as values, never retain a
    // reference to the transient interrupt frame or switch stacks here.
    if BUSY_ACTIVE.load(Ordering::Relaxed) {
        if BUSY_IRQS.load(Ordering::Relaxed) == 0 {
            BUSY_RIP.store(frame.instruction_pointer.as_u64(), Ordering::Relaxed);
            BUSY_RSP.store(frame.stack_pointer.as_u64(), Ordering::Relaxed);
            BUSY_CS.store(frame.code_segment, Ordering::Relaxed);
            BUSY_RFLAGS.store(frame.cpu_flags, Ordering::Relaxed);
            BUSY_STEPS_AT_IRQ.store(BUSY_STEPS.load(Ordering::Relaxed), Ordering::Relaxed);
        }
        BUSY_IRQS.fetch_add(1, Ordering::Relaxed);
    }
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

#[cfg(feature = "apic-calibration-smoke")]
fn pit2_calibrated_initial_count() -> Option<(u64, u32)> {
    use crate::lapic_timer_calibration;
    use lapic_timer_layout::TimerMode;

    // Channel 2 PIT runs independently of IRQ0. The CPU IF flag remains off.
    // Use a bounded poll of PIT OUT2 to measure one hardware countdown.
    let masked_oneshot = lapic_timer_layout::make_lvt(
        TIMER_VECTOR, true, TimerMode::OneShot
    ).ok()?;
    let divisor = lapic_timer_layout::encode_divisor(DIVISOR).ok()?;
    let old_speaker = inb(SPEAKER_CONTROL);
    // Gate low and disable the speaker before configuring channel 2.
    outb(SPEAKER_CONTROL, old_speaker & !0x03);
    // PIT 8254: channel 2, low/high bytes, interrupt-on-terminal-count.
    outb(PIT_COMMAND, 0xb0);
    outb(PIT_CHANNEL2, PIT_INTERVAL_TICKS as u8);
    outb(PIT_CHANNEL2, (PIT_INTERVAL_TICKS >> 8) as u8);
    // Verify that the OUT2 signal starts low rather than accepting a stale
    // high bit as a completed reference interval.
    if inb(SPEAKER_CONTROL) & 0x20 != 0 {
        outb(SPEAKER_CONTROL, old_speaker);
        return None;
    }
    unsafe {
        apic_write(lapic_timer_layout::LVT_TIMER_OFFSET, masked_oneshot);
        apic_write(lapic_timer_layout::DIVIDE_CONFIG_OFFSET, divisor);
        apic_write(lapic_timer_layout::INITIAL_COUNT_OFFSET, u32::MAX);
    }
    let start = unsafe { apic_read(lapic_timer_layout::CURRENT_COUNT_OFFSET) };
    outb(SPEAKER_CONTROL, (old_speaker & !0x03) | 0x01);
    let mut terminal_count = false;
    for _ in 0..CALIBRATION_MAX_SPINS {
        if inb(SPEAKER_CONTROL) & 0x20 != 0 {
            terminal_count = true;
            break;
        }
        core::hint::spin_loop();
    }
    let end = unsafe { apic_read(lapic_timer_layout::CURRENT_COUNT_OFFSET) };
    outb(SPEAKER_CONTROL, old_speaker);
    unsafe { apic_write(lapic_timer_layout::INITIAL_COUNT_OFFSET, 0); }
    if !terminal_count {
        return None;
    }
    let delta = start.checked_sub(end)?;
    let effective_hz = lapic_timer_calibration::effective_ticks_per_second(
        delta, u64::from(PIT_INTERVAL_TICKS), PIT_CLOCK_HZ
    ).ok()?;
    let initial_count = lapic_timer_calibration::periodic_initial_count(
        effective_hz, 100
    ).ok()?;
    // Reject obvious broken observations, but do not claim PIT-level
    // precision, platform stability or a production clocksource.
    if !(1_000..=1_000_000_000).contains(&effective_hz) {
        return None;
    }
    Some((effective_hz, initial_count))
}

/// No task yields here. A real BSP local-APIC interrupt observes the
/// running function, EOIs and returns to the same frame via hardware IRETQ.
/// Enters with IF=1; exits with IF=0, including on timeout.
#[inline(never)]
fn prove_read_only_interrupt_frame() -> bool {
    if !x86_64::instructions::interrupts::are_enabled() { return false; }
    BUSY_STEPS.store(1, Ordering::Relaxed);
    BUSY_ACTIVE.store(true, Ordering::Relaxed);
    for _ in 0..MAX_SPINS {
        BUSY_STEPS.fetch_add(1, Ordering::Relaxed);
        if BUSY_IRQS.load(Ordering::Relaxed) >= TICKS_REQUIRED { break; }
        core::hint::spin_loop();
    }
    BUSY_ACTIVE.store(false, Ordering::Relaxed);
    x86_64::instructions::interrupts::disable();
    let busy_irqs = BUSY_IRQS.load(Ordering::Relaxed);
    let steps = BUSY_STEPS.load(Ordering::Relaxed);
    let irq_step = BUSY_STEPS_AT_IRQ.load(Ordering::Relaxed);
    let rip = BUSY_RIP.load(Ordering::Relaxed);
    let rsp = BUSY_RSP.load(Ordering::Relaxed);
    let cs = BUSY_CS.load(Ordering::Relaxed);
    let rflags = BUSY_RFLAGS.load(Ordering::Relaxed);
    let frame = irq_frame_observation::validate_kernel_irq_frame(rip, rsp, cs, rflags);
    let ok = busy_irqs >= TICKS_REQUIRED && irq_step > 0
        && steps > irq_step && frame.is_ok();
    if ok {
        serial::write_fmt(format_args!(
            "WOLFOS_APIC_IRQ_FRAME_OK busy_irqs={} work_steps={} irq_step={} rip={:#x} rsp={:#x} cs={:#x} rflags={:#x} preemptive=0\n",
            busy_irqs, steps, irq_step, rip, rsp, cs, rflags
        ));
    } else {
        serial::write_fmt(format_args!(
            "WOLFOS_APIC_IRQ_FRAME_ERROR busy_irqs={} work_steps={} irq_step={} frame={:?}\n",
            busy_irqs, steps, irq_step, frame.err()
        ));
    }
    ok
}

fn run_mapped_test(expected_id: u32) -> bool {
    // Enter with IF=0, and leave with IF=0 on every path.
    // SAFETY: called only after the alias exists and is verified to point
    // to the BSP's enabled xAPIC MMIO base.
    let id = unsafe { apic_read(lapic_mmio_layout::XAPIC_ID_OFFSET) };
    let version = unsafe { apic_read(lapic_mmio_layout::XAPIC_VERSION_OFFSET) };
    if lapic_mmio_layout::decode_version(version).is_err()
        || lapic_mmio_layout::verify_identity(id, expected_id).is_err()
    {
        return false;
    }

    #[cfg(feature = "apic-calibration-smoke")]
    let (effective_hz, initial_count) = match pit2_calibrated_initial_count() {
        Some(measurement) => measurement,
        None => {
            serial::write_line("WOLFOS_APIC_CALIBRATION_ERROR pit2_measurement_failed");
            return false;
        }
    };
    #[cfg(not(feature = "apic-calibration-smoke"))]
    let initial_count = INITIAL_COUNT;
    let plan = match lapic_timer_plan::periodic_timer_plan(
        TIMER_VECTOR, DIVISOR, initial_count
    ) {
        Ok(plan) => plan,
        Err(_) => return false,
    };
    #[cfg(feature = "apic-calibration-smoke")]
    serial::write_fmt(format_args!(
        "WOLFOS_APIC_CALIBRATION_OK effective_hz={} initial_count={} pit_hz={} pit_ticks={} divisor={} target_hz=100\n",
        effective_hz, initial_count, PIT_CLOCK_HZ, PIT_INTERVAL_TICKS, DIVISOR
    ));

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
    BUSY_ACTIVE.store(false, Ordering::Relaxed);
    BUSY_STEPS.store(0, Ordering::Relaxed);
    BUSY_STEPS_AT_IRQ.store(0, Ordering::Relaxed);
    BUSY_IRQS.store(0, Ordering::Relaxed);
    BUSY_RIP.store(0, Ordering::Relaxed);
    BUSY_RSP.store(0, Ordering::Relaxed);
    BUSY_CS.store(0, Ordering::Relaxed);
    BUSY_RFLAGS.store(0, Ordering::Relaxed);

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
        TIMER_VECTOR, initial_count, DIVISOR, TICKS_REQUIRED
    ));
    x86_64::instructions::interrupts::enable();
    // Explicitly test asynchronous entry while work has no yield point.
    // The handler does NOT implement a task switch or restore a new frame.
    let frame_ok = prove_read_only_interrupt_frame();
    let delivered = TICKS.load(Ordering::Relaxed) >= TICKS_REQUIRED;
    // Each separate worker dispatch must be gated by a fresh real local
    // APIC IRQ epoch. This is voluntarily yielded, never IRQ-frame preemption.
    // verify() expects IF=0 and enables IF only inside its worker stacks.
    let tasks_ok = delivered && frame_ok && crate::timer_tasks::verify();
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
    if delivered && frame_ok && ticks >= TICKS_REQUIRED && ticks == acks && tasks_ok {
        serial::write_fmt(format_args!(
            "WOLFOS_APIC_TIMER_TASKS_OK threads={} dispatches={} switches={} stack_kib={} gated_by_irq=1 preemptive=0\n",
            crate::timer_tasks::THREAD_COUNT, crate::timer_tasks::DISPATCH_COUNT,
            crate::timer_tasks::SWITCH_COUNT, crate::timer_tasks::STACK_KIB
        ));
        serial::write_fmt(format_args!(
            "WOLFOS_APIC_TIMER_IRQ_OK vector={} ticks={} eoi={} spurious={} preemptive=0\n",
            TIMER_VECTOR, ticks, acks, spurious
        ));
        true
    } else {
        serial::write_fmt(format_args!(
            "WOLFOS_APIC_TIMER_ERROR no_irq_eoi_or_context ticks={} eoi={} spurious={} frame_ok={} tasks_ok={}\n",
            ticks, acks, spurious, frame_ok, tasks_ok
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
