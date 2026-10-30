//! A monotonic millisecond clock the guest itself owns.
//!
//! A confirmation window that is only measured by the peer is not a window:
//! a silent or hostile peer can hold the guest forever. This module gives the
//! guest an independent deadline source so "the user did not confirm in time"
//! is decided locally, not asserted by the other side.
//!
//! The only hardware fact this relies on is the HPET general capabilities
//! register, which carries the counter clock period itself: the conversion from
//! counter ticks to milliseconds is derived from the device, never assumed from
//! a nominal frequency. Identity, revision, counter width and liveness are all
//! validated before the clock is published; anything unexpected leaves the
//! clock absent and the caller falls back to a peer-measured window instead of
//! inventing a time base.
//!
//! Scope: BSP-only. The only register write is the single ENABLE_CNF bit that
//! makes the main counter run at all; no comparator, timer mode, interrupt
//! route or other configuration bit is ever touched, and nothing here
//! schedules work.

pub const HPET_MMIO_BASE: u64 = 0xFED0_0000;
/// One unused canonical virtual page reserved for this mapping, next to the
/// xAPIC slot. Chosen so an existing mapping is detected instead of clobbered.
pub const HPET_VIRTUAL_ADDRESS: u64 = 0x0000_4000_0000_3000;
pub const REG_CAPABILITIES_ID: usize = 0x00;
pub const REG_GENERAL_CONFIG: usize = 0x10;
pub const REG_MAIN_COUNTER: usize = 0xF0;
/// General Configuration bit 0. The main counter stays halted until this is
/// set, so a device that never sees it enabled would only ever read zero.
pub const CONF_ENABLE_CNF: u64 = 1 << 0;
/// The ID register's vendor field must be a real PCI-SIG vendor id: 0x8086 is
/// what QEMU's HPET device reports. A wrong value means "not a device we have
/// validated", not "close enough".
pub const EXPECTED_VENDOR_ID: u16 = 0x8086;
/// The HPET specification caps the counter clock period at 100 ns, i.e. 10^8 fs.
pub const MAX_PERIOD_FS: u32 = 100_000_000;
pub const FEMTOSECONDS_PER_MS: u128 = 1_000_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockError {
    BadVendor,
    BadRevision,
    NoLongCounter,
    BadPeriod,
    NoTimers,
}

impl ClockError {
    pub fn label(self) -> &'static str {
        match self {
            ClockError::BadVendor => "bad_vendor_id",
            ClockError::BadRevision => "bad_revision",
            ClockError::NoLongCounter => "no_64bit_counter",
            ClockError::BadPeriod => "bad_counter_period",
            ClockError::NoTimers => "no_timers",
        }
    }
}

/// Decoded, validated facts from the general capabilities and ID register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    pub vendor_id: u16,
    pub revision: u8,
    pub timers: u8,
    pub counter_64bit: bool,
    pub period_fs: u32,
}

/// Bits of the general capabilities and ID register (HPET specification 2.3.1).
pub fn decode_capabilities(raw: u64) -> Result<Capabilities, ClockError> {
    // Layout: 0:7 revision, 8:12 number of timers minus one, 13 64-bit
    // counter, 16:31 vendor id, 32:63 counter clock period in femtoseconds.
    let revision = (raw & 0xFF) as u8;
    let timers = (((raw >> 8) & 0x1F) as u8).saturating_add(1);
    let vendor_id = ((raw >> 16) & 0xFFFF) as u16;
    let counter_64bit = raw & (1 << 13) != 0;
    let period_fs = (raw >> 32) as u32;
    if vendor_id != EXPECTED_VENDOR_ID { return Err(ClockError::BadVendor); }
    if revision == 0 { return Err(ClockError::BadRevision); }
    // A 32-bit counter wraps every 43 s at 100 ns, which is too close to a 15 s
    // window to be worth the ambiguity: require the documented 64-bit counter.
    if !counter_64bit { return Err(ClockError::NoLongCounter); }
    if period_fs == 0 || period_fs > MAX_PERIOD_FS {
        return Err(ClockError::BadPeriod);
    }
    if timers == 0 { return Err(ClockError::NoTimers); }
    Ok(Capabilities { vendor_id, revision, timers, counter_64bit, period_fs })
}

/// Converts counter ticks to milliseconds using only the device-reported period.
pub fn ticks_to_ms(ticks: u64, period_fs: u32) -> u64 {
    let femtoseconds = (ticks as u128) * (period_fs as u128);
    (femtoseconds / FEMTOSECONDS_PER_MS).min(u64::MAX as u128) as u64
}

/// Milliseconds between two counter readings, tolerant of a 64-bit wrap.
pub fn elapsed_ms(start: u64, now: u64, period_fs: u32) -> u64 {
    ticks_to_ms(now.wrapping_sub(start), period_fs)
}

/// Whether a deadline has been reached, given readings from the same counter.
pub fn deadline_reached(start: u64, now: u64, period_fs: u32, window_ms: u64) -> bool {
    elapsed_ms(start, now, period_fs) >= window_ms
}

#[cfg(feature = "qemu-virtio-gpu-desktop-scanout-smoke")]
mod mmio {
    use super::*;
    use limine::memmap::Entry;
    use x86_64::registers::control::Cr3;
    use x86_64::structures::paging::{
        FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame,
        Size4KiB, Translate,
    };
    use x86_64::{PhysAddr, VirtAddr};
    use crate::lapic_mmio::safe_mmio_region;
    use crate::serial;
    use crate::pmm;

    struct TableAllocator;
    // SAFETY: the PMM hands out unique 4 KiB-aligned usable frames, and page
    // table frames are deliberately retained in the live tree.
    unsafe impl FrameAllocator<Size4KiB> for TableAllocator {
        fn allocate_frame(&mut self) -> Option<PhysFrame> {
            let physical = pmm::allocate_frame()?;
            Some(PhysFrame::containing_address(PhysAddr::new(physical)))
        }
    }

    static mut PERIOD_FS: u32 = 0;
    static mut PUBLISHED: bool = false;

    /// Maps the HPET page, validates the device and publishes a clock.
    ///
    /// Fails closed: any mismatch leaves the clock absent and prints why, so a
    /// caller can never silently measure a window with an unvalidated counter.
    pub fn init(hhdm: u64, entries: &[&Entry]) -> bool {
        if !safe_mmio_region(HPET_MMIO_BASE, entries) {
            serial::write_line("WOLFOS_HPET_CLOCK_ABSENT reason=overlaps_managed_ram");
            return false;
        }
        let (cr3_frame, _) = Cr3::read();
        let Some(pml4_va) = hhdm
            .checked_add(cr3_frame.start_address().as_u64())
            .and_then(|a| VirtAddr::try_new(a).ok())
        else {
            serial::write_line("WOLFOS_HPET_CLOCK_ABSENT reason=bad_cr3_hhdm");
            return false;
        };
        let Some(hhdm_va) = VirtAddr::try_new(hhdm).ok() else {
            serial::write_line("WOLFOS_HPET_CLOCK_ABSENT reason=bad_hhdm");
            return false;
        };
        // SAFETY: the active PML4 is permanently mapped by Limine's HHDM and
        // only this boot CPU mutates it during the smoke proof.
        let pml4 = unsafe { &mut *pml4_va.as_mut_ptr::<PageTable>() };
        let mut mapper = unsafe { OffsetPageTable::new(pml4, hhdm_va) };
        let target = VirtAddr::new(HPET_VIRTUAL_ADDRESS);
        if mapper.translate_addr(target).is_some() {
            serial::write_line("WOLFOS_HPET_CLOCK_ABSENT reason=virtual_slot_occupied");
            return false;
        }
        let page = Page::<Size4KiB>::containing_address(target);
        let physical = PhysFrame::<Size4KiB>::containing_address(
            PhysAddr::new(HPET_MMIO_BASE),
        );
        // Device register accesses must not be cached, and the single
        // ENABLE_CNF write needs the page to be writable. It is kept for the
        // lifetime of the boot because the counter is read continuously.
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE
            | PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH;
        // SAFETY: one unused canonical VA mapped to one non-RAM MMIO frame
        // reserved by firmware, with no aliases created here.
        let Ok(flush) = (unsafe { mapper.map_to(page, physical, flags, &mut TableAllocator) })
        else {
            serial::write_line("WOLFOS_HPET_CLOCK_ABSENT reason=mapping_failed");
            return false;
        };
        flush.flush();
        if mapper.translate_addr(target).map(|p| p.as_u64()) != Some(HPET_MMIO_BASE) {
            serial::write_line("WOLFOS_HPET_CLOCK_ABSENT reason=translation_mismatch");
            return false;
        }
        // SAFETY: the page above is present, uncached and covers these aligned
        // architectural register offsets.
        let raw = unsafe {
            (target.as_u64() as *const u64)
                .add(REG_CAPABILITIES_ID / 8)
                .read_volatile()
        };
        let capabilities = match decode_capabilities(raw) {
            Ok(capabilities) => capabilities,
            Err(error) => {
                serial::write_fmt(format_args!(
                    "WOLFOS_HPET_CLOCK_ABSENT reason={} caps={:#018x}\n",
                    error.label(), raw
                ));
                return false;
            }
        };
        // The main counter is halted until ENABLE_CNF is set. That single bit is
        // the only write this module ever performs: no comparator, no timer
        // mode, no interrupt route, and no other configuration bit is touched.
        let config = read_config(target);
        if config & CONF_ENABLE_CNF == 0 {
            write_config(target, config | CONF_ENABLE_CNF);
        }
        let enabled = read_config(target);
        if enabled & CONF_ENABLE_CNF == 0 {
            serial::write_fmt(format_args!(
                "WOLFOS_HPET_CLOCK_ABSENT reason=enable_refused conf={:#x}\n",
                enabled
            ));
            return false;
        }
        let first = read_counter(target);
        let mut advanced = false;
        // Liveness only: a bounded number of reads proves the counter runs. The
        // bound never stands in for a duration -- durations come from the
        // counter itself.
        for _ in 0..1_000_000u32 {
            if read_counter(target) != first {
                advanced = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !advanced {
            serial::write_line("WOLFOS_HPET_CLOCK_ABSENT reason=counter_not_running");
            return false;
        }
        // SAFETY: single boot CPU, no interrupts enabled during the proof.
        unsafe {
            PERIOD_FS = capabilities.period_fs;
            PUBLISHED = true;
        }
        serial::write_fmt(format_args!(
            "WOLFOS_HPET_CLOCK_OK vendor={:#06x} revision={} timers={} counter_bits=64 period_fs={} base={:#x} uncached=1 main_counter_enabled=1 mmio_writes=1 comparators_programmed=0 interrupts_routed=0\n",
            capabilities.vendor_id, capabilities.revision, capabilities.timers,
            capabilities.period_fs, HPET_MMIO_BASE
        ));
        true
    }

    fn read_config(target: VirtAddr) -> u64 {
        // SAFETY: same validated uncached mapping, aligned 64-bit read.
        unsafe {
            (target.as_u64() as *const u64)
                .add(REG_GENERAL_CONFIG / 8)
                .read_volatile()
        }
    }

    fn write_config(target: VirtAddr, value: u64) {
        // SAFETY: same validated uncached mapping. The caller only ever sets
        // ENABLE_CNF while preserving every other bit it just read.
        unsafe {
            (target.as_u64() as *mut u64)
                .add(REG_GENERAL_CONFIG / 8)
                .write_volatile(value)
        }
    }

    fn read_counter(target: VirtAddr) -> u64 {
        // SAFETY: same validated uncached mapping as above, aligned 64-bit read
        // of the read-only main counter.
        unsafe {
            (target.as_u64() as *const u64)
                .add(REG_MAIN_COUNTER / 8)
                .read_volatile()
        }
    }

    /// Raw counter value, or `None` when no validated clock exists.
    pub fn counter() -> Option<u64> {
        // SAFETY: the fields are written once before any reader runs.
        unsafe {
            if !PUBLISHED { return None; }
        }
        Some(read_counter(VirtAddr::new(HPET_VIRTUAL_ADDRESS)))
    }

    /// Device-reported counter period in femtoseconds.
    pub fn period_fs() -> Option<u32> {
        // SAFETY: the field is written once before any reader runs.
        unsafe {
            if !PUBLISHED { return None; }
            Some(PERIOD_FS)
        }
    }
}

#[cfg(feature = "qemu-virtio-gpu-desktop-scanout-smoke")]
pub use mmio::{counter, init, period_fs};

/// Milliseconds since the counter started, from the validated device clock.
#[cfg(feature = "qemu-virtio-gpu-desktop-scanout-smoke")]
pub fn now_ms() -> Option<u64> {
    Some(ticks_to_ms(counter()?, period_fs()?))
}

/// Whether the guest owns a validated clock for this boot.
#[cfg(feature = "qemu-virtio-gpu-desktop-scanout-smoke")]
pub fn present() -> bool {
    period_fs().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// QEMU's q35 HPET: vendor 0x8086, revision 1, three timers, 64-bit
    /// counter, 10 ns counter period (10^7 fs).
    const QEMU_CAPS: u64 = 1            // revision
        | (2 << 8)                      // three timers, stored as "minus one"
        | (1 << 13)                     // 64-bit counter
        | (0x8086 << 16)                // vendor id
        | (10_000_000u64 << 32);        // 10 ns counter clock period

    #[test]
    fn decodes_the_qemu_capabilities() {
        let caps = decode_capabilities(QEMU_CAPS).unwrap();
        assert_eq!(caps.vendor_id, 0x8086);
        assert_eq!(caps.revision, 1);
        assert_eq!(caps.timers, 3);
        assert!(caps.counter_64bit);
        assert_eq!(caps.period_fs, 10_000_000);
    }

    #[test]
    fn rejects_a_foreign_vendor() {
        let raw = (QEMU_CAPS & !(0xFFFF << 16)) | (0x1234 << 16);
        assert_eq!(decode_capabilities(raw), Err(ClockError::BadVendor));
    }

    #[test]
    fn rejects_a_zero_revision() {
        let raw = QEMU_CAPS & !0xFF;
        assert_eq!(decode_capabilities(raw), Err(ClockError::BadRevision));
    }

    #[test]
    fn rejects_a_32bit_only_counter() {
        let raw = QEMU_CAPS & !(1 << 13);
        assert_eq!(decode_capabilities(raw), Err(ClockError::NoLongCounter));
    }

    #[test]
    fn rejects_a_zero_or_oversized_period() {
        let zero = QEMU_CAPS & 0xFFFF_FFFF;
        assert_eq!(decode_capabilities(zero), Err(ClockError::BadPeriod));
        let oversized = (QEMU_CAPS & 0xFFFF_FFFF) | ((MAX_PERIOD_FS as u64 + 1) << 32);
        assert_eq!(decode_capabilities(oversized), Err(ClockError::BadPeriod));
    }

    #[test]
    fn accepts_the_specification_maximum_period() {
        let raw = (QEMU_CAPS & 0xFFFF_FFFF) | ((MAX_PERIOD_FS as u64) << 32);
        assert_eq!(decode_capabilities(raw).unwrap().period_fs, MAX_PERIOD_FS);
    }

    #[test]
    fn converts_ticks_with_the_device_period() {
        // 10 ns per tick: 100 ticks are one microsecond, 100_000 are one ms.
        assert_eq!(ticks_to_ms(100_000, 10_000_000), 1);
        assert_eq!(ticks_to_ms(0, 10_000_000), 0);
        // 100 ns per tick: 10_000 ticks are one ms.
        assert_eq!(ticks_to_ms(10_000, MAX_PERIOD_FS), 1);
        assert_eq!(ticks_to_ms(9_999, MAX_PERIOD_FS), 0);
        // A 15 s window at 10 ns per tick is 1.5e9 ticks.
        assert_eq!(ticks_to_ms(1_500_000_000, 10_000_000), 15_000);
    }

    #[test]
    fn conversion_does_not_overflow_for_wide_counters() {
        assert_eq!(ticks_to_ms(u64::MAX, 10_000_000), 184_467_440_737_095);
        assert_eq!(ticks_to_ms(u64::MAX, MAX_PERIOD_FS), 1_844_674_407_370_955);
    }

    #[test]
    fn elapsed_time_is_wrap_tolerant() {
        assert_eq!(elapsed_ms(1_000, 2_000, 10_000_000), 0);
        assert_eq!(elapsed_ms(0, 1_500_000_000, 10_000_000), 15_000);
        // Cross a 64-bit wrap: the unsigned difference still measures forward.
        assert_eq!(elapsed_ms(u64::MAX - 499_999, 500_000, 10_000_000), 10);
    }

    #[test]
    fn deadline_is_inclusive_and_only_uses_the_counter() {
        assert!(!deadline_reached(0, 1_499_999_999, 10_000_000, 15_000));
        assert!(deadline_reached(0, 1_500_000_000, 10_000_000, 15_000));
        assert!(deadline_reached(0, 9_000_000_000, 10_000_000, 15_000));
    }

    #[test]
    fn every_rejection_has_a_distinct_label() {
        let labels = [
            ClockError::BadVendor.label(),
            ClockError::BadRevision.label(),
            ClockError::NoLongCounter.label(),
            ClockError::BadPeriod.label(),
            ClockError::NoTimers.label(),
        ];
        for (index, label) in labels.iter().enumerate() {
            assert!(!label.is_empty());
            assert!(!labels[..index].contains(label));
        }
    }
}
