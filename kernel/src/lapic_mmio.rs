//! BSP-only read-only xAPIC identity through explicit UC page mapping.
//!
//! Never assume that physical MMIO is part of Limine's HHDM. Temporarily
//! map a single page with cache-disable and write-through page flags, inspect
//! two read-only registers, unmap and invalidate TLB BEFORE releasing APs.
//! No APIC mode changes, LVT setup, IPI, EOI or APIC timer programming.

use limine::memmap::{
    Entry, MEMMAP_USABLE, MEMMAP_BOOTLOADER_RECLAIMABLE,
    MEMMAP_EXECUTABLE_AND_MODULES, MEMMAP_ACPI_RECLAIMABLE, MEMMAP_ACPI_NVS,
};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable,
    PageTableFlags, PhysFrame, Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::{lapic_mmio_layout, lapic_probe, pmm, serial};

pub const XAPIC_TEST_VIRTUAL_ADDRESS: u64 = 0x0000_4000_0000_2000;
const PAGE_SIZE: u64 = 4096;

struct TableAllocator;
// SAFETY: PMM hands out unique, 4KiB-aligned usable RAM frames. Page table
// frames are deliberately retained in the active page tree, never freed here.
unsafe impl FrameAllocator<Size4KiB> for TableAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let physical = pmm::allocate_frame()?;
        Some(PhysFrame::containing_address(PhysAddr::new(physical)))
    }
}

fn safe_mmio_region(base: u64, entries: &[&Entry]) -> bool {
    if base == 0 || base % PAGE_SIZE != 0 { return false; }
    let Some(end) = base.checked_add(PAGE_SIZE) else { return false; };
    for entry in entries.iter().copied() {
        let forbidden = matches!(entry.type_,
            MEMMAP_USABLE | MEMMAP_BOOTLOADER_RECLAIMABLE |
            MEMMAP_EXECUTABLE_AND_MODULES | MEMMAP_ACPI_RECLAIMABLE | MEMMAP_ACPI_NVS
        );
        if !forbidden { continue; }
        let Some(entry_end) = entry.base.checked_add(entry.length) else {
            return false;
        };
        if base < entry_end && entry.base < end { return false; }
    }
    true
}

pub fn verify_bsp(expected_lapic_id: u32, hhdm: u64, entries: &[&Entry]) -> bool {
    // Verified current-core CPUID+MSR; fail closed if using x2APIC mode,
    // which does not expose these legacy xAPIC MMIO registers.
    let Some(base) = lapic_probe::bsp_mmio_base(expected_lapic_id) else {
        serial::write_line("WOLFOS_LAPIC_MMIO_ERROR no_xapic_base");
        return false;
    };
    if !safe_mmio_region(base, entries) {
        serial::write_line("WOLFOS_LAPIC_MMIO_ERROR overlaps_managed_ram");
        return false;
    }
    // Only BSP writes page tables; other processors have not been started.
    if x86_64::instructions::interrupts::are_enabled() {
        serial::write_line("WOLFOS_LAPIC_MMIO_ERROR interrupts_enabled");
        return false;
    }
    let (cr3_frame, _) = Cr3::read();
    let Some(pml4_va) = hhdm.checked_add(cr3_frame.start_address().as_u64())
        .and_then(|a| VirtAddr::try_new(a).ok())
    else {
        serial::write_line("WOLFOS_LAPIC_MMIO_ERROR bad_cr3_hhdm");
        return false;
    };
    let Some(hhdm_va) = VirtAddr::try_new(hhdm).ok() else {
        serial::write_line("WOLFOS_LAPIC_MMIO_ERROR bad_hhdm");
        return false;
    };

    // SAFETY: active PML4 is permanently mapped by Limine's HHDM and only
    // this boot CPU mutates it before AP startup. No concurrent walker.
    let pml4 = unsafe { &mut *pml4_va.as_mut_ptr::<PageTable>() };
    let mut mapper = unsafe { OffsetPageTable::new(pml4, hhdm_va) };
    let target = VirtAddr::new(XAPIC_TEST_VIRTUAL_ADDRESS);
    if mapper.translate_addr(target).is_some() {
        serial::write_line("WOLFOS_LAPIC_MMIO_ERROR virtual_slot_occupied");
        return false;
    }
    let page = Page::<Size4KiB>::containing_address(target);
    let physical = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(base));
    // PCD+PWT to avoid caching device register accesses; no WRITABLE and
    // never allow user access. Mapping is removed before any AP is released.
    let flags = PageTableFlags::PRESENT | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH;
    // SAFETY: one unused canonical VA, one non-RAM MMIO frame from the
    // BSP's architecturally enabled IA32_APIC_BASE register; no aliases
    // created here and no memory writes through this mapping.
    let Ok(flush) = (unsafe { mapper.map_to(page, physical, flags, &mut TableAllocator) }) else {
        serial::write_line("WOLFOS_LAPIC_MMIO_ERROR mapping_failed");
        return false; // fail-stop: allocated table frames remain reserved
    };
    flush.flush();
    if mapper.translate_addr(target).map(|p| p.as_u64()) != Some(base) {
        serial::write_line("WOLFOS_LAPIC_MMIO_ERROR translation_mismatch");
        return false;
    }

    // SAFETY: mapped non-cacheable MMIO page is present throughout these
    // volatile 32-bit reads at architectural, aligned register offsets.
    let id = unsafe {
        target.as_u64().wrapping_add(lapic_mmio_layout::XAPIC_ID_OFFSET as u64)
            as *const u32
    };
    let version = unsafe {
        target.as_u64().wrapping_add(lapic_mmio_layout::XAPIC_VERSION_OFFSET as u64)
            as *const u32
    };
    let raw_id = unsafe { id.read_volatile() };
    let raw_version = unsafe { version.read_volatile() };
    // Unmap and invalidate TLB even if register contents are invalid.
    let Ok((unmapped, flush)) = mapper.unmap(page) else {
        serial::write_line("WOLFOS_LAPIC_MMIO_ERROR unmap_failed");
        return false;
    };
    flush.flush();
    if unmapped.start_address().as_u64() != base
        || mapper.translate_addr(target).is_some()
    {
        serial::write_line("WOLFOS_LAPIC_MMIO_ERROR stale_mapping");
        return false;
    }
    let Ok(found_id) = lapic_mmio_layout::verify_identity(raw_id, expected_lapic_id) else {
        serial::write_line("WOLFOS_LAPIC_MMIO_ERROR id_mismatch");
        return false;
    };
    let Ok(version) = lapic_mmio_layout::decode_version(raw_version) else {
        serial::write_line("WOLFOS_LAPIC_MMIO_ERROR bad_version");
        return false;
    };
    serial::write_fmt(format_args!(
        "WOLFOS_LAPIC_MMIO_OK id={} base={:#x} version={:#x} max_lvt={} readonly=1 uncached=1\n",
        found_id, base, version.version, version.max_lvt
    ));
    true
}
