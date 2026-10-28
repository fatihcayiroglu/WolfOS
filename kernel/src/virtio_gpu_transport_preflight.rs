//! QEMU-only VirtIO-GPU transport preflight: one transient UC RO page.
//!
//! This diagnostic neither binds a GPU driver nor configures VirtIO queues.
//! It refuses physical RAM and framebuffer overlap, maps the validated BAR
//! window only on the BSP, reads three registers, and flushes the unmap.
//! Never dereference PCI MMIO through Limine's higher-half direct RAM map.

use limine::memmap::{
    Entry, MEMMAP_USABLE, MEMMAP_BOOTLOADER_RECLAIMABLE,
    MEMMAP_EXECUTABLE_AND_MODULES, MEMMAP_ACPI_RECLAIMABLE, MEMMAP_ACPI_NVS,
    MEMMAP_FRAMEBUFFER,
};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags,
    PhysFrame, Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::{pci, pmm, serial, virtio_gpu_mmio_contract as contract,
    virtio_gpu_transport_preflight_contract as preflight};

const TEST_SLOT: u64 = 0x0000_4000_0000_5000;

struct TableAllocator;
// SAFETY: PMM returns unique aligned usable-RAM frames. Newly allocated
// page-table frames remain permanently owned by the active page tables.
unsafe impl FrameAllocator<Size4KiB> for TableAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let physical = pmm::allocate_frame()?;
        Some(PhysFrame::containing_address(PhysAddr::new(physical)))
    }
}

fn disjoint_from_ram_and_framebuffer(base: u64, entries: &[&Entry]) -> bool {
    let Some(end) = base.checked_add(contract::PAGE_BYTES) else { return false; };
    for entry in entries.iter().copied() {
        if !matches!(entry.type_,
            MEMMAP_USABLE | MEMMAP_BOOTLOADER_RECLAIMABLE |
            MEMMAP_EXECUTABLE_AND_MODULES | MEMMAP_ACPI_RECLAIMABLE |
            MEMMAP_ACPI_NVS | MEMMAP_FRAMEBUFFER
        ) { continue; }
        let Some(entry_end) = entry.base.checked_add(entry.length) else {
            return false;
        };
        if base < entry_end && entry.base < end { return false; }
    }
    true
}

pub fn verify(hhdm: u64, entries: &[&Entry], window: pci::QemuBarWindow) -> bool {
    let contract_window = contract::Window {
        bar_base: window.physical_base,
        bar_bytes: window.aperture_bytes,
        offset: window.common_offset,
        length: window.common_length,
        is_memory: window.is_memory,
    };
    let span = match contract::check(contract_window) {
        Ok(span) => span,
        Err(error) => {
            serial::write_fmt(format_args!(
                "WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_FAIL window={error:?}\n"
            ));
            return false;
        }
    };
    if !disjoint_from_ram_and_framebuffer(span.physical_page, entries) {
        serial::write_line("WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_FAIL overlaps_memory");
        return false;
    }
    if x86_64::instructions::interrupts::are_enabled() {
        serial::write_line("WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_FAIL interrupts_enabled");
        return false;
    }
    let (cr3_frame, _) = Cr3::read();
    let Some(pml4_va) = hhdm.checked_add(cr3_frame.start_address().as_u64())
        .and_then(|a| VirtAddr::try_new(a).ok())
    else {
        serial::write_line("WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_FAIL bad_cr3");
        return false;
    };
    let Some(hhdm_va) = VirtAddr::try_new(hhdm).ok() else {
        serial::write_line("WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_FAIL bad_hhdm");
        return false;
    };
    // SAFETY: only the BSP mutates these active tables; no AP was started
    // and interrupts are disabled. The PML4 itself is RAM in HHDM.
    let pml4 = unsafe { &mut *pml4_va.as_mut_ptr::<PageTable>() };
    let mut mapper = unsafe { OffsetPageTable::new(pml4, hhdm_va) };
    let target = VirtAddr::new(TEST_SLOT);
    if mapper.translate_addr(target).is_some() {
        serial::write_line("WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_FAIL slot_occupied");
        return false;
    }
    let page = Page::<Size4KiB>::containing_address(target);
    let physical = PhysFrame::<Size4KiB>::containing_address(
        PhysAddr::new(span.physical_page)
    );
    let flags = PageTableFlags::PRESENT | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH;
    // SAFETY: one previously unmapped canonical virtual page, one validated
    // non-RAM BAR MMIO page; no WRITABLE or USER_ACCESSIBLE flag set.
    let Ok(flush) = (unsafe {
        mapper.map_to(page, physical, flags, &mut TableAllocator)
    }) else {
        serial::write_line("WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_FAIL map");
        return false;
    };
    flush.flush();

    // A failed translation check still unmaps before returning.
    let mapped_ok = mapper.translate_addr(target)
        .map(|p| p.as_u64()) == Some(span.physical_page);
    let sample = if mapped_ok {
        let start = TEST_SLOT + span.page_offset;
        // SAFETY: each volatile field is within the validated 56-byte
        // common capability and its mapped uncached read-only page.
        // No selector, status or queue settings are written.
        let selector = unsafe {
            ((start + preflight::FEATURE_SELECTOR_OFFSET) as *const u32).read_volatile()
        };
        let features = unsafe {
            ((start + preflight::DEVICE_FEATURE_OFFSET) as *const u32).read_volatile()
        };
        let status = unsafe {
            ((start + preflight::DEVICE_STATUS_OFFSET) as *const u8).read_volatile()
        };
        let queue_select = unsafe {
            ((start + preflight::QUEUE_SELECTOR_OFFSET) as *const u16).read_volatile()
        };
        let queue_size = unsafe {
            ((start + preflight::QUEUE_SIZE_OFFSET) as *const u16).read_volatile()
        };
        let queue_enable = unsafe {
            ((start + preflight::QUEUE_ENABLE_OFFSET) as *const u16).read_volatile()
        };
        preflight::Snapshot {
            feature_selector: u32::from_le(selector),
            feature_word: u32::from_le(features),
            status,
            queue_selector: u16::from_le(queue_select),
            queue_size: u16::from_le(queue_size),
            queue_enabled: u16::from_le(queue_enable),
        }
    } else {
        preflight::Snapshot {
            feature_selector:0, feature_word:0, status:0,
            queue_selector:0, queue_size:0, queue_enabled:0,
        }
    };

    // Mandatory rollback even when values are implausible.
    let Ok((unmapped, flush)) = mapper.unmap(page) else {
        serial::write_line("WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_FAIL unmap");
        return false;
    };
    flush.flush();
    if !mapped_ok || unmapped.start_address().as_u64() != span.physical_page
        || mapper.translate_addr(target).is_some()
    {
        serial::write_line("WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_FAIL mapping_not_restored");
        return false;
    }
    let verified = match preflight::validate(sample) {
        Ok(ok) => ok,
        Err(error) => {
        serial::write_fmt(format_args!(
            "WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_FAIL registers={error:?}\n"
        ));
            return false;
        }
    };

    serial::write_fmt(format_args!(
        "WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_OK feature_select=0 features={} edid={} queue_select=0 queue_size={} queue_enabled=0 status=0 ro=1 uc=1 pages=1 writes=0 dma=0\n",
        verified.feature_word, u8::from(verified.edid), verified.queue_size
    ));
    true
}
