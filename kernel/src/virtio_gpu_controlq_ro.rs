//! QEMU-only VirtIO-GPU controlq descriptor-address and layout readback.
//!
//! This diagnostic neither binds a GPU driver nor configures VirtIO queues.
//! It refuses physical RAM and framebuffer overlap, maps the validated BAR
//! window only on the BSP, reads queue0 registers, and flushes the unmap.
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
    virtio_gpu_transport_preflight_contract as preflight,
    virtio_gpu_controlq_ro_contract as controlq};

const TEST_SLOT: u64 = 0x0000_4000_0000_8000;

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

pub fn verify(hhdm: u64, entries: &[&Entry], window: pci::QemuBarWindow) -> Option<controlq::Layout> {
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
                "WOLFOS_VIRTIO_GPU_CONTROLQ_RO_FAIL window={error:?}\n"
            ));
            return None;
        }
    };
    if !disjoint_from_ram_and_framebuffer(span.physical_page, entries) {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_RO_FAIL overlaps_memory");
        return None;
    }
    if x86_64::instructions::interrupts::are_enabled() {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_RO_FAIL interrupts_enabled");
        return None;
    }
    let (cr3_frame, _) = Cr3::read();
    let Some(pml4_va) = hhdm.checked_add(cr3_frame.start_address().as_u64())
        .and_then(|a| VirtAddr::try_new(a).ok())
    else {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_RO_FAIL bad_cr3");
        return None;
    };
    let Some(hhdm_va) = VirtAddr::try_new(hhdm).ok() else {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_RO_FAIL bad_hhdm");
        return None;
    };
    // SAFETY: only the BSP mutates these active tables; no AP was started
    // and interrupts are disabled. The PML4 itself is RAM in HHDM.
    let pml4 = unsafe { &mut *pml4_va.as_mut_ptr::<PageTable>() };
    let mut mapper = unsafe { OffsetPageTable::new(pml4, hhdm_va) };
    let target = VirtAddr::new(TEST_SLOT);
    if mapper.translate_addr(target).is_some() {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_RO_FAIL slot_occupied");
        return None;
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
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_RO_FAIL map");
        return None;
    };
    flush.flush();

    // A failed translation check still unmaps before returning.
    let mapped_ok = mapper.translate_addr(target)
        .map(|p| p.as_u64()) == Some(span.physical_page);
    let (snapshot, feature_bank_zero) = if mapped_ok {
        let start = TEST_SLOT + span.page_offset;
        // Split 64-bit MMIO register reads into spec-sized 32-bit halves.
        // No atomic 64-bit PCI MMIO access is assumed or required.
        let read32 = |offset:u64| -> u32 {
            u32::from_le(unsafe { ((start+offset) as *const u32).read_volatile() })
        };
        let read64 = |offset:u64| -> u64 {
            u64::from(read32(offset)) | (u64::from(read32(offset+4)) << 32)
        };
        let read16 = |offset:u64| -> u16 {
            u16::from_le(unsafe { ((start+offset) as *const u16).read_volatile() })
        };
        let status = unsafe {
            ((start + preflight::DEVICE_STATUS_OFFSET) as *const u8).read_volatile()
        };
        let bank_zero = read32(preflight::FEATURE_SELECTOR_OFFSET) == 0;
        (controlq::Snapshot {
            num_queues:read16(controlq::NUM_QUEUES),
            queue_select:read16(preflight::QUEUE_SELECTOR_OFFSET),
            queue_size:read16(preflight::QUEUE_SIZE_OFFSET),
            queue_enable:read16(preflight::QUEUE_ENABLE_OFFSET),
            queue_notify_off:read16(controlq::QUEUE_NOTIFY_OFF),
            desc:read64(controlq::QUEUE_DESC),
            driver:read64(controlq::QUEUE_DRIVER),
            device:read64(controlq::QUEUE_DEVICE),
            status,
        }, bank_zero)
    } else {
        (controlq::Snapshot {
            num_queues:0,queue_select:0,queue_size:0,queue_enable:0,
            queue_notify_off:0,desc:0,driver:0,device:0,status:0,
        }, false)
    };

    // Mandatory removal of temporary read-only mapping.
    let Ok((unmapped, flush)) = mapper.unmap(page) else {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_RO_FAIL unmap");
        return None;
    };
    flush.flush();
    if !mapped_ok || unmapped.start_address().as_u64() != span.physical_page
        || mapper.translate_addr(target).is_some()
    {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_RO_FAIL mapping_not_restored");
        return None;
    }
    if !feature_bank_zero {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_RO_FAIL feature_bank_not_zero");
        return None;
    }
    let layout = match controlq::verify(snapshot) {
        Ok(l) => l,
        Err(error) => {
            serial::write_fmt(format_args!(
                "WOLFOS_VIRTIO_GPU_CONTROLQ_RO_FAIL registers={error:?}\n"
            ));
            return None;
        }
    };
    serial::write_fmt(format_args!(
        "WOLFOS_VIRTIO_GPU_CONTROLQ_RO_OK queues={} selected=0 size={} notify_off={} desc=0 driver=0 device=0 enabled=0 layout_n={} desc_bytes={} avail_bytes={} used_bytes={} ro=1 uc=1 pages=1 writes=0 dma=0\n",
        snapshot.num_queues, snapshot.queue_size, snapshot.queue_notify_off,
        layout.selected,layout.desc_bytes,layout.avail_bytes,layout.used_bytes
    ));
    Some(layout)
}
