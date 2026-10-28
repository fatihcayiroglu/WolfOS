//! QEMU-only VirtIO-GPU device-feature bank1 transaction and rollback.
//!
//! Only a dedicated QEMU flavor writes device_feature_select (1 then 0).
//! It refuses physical RAM and framebuffer overlap, maps the validated BAR
//! window only on the BSP, restores the selector, and flushes the unmap.
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
    virtio_gpu_bank1_tx_contract as tx};

const TEST_SLOT: u64 = 0x0000_4000_0000_6000;

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
                "WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_FAIL window={error:?}\n"
            ));
            return false;
        }
    };
    if !disjoint_from_ram_and_framebuffer(span.physical_page, entries) {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_FAIL overlaps_memory");
        return false;
    }
    if x86_64::instructions::interrupts::are_enabled() {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_FAIL interrupts_enabled");
        return false;
    }
    let (cr3_frame, _) = Cr3::read();
    let Some(pml4_va) = hhdm.checked_add(cr3_frame.start_address().as_u64())
        .and_then(|a| VirtAddr::try_new(a).ok())
    else {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_FAIL bad_cr3");
        return false;
    };
    let Some(hhdm_va) = VirtAddr::try_new(hhdm).ok() else {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_FAIL bad_hhdm");
        return false;
    };
    // SAFETY: only the BSP mutates these active tables; no AP was started
    // and interrupts are disabled. The PML4 itself is RAM in HHDM.
    let pml4 = unsafe { &mut *pml4_va.as_mut_ptr::<PageTable>() };
    let mut mapper = unsafe { OffsetPageTable::new(pml4, hhdm_va) };
    let target = VirtAddr::new(TEST_SLOT);
    if mapper.translate_addr(target).is_some() {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_FAIL slot_occupied");
        return false;
    }
    let page = Page::<Size4KiB>::containing_address(target);
    let physical = PhysFrame::<Size4KiB>::containing_address(
        PhysAddr::new(span.physical_page)
    );
    let flags = PageTableFlags::PRESENT | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH | PageTableFlags::WRITABLE;
    // SAFETY: one previously unmapped virtual page, validated QEMU PCI MMIO.
    // Writable only for TWO bounded device_feature_select writes.
    // No USER_ACCESSIBLE flag and no live AP. All previous RO proof
    // gates must pass before this isolated QEMU-only test is called.
    let Ok(flush) = (unsafe {
        mapper.map_to(page, physical, flags, &mut TableAllocator)
    }) else {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_FAIL map");
        return false;
    };
    flush.flush();

    // A failed translation check still unmaps before returning.
    let mapped_ok = mapper.translate_addr(target)
        .map(|p| p.as_u64()) == Some(span.physical_page);
    let transaction = if mapped_ok {
        let start = TEST_SLOT + span.page_offset;
        // SAFETY: pointers are all within the independently checked
        // 56-byte common-config region on this one uncached physical page.
        let selector_ptr = (start + tx::FEATURE_SELECTOR) as *mut u32;
        let feature_ptr = (start + tx::FEATURE_WORD) as *const u32;
        let status_ptr = (start + tx::DEVICE_STATUS) as *const u8;
        let queue_enable_ptr = (start + tx::QUEUE_ENABLE) as *const u16;
        let read_selector = u32::from_le(unsafe { selector_ptr.read_volatile() });
        let bank0 = u32::from_le(unsafe { feature_ptr.read_volatile() });
        let status_before = unsafe { status_ptr.read_volatile() };
        let queue_enable_before = u16::from_le(unsafe { queue_enable_ptr.read_volatile() });
        let queue_select = u16::from_le(unsafe {
            ((start + preflight::QUEUE_SELECTOR_OFFSET) as *const u16).read_volatile()
        });
        let queue_size = u16::from_le(unsafe {
            ((start + preflight::QUEUE_SIZE_OFFSET) as *const u16).read_volatile()
        });
        let sample = preflight::Snapshot {
            feature_selector: read_selector, feature_word: bank0,
            status: status_before, queue_selector: queue_select,
            queue_size, queue_enabled: queue_enable_before,
        };

        // Do not perform even the selector transaction on an active or
        // unclaimed-bank device. This is a QEMU-only fail-closed gate.
        if preflight::validate(sample).is_ok() {
            // SAFETY: both volatile stores target ONLY the PCI common-config
            // device_feature_select register, not a queue or status field.
            // There is NO EARLY RETURN between the bank1 write and the
            // mandatory original-selector restoration.
            unsafe { selector_ptr.write_volatile(1u32.to_le()) };
            let selector_during =
                u32::from_le(unsafe { selector_ptr.read_volatile() });
            let bank1 = u32::from_le(unsafe { feature_ptr.read_volatile() });
            unsafe { selector_ptr.write_volatile(read_selector.to_le()) };

            let selector_after =
                u32::from_le(unsafe { selector_ptr.read_volatile() });
            let bank0_after =
                u32::from_le(unsafe { feature_ptr.read_volatile() });
            let status_after = unsafe { status_ptr.read_volatile() };
            let queue_enabled_after = u16::from_le(unsafe {
                queue_enable_ptr.read_volatile()
            });
            Some(tx::Readback {
                selector_before: read_selector, selector_during, selector_after,
                bank0_before: bank0, bank0_after, bank1, status_before,
                status_after, queue_enabled_before: queue_enable_before,
                queue_enabled_after,
            })
        } else {
            None
        }
    } else {
        None
    };

    // Mandatory rollback even when values are implausible.
    let Ok((unmapped, flush)) = mapper.unmap(page) else {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_FAIL unmap");
        return false;
    };
    flush.flush();
    if !mapped_ok || unmapped.start_address().as_u64() != span.physical_page
        || mapper.translate_addr(target).is_some()
    {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_FAIL mapping_not_restored");
        return false;
    }
    let Some(readback) = transaction else {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_FAIL preflight_not_unclaimed");
        return false;
    };
    if let Err(error) = tx::verify(readback) {
        serial::write_fmt(format_args!(
            "WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_FAIL registers={error:?}\n"
        ));
        return false;
    }

    serial::write_fmt(format_args!(
        "WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_OK bank0={} bank1={} version1=1 selector_writes=2 restored=1 status=0 queue_enabled=0 dma=0\n",
        readback.bank0_before, readback.bank1
    ));
    true
}
