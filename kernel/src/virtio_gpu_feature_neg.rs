//! QEMU-only VirtIO 1.2 feature handshake and mandatory reset proof.
//!
//! Dedicated opt-in QEMU flavor; never sets DRIVER_OK or enables DMA.
//! Refuses physical RAM and framebuffer overlap, maps the validated BAR
//! window on BSP only, then resets the device and flushes the unmap.
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
    virtio_gpu_bank1_tx_contract as tx,
    virtio_gpu_feature_neg_contract as negotiation};

const TEST_SLOT: u64 = 0x0000_4000_0000_7000;

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
                "WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_FAIL window={error:?}\n"
            ));
            return false;
        }
    };
    if !disjoint_from_ram_and_framebuffer(span.physical_page, entries) {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_FAIL overlaps_memory");
        return false;
    }
    if x86_64::instructions::interrupts::are_enabled() {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_FAIL interrupts_enabled");
        return false;
    }
    let (cr3_frame, _) = Cr3::read();
    let Some(pml4_va) = hhdm.checked_add(cr3_frame.start_address().as_u64())
        .and_then(|a| VirtAddr::try_new(a).ok())
    else {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_FAIL bad_cr3");
        return false;
    };
    let Some(hhdm_va) = VirtAddr::try_new(hhdm).ok() else {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_FAIL bad_hhdm");
        return false;
    };
    // SAFETY: only the BSP mutates these active tables; no AP was started
    // and interrupts are disabled. The PML4 itself is RAM in HHDM.
    let pml4 = unsafe { &mut *pml4_va.as_mut_ptr::<PageTable>() };
    let mut mapper = unsafe { OffsetPageTable::new(pml4, hhdm_va) };
    let target = VirtAddr::new(TEST_SLOT);
    if mapper.translate_addr(target).is_some() {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_FAIL slot_occupied");
        return false;
    }
    let page = Page::<Size4KiB>::containing_address(target);
    let physical = PhysFrame::<Size4KiB>::containing_address(
        PhysAddr::new(span.physical_page)
    );
    let flags = PageTableFlags::PRESENT | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH | PageTableFlags::WRITABLE;
    // SAFETY: one previously unmapped virtual page, validated QEMU PCI MMIO.
    // Writable only for this QEMU-only feature handshake and reset.
    // No USER_ACCESSIBLE flag and no live AP. All previous RO proof
    // gates must pass before this isolated QEMU-only test is called.
    let Ok(flush) = (unsafe {
        mapper.map_to(page, physical, flags, &mut TableAllocator)
    }) else {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_FAIL map");
        return false;
    };
    flush.flush();

    // A failed translation check still unmaps before returning.
    let mapped_ok = mapper.translate_addr(target)
        .map(|p| p.as_u64()) == Some(span.physical_page);
    let transaction = if mapped_ok {
        let start = TEST_SLOT + span.page_offset;
        // All volatile accesses reside within the checked common MMIO capability.
        let device_select = (start + tx::FEATURE_SELECTOR) as *const u32;
        let feature_word = (start + tx::FEATURE_WORD) as *const u32;
        let driver_select = (start + negotiation::DRIVER_SELECT) as *mut u32;
        let driver_feature = (start + negotiation::DRIVER_FEATURE) as *mut u32;
        let status = (start + negotiation::DEVICE_STATUS) as *mut u8;
        let queue = (start + negotiation::QUEUE_ENABLE) as *const u16;
        let before = unsafe { status.read_volatile() };
        let device_bank = u32::from_le(unsafe { device_select.read_volatile() });
        let bank0 = u32::from_le(unsafe { feature_word.read_volatile() });
        let driver_select_before = u32::from_le(unsafe { driver_select.read_volatile() });
        let queue_before = u16::from_le(unsafe { queue.read_volatile() });
        let queue_selector = u16::from_le(unsafe {
            ((start + preflight::QUEUE_SELECTOR_OFFSET) as *const u16).read_volatile()
        });
        let queue_size = u16::from_le(unsafe {
            ((start + preflight::QUEUE_SIZE_OFFSET) as *const u16).read_volatile()
        });
        let sample = preflight::Snapshot {
            feature_selector:device_bank,feature_word:bank0,status:before,
            queue_selector,queue_size,queue_enabled:queue_before,
        };
        if preflight::validate(sample).is_ok() && driver_select_before == 0 {
            // This QEMU-only test never enables DRIVER_OK. No early returns
            // until a final status=0 device reset, even on unexpected values.
            unsafe { status.write_volatile(0) };
            let initial_reset = unsafe { status.read_volatile() };
            unsafe { status.write_volatile(negotiation::ACK) };
            let ack = unsafe { status.read_volatile() };
            unsafe { status.write_volatile(negotiation::DRIVER) };
            let driver = unsafe { status.read_volatile() };
            unsafe { driver_select.write_volatile(1u32.to_le()) };
            let driver_select_during = u32::from_le(unsafe { driver_select.read_volatile() });
            unsafe { driver_feature.write_volatile(negotiation::VERSION_ONE.to_le()) };
            let accepted_bank1 = u32::from_le(unsafe { driver_feature.read_volatile() });
            unsafe { driver_select.write_volatile(driver_select_before.to_le()) };
            let driver_select_after = u32::from_le(unsafe { driver_select.read_volatile() });
            unsafe { status.write_volatile(negotiation::FEATURES_OK) };
            let features_ok = unsafe { status.read_volatile() };
            // Always reset the QEMU device after provisional negotiation.
            unsafe { status.write_volatile(0) };
            let mut final_reset = unsafe { status.read_volatile() };
            let mut reset_completed = final_reset == 0;
            for _ in 0..4096 {
                if reset_completed { break; }
                core::hint::spin_loop();
                final_reset = unsafe { status.read_volatile() };
                reset_completed = final_reset == 0;
            }
            let queue_after = u16::from_le(unsafe { queue.read_volatile() });
            Some(negotiation::Observation {
                before, initial_reset, ack, driver, features_ok,
                final_reset, reset_completed,
                driver_select_before, driver_select_during, driver_select_after,
                accepted_bank1, queue_before, queue_after,
            })
        } else { None }
    } else { None };

    // Mandatory unmap, including when readback is implausible.
    let Ok((unmapped, flush)) = mapper.unmap(page) else {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_FAIL unmap");
        return false;
    };
    flush.flush();
    if !mapped_ok || unmapped.start_address().as_u64() != span.physical_page
        || mapper.translate_addr(target).is_some()
    {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_FAIL mapping_not_restored");
        return false;
    }
    let Some(readback) = transaction else {
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_FAIL preflight_not_unclaimed");
        return false;
    };
    if let Err(error) = negotiation::verify(readback) {
        serial::write_fmt(format_args!(
            "WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_FAIL registers={error:?}\n"
        ));
        return false;
    }

    serial::write_fmt(format_args!(
        "WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_OK accepted_version1={} ack=1 driver=3 features_ok=11 status_writes=5 feature_writes=1 selector_writes=2 reset=0 queue_enabled=0 dma=0\n",
        readback.accepted_bank1
    ));
    true
}
