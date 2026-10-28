//! QEMU virtio-vga only: register three live split-ring pages with controlq0,
//! verify MMIO readback, then reset before freeing them. Never DRIVER_OK,
//! notify, GPU command, or physical device access. Fails closed on reset.
use core::sync::atomic::{fence,Ordering};
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
use x86_64::{PhysAddr,VirtAddr};
use crate::{
    pci,pmm,serial,
    virtio_gpu_mmio_contract as mmio,
    virtio_gpu_controlq_ro_contract as queue,
    virtio_gpu_controlq_tx_contract as tx,
    virtio_gpu_transport_preflight_contract as offsets,
};
const TEST_SLOT:u64=0x0000_4000_0000_9000;
struct TableAllocator;
unsafe impl FrameAllocator<Size4KiB> for TableAllocator {
    fn allocate_frame(&mut self)->Option<PhysFrame> {
        Some(PhysFrame::containing_address(PhysAddr::new(pmm::allocate_frame()?)))
    }
}
fn disjoint_from_ram_and_framebuffer(base:u64, entries:&[&Entry])->bool {
    let Some(end)=base.checked_add(mmio::PAGE_BYTES) else{return false;};
    for entry in entries.iter().copied() {
        if !matches!(entry.type_,
            MEMMAP_USABLE | MEMMAP_BOOTLOADER_RECLAIMABLE |
            MEMMAP_EXECUTABLE_AND_MODULES | MEMMAP_ACPI_RECLAIMABLE |
            MEMMAP_ACPI_NVS | MEMMAP_FRAMEBUFFER
        ) {continue;}
        let Some(entry_end)=entry.base.checked_add(entry.length) else{return false;};
        if base < entry_end && entry.base < end {return false;}
    }
    true
}
fn valid_layout(l:queue::Layout)->bool {
    l.selected>=2 && l.selected.is_power_of_two() &&
    l.desc_pages==1 && l.avail_pages==1 && l.used_pages==1 &&
    l.desc_bytes<=queue::PAGE_BYTES && l.avail_bytes<=queue::PAGE_BYTES &&
    l.used_bytes<=queue::PAGE_BYTES
}
pub fn verify(hhdm:u64, entries:&[&Entry], window:pci::QemuBarWindow, layout:queue::Layout)->bool {
    if !valid_layout(layout) || x86_64::instructions::interrupts::are_enabled() {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_TX_FAIL layout_or_irqs");
        return false;
    }
    let span=match mmio::check(mmio::Window {
        bar_base:window.physical_base,bar_bytes:window.aperture_bytes,
        offset:window.common_offset,length:window.common_length,
        is_memory:window.is_memory,
    }) {
        Ok(span)=>span,
        Err(error)=>{
            serial::write_fmt(format_args!("WOLFOS_VIRTIO_GPU_CONTROLQ_TX_FAIL window={error:?}\n"));
            return false;
        }
    };
    if !disjoint_from_ram_and_framebuffer(span.physical_page,entries) {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_TX_FAIL mmio_overlaps_ram");
        return false;
    }
    let (cr3_frame,_)=Cr3::read();
    let Some(pml4_va)=hhdm.checked_add(cr3_frame.start_address().as_u64())
        .and_then(|a|VirtAddr::try_new(a).ok()) else {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_TX_FAIL bad_cr3");
        return false;
    };
    let Some(hhdm_va)=VirtAddr::try_new(hhdm).ok() else {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_TX_FAIL bad_hhdm");
        return false;
    };
    // SAFETY: test is BSP-only with interrupts off and no AP. Active page
    // tables are exclusively owned here; the PML4 is RAM in Limine HHDM.
    let pml4=unsafe{&mut *pml4_va.as_mut_ptr::<PageTable>()};
    let mut mapper=unsafe{OffsetPageTable::new(pml4,hhdm_va)};
    let target=VirtAddr::new(TEST_SLOT);
    if mapper.translate_addr(target).is_some() {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_TX_FAIL slot_occupied");
        return false;
    }
    let page=Page::<Size4KiB>::containing_address(target);
    let physical=PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(span.physical_page));
    let flags=PageTableFlags::PRESENT | PageTableFlags::WRITABLE |
        PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH;
    // SAFETY: one non-user, validated QEMU PCI BAR page, non-overlapping
    // physical RAM and framebuffer, mapped only for this opt-in test.
    let Ok(flush)= (unsafe{mapper.map_to(page,physical,flags,&mut TableAllocator)}) else {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_TX_FAIL map");
        return false;
    };
    flush.flush();
    let mapped_ok=mapper.translate_addr(target).map(|p|p.as_u64())==Some(span.physical_page);

    // Baseline after any persistent page-table frame allocations.
    let baseline=pmm::statistics().allocated_frames;
    let mut frames=[0u64;3];
    let mut acquired=0usize;
    if mapped_ok {
        for frame in &mut frames {
            match pmm::allocate_frame() {
                Some(addr)=>{*frame=addr;acquired+=1;}
                None=>break,
            }
        }
    }
    let addresses_ok=acquired==3 &&
        queue::validate_future_regions(layout,frames[0],frames[1],frames[2]).is_ok();
    let mut zero_verified=addresses_ok;
    if addresses_ok {
        for frame in frames {
            let Some(va)=hhdm.checked_add(frame).and_then(|a|VirtAddr::try_new(a).ok()) else {
                zero_verified=false;break;
            };
            // SAFETY: exclusively owned, aligned PMM RAM frame in HHDM,
            // not a PCI register, with no other QEMU CPU/IRQ running.
            let ptr=va.as_mut_ptr::<u8>();
            unsafe{core::ptr::write_bytes(ptr,0,queue::PAGE_BYTES as usize);}
            for i in 0..queue::PAGE_BYTES as usize {
                if unsafe{ptr.add(i).read_volatile()}!=0 {
                    zero_verified=false;break;
                }
            }
            if !zero_verified {break;}
        }
    }
    fence(Ordering::SeqCst);

    let mut exposed_to_device=false;
    let mut reset_confirmed=false;
    let mut observation:Option<tx::Observation>=None;
    if zero_verified {
        let base=TEST_SLOT+span.page_offset;
        let read16=|at:u64| ->u16 {
            u16::from_le(unsafe{((base+at) as *const u16).read_volatile()})
        };
        let read32=|at:u64| ->u32 {
            u32::from_le(unsafe{((base+at) as *const u32).read_volatile()})
        };
        let read64=|at:u64| ->u64 {
            u64::from(read32(at)) | (u64::from(read32(at+4))<<32)
        };
        let write16=|at:u64,v:u16|{
            unsafe{((base+at) as *mut u16).write_volatile(v.to_le());}
        };
        let write32=|at:u64,v:u32|{
            unsafe{((base+at) as *mut u32).write_volatile(v.to_le());}
        };
        let write64=|at:u64,v:u64|{
            write32(at,v as u32);
            write32(at+4,(v>>32) as u32);
        };
        let status_ptr=(base+offsets::DEVICE_STATUS_OFFSET) as *mut u8;
        let status_before=unsafe{status_ptr.read_volatile()};
        let enabled_before=read16(offsets::QUEUE_ENABLE_OFFSET);
        let size_before=read16(offsets::QUEUE_SIZE_OFFSET);
        let driver_selector_before=read32(8);
        let clean_preflight=status_before==0 && enabled_before==0 &&
            read16(offsets::QUEUE_SELECTOR_OFFSET)==0 &&
            read32(offsets::FEATURE_SELECTOR_OFFSET)==0 &&
            driver_selector_before==0 &&
            read16(queue::NUM_QUEUES)>=2 && size_before>=layout.selected &&
            read64(queue::QUEUE_DESC)==0 &&
            read64(queue::QUEUE_DRIVER)==0 &&
            read64(queue::QUEUE_DEVICE)==0;
        if clean_preflight {
            // Negotiate only VERSION_1. Do not ever write DRIVER_OK.
            unsafe{status_ptr.write_volatile(0)};
            let initial_reset=unsafe{status_ptr.read_volatile()};
            unsafe{status_ptr.write_volatile(1)};
            let ack=unsafe{status_ptr.read_volatile()};
            unsafe{status_ptr.write_volatile(3)};
            let driver=unsafe{status_ptr.read_volatile()};
            write32(8,1);
            let driver_selector_during=read32(8);
            write32(12,1);
            let accepted_version1=read32(12);
            write32(8,0);
            let driver_selector_after=read32(8);
            unsafe{status_ptr.write_volatile(11)};
            let features_ok=unsafe{status_ptr.read_volatile()};
            let handshake_ok=initial_reset==0 && ack==1 && driver==3 &&
                driver_selector_during==1 && accepted_version1==1 &&
                driver_selector_after==0 && features_ok==11;
            let mut size_written=0;
            let mut desc_written=0;
            let mut avail_written=0;
            let mut used_written=0;
            let mut enabled_written=0;
            if handshake_ok {
                write16(offsets::QUEUE_SELECTOR_OFFSET,0);
                write16(offsets::QUEUE_SIZE_OFFSET,layout.selected);
                size_written=read16(offsets::QUEUE_SIZE_OFFSET);
                // Mark as exposed BEFORE first physical address register
                // write. No failure branch may release these pages unless
                // full device reset confirms both status0 and queue_disable.
                exposed_to_device=true;
                write64(queue::QUEUE_DESC,frames[0]);
                write64(queue::QUEUE_DRIVER,frames[1]);
                write64(queue::QUEUE_DEVICE,frames[2]);
                fence(Ordering::SeqCst);
                write16(offsets::QUEUE_ENABLE_OFFSET,1);
                desc_written=read64(queue::QUEUE_DESC);
                avail_written=read64(queue::QUEUE_DRIVER);
                used_written=read64(queue::QUEUE_DEVICE);
                enabled_written=read16(offsets::QUEUE_ENABLE_OFFSET);
            }
            // UNCONDITIONAL device-wide reset after first status mutation.
            // Reading stale queue address fields after reset is not a leak:
            // spec requires no active queue, not zeroed address registers.
            unsafe{status_ptr.write_volatile(0)};
            fence(Ordering::SeqCst);
            let mut final_status=unsafe{status_ptr.read_volatile()};
            let mut final_enabled=read16(offsets::QUEUE_ENABLE_OFFSET);
            for _ in 0..4096 {
                if final_status==0 && final_enabled==0 {break;}
                core::hint::spin_loop();
                final_status=unsafe{status_ptr.read_volatile()};
                final_enabled=read16(offsets::QUEUE_ENABLE_OFFSET);
            }
            reset_confirmed=final_status==0 && final_enabled==0;
            observation=Some(tx::Observation {
                status_before,enabled_before,size_before,driver_selector_before,
                initial_reset,ack,driver,driver_selector_during,accepted_version1,
                driver_selector_after,features_ok,size_written,desc_written,
                avail_written,used_written,enabled_written,final_status,
                final_enabled,reset_confirmed,
            });
        }
    }
    let Ok((unmapped,flush))=mapper.unmap(page) else {
        // A failed unmap does not justify freeing pages still potentially
        // visible to an unreset device. CI must fail.
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_TX_FAIL unmap");
        return false;
    };
    flush.flush();
    let mapping_restored=mapped_ok &&
        unmapped.start_address().as_u64()==span.physical_page &&
        mapper.translate_addr(target).is_none();

    // Fail closed: if any MMIO queue physical address was written and reset
    // could not be proven, deliberately quarantine frames until VM teardown.
    let may_free=!exposed_to_device || reset_confirmed;
    let mut released=0usize;
    let mut free_errors=0usize;
    if may_free {
        for frame in frames[..acquired].iter().rev().copied() {
            if pmm::free_frame(frame).is_ok() {released+=1;} else {free_errors+=1;}
        }
    }
    let after=pmm::statistics().allocated_frames;
    let balanced=acquired==3 && released==3 && free_errors==0 &&
        after==baseline;
    let verified=observation.map(|o|tx::validate(
        o,layout.selected,frames[0],frames[1],frames[2]
    ).is_ok()).unwrap_or(false);
    if !mapping_restored || !addresses_ok || !zero_verified ||
        !verified || !balanced || !reset_confirmed || !exposed_to_device
    {
        serial::write_fmt(format_args!(
            "WOLFOS_VIRTIO_GPU_CONTROLQ_TX_FAIL acquired={} released={} quarantined={} reset={} observation={} map={} zero={} balanced={}\n",
            acquired,released,acquired-released,reset_confirmed,verified,
            mapping_restored,zero_verified,balanced
        ));
        return false;
    }
    serial::write_fmt(format_args!(
        "WOLFOS_VIRTIO_GPU_CONTROLQ_TX_OK layout_n={} desc_written=1 avail_written=1 used_written=1 queue_enabled=1 features_ok=11 driver_ok=0 notify=0 reset=0 queue_disabled=1 frames_released=3 pmm_leak=0 qemu_only=1\n",
        layout.selected
    ));
    true
}
