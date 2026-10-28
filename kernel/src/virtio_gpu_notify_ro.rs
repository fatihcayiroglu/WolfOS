//! QEMU-only: read the queue0 notify offset from proven common config,
//! resolve notification MMIO strictly inside the sized preferred BAR.
//! NEVER reads the write-only notify port, never notifies a queue.
use limine::memmap::{
    Entry,MEMMAP_USABLE,MEMMAP_BOOTLOADER_RECLAIMABLE,
    MEMMAP_EXECUTABLE_AND_MODULES,MEMMAP_ACPI_RECLAIMABLE,MEMMAP_ACPI_NVS,
    MEMMAP_FRAMEBUFFER,
};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator,Mapper,OffsetPageTable,Page,PageTable,PageTableFlags,
    PhysFrame,Size4KiB,Translate,
};
use x86_64::{PhysAddr,VirtAddr};
use crate::{pci,pmm,serial,virtio_gpu_mmio_contract as mmio,
    virtio_gpu_controlq_ro_contract as q,
    virtio_gpu_transport_preflight_contract as preflight,
    virtio_gpu_notify_contract as notify};
const TEST_SLOT:u64=0x0000_4000_0000_a000;
struct TableAllocator;
unsafe impl FrameAllocator<Size4KiB> for TableAllocator{
    fn allocate_frame(&mut self)->Option<PhysFrame>{
        Some(PhysFrame::containing_address(PhysAddr::new(pmm::allocate_frame()?)))
    }
}
fn disjoint_from_ram_and_framebuffer(base:u64,entries:&[&Entry])->bool{
    let Some(end)=base.checked_add(mmio::PAGE_BYTES) else{return false;};
    for e in entries.iter().copied(){
        if !matches!(e.type_,
            MEMMAP_USABLE | MEMMAP_BOOTLOADER_RECLAIMABLE |
            MEMMAP_EXECUTABLE_AND_MODULES | MEMMAP_ACPI_RECLAIMABLE |
            MEMMAP_ACPI_NVS | MEMMAP_FRAMEBUFFER
        ){continue;}
        let Some(last)=e.base.checked_add(e.length) else{return false;};
        if base<last && e.base<end{return false;}
    }
    true
}
pub fn verify(hhdm:u64,entries:&[&Entry],
    common:pci::QemuBarWindow,cappci:pci::QemuNotifyWindow)->bool {
    if x86_64::instructions::interrupts::are_enabled(){
        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL interrupts_enabled");
        return false;
    }
    let span=match mmio::check(mmio::Window{
        bar_base:common.physical_base,bar_bytes:common.aperture_bytes,
        offset:common.common_offset,length:common.common_length,
        is_memory:common.is_memory,
    }){
        Ok(s)=>s,Err(e)=>{
            serial::write_fmt(format_args!("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL common={e:?}\n"));
            return false;
        }
    };
    if !disjoint_from_ram_and_framebuffer(span.physical_page,entries){
        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL overlaps_ram");
        return false;
    }
    if cappci.physical_base!=common.physical_base ||
        cappci.aperture_bytes!=common.aperture_bytes {
        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL aperture_changed");
        return false;
    }
    let (cr3_frame,_)=Cr3::read();
    let Some(pml4_va)=hhdm.checked_add(cr3_frame.start_address().as_u64())
        .and_then(|a|VirtAddr::try_new(a).ok()) else {
        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL bad_cr3");
        return false;
    };
    let Some(hhdm_va)=VirtAddr::try_new(hhdm).ok() else{
        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL bad_hhdm");
        return false;
    };
    // SAFETY: BSP only, interrupts disabled, PML4 mapped in Limine HHDM.
    let pml4=unsafe{&mut *pml4_va.as_mut_ptr::<PageTable>()};
    let mut mapper=unsafe{OffsetPageTable::new(pml4,hhdm_va)};
    let target=VirtAddr::new(TEST_SLOT);
    if mapper.translate_addr(target).is_some(){
        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL slot_occupied");
        return false;
    }
    let page=Page::<Size4KiB>::containing_address(target);
    let frame=PhysFrame::<Size4KiB>::containing_address(
        PhysAddr::new(span.physical_page)
    );
    // no writable or USER_ACCESSIBLE flag, UC-ish memory mapping.
    let flags=PageTableFlags::PRESENT|PageTableFlags::NO_CACHE|
        PageTableFlags::WRITE_THROUGH;
    let Ok(flush)=(unsafe{mapper.map_to(page,frame,flags,&mut TableAllocator)})else{
        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL map");
        return false;
    };
    flush.flush();
    let mapped=mapper.translate_addr(target).map(|p|p.as_u64())==
        Some(span.physical_page);
    let snapshot=if mapped{
        let start=TEST_SLOT+span.page_offset;
        let read16=|offset:u64|->u16{
            u16::from_le(unsafe{((start+offset)as *const u16).read_volatile()})
        };
        let status=unsafe{
            ((start+preflight::DEVICE_STATUS_OFFSET)as *const u8).read_volatile()
        };
        Some((read16(preflight::QUEUE_SELECTOR_OFFSET),
              read16(preflight::QUEUE_ENABLE_OFFSET),
              read16(preflight::QUEUE_SIZE_OFFSET),
              read16(q::QUEUE_NOTIFY_OFF),status))
    }else{None};
    // Always remove temporary common-config mapping before checking results.
    let Ok((unmapped,flush))=mapper.unmap(page)else{
        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL unmap");
        return false;
    };
    flush.flush();
    if !mapped || unmapped.start_address().as_u64()!=span.physical_page ||
        mapper.translate_addr(target).is_some(){
        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL mapping_not_restored");
        return false;
    }
    let Some((selection,enable,size,queue_off,status))=snapshot else{
        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL unreadable");
        return false;
    };
    if selection!=0 || enable!=0 || size<2 || status!=0{
        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL postreset_queue_state");
        return false;
    }
    let cap=notify::Capability{
        bar_base:cappci.physical_base,bar_bytes:cappci.aperture_bytes,
        cap_offset:cappci.notify_offset,cap_length:cappci.notify_length,
        multiplier:cappci.notify_multiplier,
        same_measured_bar:cappci.same_measured_bar,
    };
    let resolved=match notify::resolve(cap,queue_off){
        Ok(resolved)=>resolved,Err(error)=>{
            serial::write_fmt(format_args!("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL notify={error:?}\n"));
            return false;
        }
    };
    if !disjoint_from_ram_and_framebuffer(resolved.physical_page,entries){
        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_FAIL notify_overlaps_ram");
        return false;
    }
    // register points at a validated write-only MMIO location. Do not read.
    serial::write_fmt(format_args!(
        "WOLFOS_VIRTIO_GPU_NOTIFY_RO_OK queue=0 notify_off={} multiplier={} cap_offset={} cap_length={} physical_bounded=1 ro=1 notify_reads=0 writes=0 dma=0\n",
        queue_off,cappci.notify_multiplier,cappci.notify_offset,
        cappci.notify_length
    ));
    true
}
