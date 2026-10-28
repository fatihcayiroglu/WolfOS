//! QEMU-only real VirtIO-GPU controlq GET_DISPLAY_INFO transaction.
//! Exactly 1 request + 1 writable response descriptor; verify used ring
//! and full device reset BEFORE freeing 5 exclusively owned PMM frames.
//! No hardware GPU, disk, rendering, or unbounded DMA.
use core::sync::atomic::{fence,Ordering};
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
use crate::{
    pci,pmm,serial,
    virtio_gpu_mmio_contract as mmio,
    virtio_gpu_controlq_ro_contract as queue,
    virtio_gpu_transport_preflight_contract as off,
    virtio_gpu_notify_contract as notify,
    virtio_gpu_display_info_contract as display,
};

#[cfg(feature="qemu-virtio-gpu-edid-live-smoke")]
use crate::{
    virtio_gpu_edid_wire as edid,virtio_gpu_edid_live_contract as live,
    display_mode_policy as mode_policy,
};
#[cfg(feature="qemu-virtio-gpu-resource2d-smoke")]
use crate::virtio_gpu_resource2d_contract as resource;
#[cfg(feature="qemu-virtio-gpu-attach-backing-smoke")]
use crate::virtio_gpu_backing_contract as backing;
#[cfg(feature="qemu-virtio-gpu-transfer2d-smoke")]
use crate::virtio_gpu_transfer2d_contract as transfer;
#[cfg(feature="qemu-virtio-gpu-scanout-live-smoke")]
use crate::virtio_gpu_scanout_contract as scanout;
#[cfg(feature="qemu-virtio-gpu-edid-live-smoke")]
#[derive(Clone,Copy)]
struct EdidProof{size:u32,modes:usize,width:u32,height:u32,refresh_millihz:u32}
#[cfg(feature="qemu-virtio-gpu-edid-live-smoke")]
fn query_edid(vas:&[u64;FRAMES],frames:&[u64;FRAMES],port:u64)
    ->Result<EdidProof,&'static str>{
    // Prior QEMU device MMIO probe proved a minimum of one scanout.
    const FENCE:u64=0x574f_4c46_4544_4944;
    let request=edid::encode_get_edid(
        edid::VIRTIO_GPU_F_EDID,1,0,1,FENCE
    ).map_err(|_|"request_contract")?;
    let request_ptr=vas[3] as *mut u8;
    let response_ptr=vas[4] as *mut u8;
    // First DMA has completed. Scrub the old response before reuse.
    unsafe{core::ptr::write_bytes(response_ptr,0,edid::RESPONSE_LEN);}
    for n in 0..edid::RESPONSE_LEN{
        if unsafe{response_ptr.add(n).read_volatile()}!=0{
            return Err("response_not_zero");
        }
    }
    for (i,b) in request.bytes.iter().copied().enumerate(){
        unsafe{request_ptr.add(i).write_volatile(b);}
    }
    let desc=vas[0] as *mut Desc;
    unsafe{
        desc.write_volatile(Desc{
            addr:frames[3].to_le(),len:(edid::REQUEST_LEN as u32).to_le(),
            flags:1u16.to_le(),next:1u16.to_le(),
        });
        desc.add(1).write_volatile(Desc{
            addr:frames[4].to_le(),len:(edid::RESPONSE_LEN as u32).to_le(),
            flags:2u16.to_le(),next:0,
        });
        ((vas[1]+6)as *mut u16).write_volatile(0u16.to_le());
    }
    fence(Ordering::SeqCst);
    unsafe{((vas[1]+2)as *mut u16).write_volatile(2u16.to_le());}
    fence(Ordering::SeqCst);
    unsafe{(port as *mut u16).write_volatile(0u16.to_le());}
    for _ in 0..2_000_000u32{
        if u16::from_le(unsafe{
            ((vas[2]+2)as *const u16).read_volatile()
        })>=2{break;}
        core::hint::spin_loop();
    }
    fence(Ordering::SeqCst);
    let idx=u16::from_le(unsafe{((vas[2]+2)as *const u16).read_volatile()});
    let head=u32::from_le(unsafe{((vas[2]+12)as *const u32).read_volatile()});
    let len=u32::from_le(unsafe{((vas[2]+16)as *const u32).read_volatile()});
    if let Err(e)=live::validate(true,idx,head,len){
        serial::write_fmt(format_args!(
            "WOLFOS_VIRTIO_GPU_EDID_LIVE_FAIL second_used={e:?} idx={idx} head={head} len={len}\n"
        ));
        return Err("used_ring");
    }
    let mut data=[0u8;edid::RESPONSE_LEN];
    for (i,b) in data.iter_mut().enumerate(){
        *b=unsafe{response_ptr.add(i).read_volatile()};
    }
    let verified=match edid::decode_get_edid(request,1,&data){
        Ok(v)=>v,
        Err(e)=>{
            let t=u32::from_le_bytes([data[0],data[1],data[2],data[3]]);
            let size=u32::from_le_bytes([data[24],data[25],data[26],data[27]]);
            serial::write_fmt(format_args!(
                "WOLFOS_VIRTIO_GPU_EDID_LIVE_FAIL decode={e:?} type={t} size={size}\n"
            ));
            return Err("decode");
        }
    };
    // The genuine monitor EDID is not a GPU scanout timing proof. QEMU's
    // GET_DISPLAY_INFO does not specify a pixel-clock/link limit, so the
    // live path must refuse automatic (or manual) selection for now.
    if verified.choose_with_gpu_evidence(
        1,None,mode_policy::UserChoice::AUTOMATIC
    )!=Err(edid::VirtioEdidError::MissingGpuTimingEvidence){
        return Err("unproven_gpu_mode_accepted");
    }
    let mut preferred=verified.modes().first().copied().ok_or("zero_modes")?;
    for m in verified.modes(){
        if m.preferred{preferred=*m;break;}
    }
    let size=u32::from_le_bytes([data[24],data[25],data[26],data[27]]);
    Ok(EdidProof{
        size,modes:verified.modes().len(),width:preferred.width,
        height:preferred.height,refresh_millihz:preferred.refresh_millihz,
    })
}


#[cfg(feature="qemu-virtio-gpu-resource2d-smoke")]
fn send_resource_command(
    vas:&[u64;FRAMES], frames:&[u64;FRAMES], notify_port:u64,
    selected:u16, next_idx:u16, request:&[u8], request_fence:u64,
) -> Result<(),&'static str> {
    if request.is_empty() || request.len()>queue::PAGE_BYTES as usize {
        return Err("request_length");
    }
    let slot=resource::ring_slot(next_idx,selected).map_err(|_|"queue_slot")?;
    let request_ptr=vas[3] as *mut u8;
    let response_ptr=vas[4] as *mut u8;
    // EDID DMA has completed. Clear its entire 1056B response before
    // exposing this same PMM-owned page to a new 24B response.
    unsafe {
        core::ptr::write_bytes(response_ptr,0,edid::RESPONSE_LEN);
        core::ptr::write_bytes(request_ptr,0,queue::PAGE_BYTES as usize);
    }
    for n in 0..edid::RESPONSE_LEN {
        if unsafe { response_ptr.add(n).read_volatile() } != 0 {
            return Err("response_not_zero");
        }
    }
    for (i,b) in request.iter().copied().enumerate() {
        unsafe { request_ptr.add(i).write_volatile(b); }
    }
    let desc=vas[0] as *mut Desc;
    unsafe {
        desc.write_volatile(Desc {
            addr:frames[3].to_le(),len:(request.len() as u32).to_le(),
            flags:1u16.to_le(),next:1u16.to_le(),
        });
        desc.add(1).write_volatile(Desc {
            addr:frames[4].to_le(),len:(resource::RESPONSE_BYTES as u32).to_le(),
            flags:2u16.to_le(),next:0,
        });
        ((vas[1]+4+u64::from(slot)*2)as *mut u16).write_volatile(0u16.to_le());
    }
    fence(Ordering::SeqCst);
    unsafe { ((vas[1]+2)as *mut u16).write_volatile(next_idx.to_le()); }
    fence(Ordering::SeqCst);
    unsafe { (notify_port as *mut u16).write_volatile(0u16.to_le()); }
    for _ in 0..2_000_000u32 {
        if u16::from_le(unsafe{
            ((vas[2]+2)as *const u16).read_volatile()
        })>=next_idx { break; }
        core::hint::spin_loop();
    }
    fence(Ordering::SeqCst);
    let idx=u16::from_le(unsafe{((vas[2]+2)as *const u16).read_volatile()});
    let used=vas[2]+4+u64::from(slot)*8;
    let head=u32::from_le(unsafe{(used as *const u32).read_volatile()});
    let len=u32::from_le(unsafe{((used+4)as *const u32).read_volatile()});
    let mut response=[0u8;resource::RESPONSE_BYTES];
    if idx==next_idx {
        for (i,b) in response.iter_mut().enumerate() {
            *b=unsafe{response_ptr.add(i).read_volatile()};
        }
    }
    if let Err(e)=resource::validate_completion(
        next_idx,idx,head,len,&response,request_fence
    ) {
        serial::write_fmt(format_args!(
            "WOLFOS_VIRTIO_GPU_RESOURCE2D_FAIL command_idx={next_idx} used={idx} head={head} len={len} response={e:?}\n"
        ));
        return Err("completion");
    }
    Ok(())
}

#[cfg(feature="qemu-virtio-gpu-transfer2d-smoke")]
fn verify_transfer_pattern(vas:&[u64;FRAMES])->Result<(),&'static str>{
    for page in 0..transfer::BACKING_PAGES{
        let ptr=vas[5+page] as *const u8;
        for at in 0..transfer::PAGE_BYTES{
            let expected=transfer::pattern_byte(page,at).map_err(|_|"pattern_contract")?;
            if unsafe{ptr.add(at).read_volatile()}!=expected{
                return Err("backing_pattern_corrupted");
            }
        }
    }
    Ok(())
}
#[cfg(feature="qemu-virtio-gpu-transfer2d-smoke")]
fn paint_transfer_pattern(vas:&[u64;FRAMES])->Result<(),&'static str>{
    for page in 0..transfer::BACKING_PAGES{
        let ptr=vas[5+page] as *mut u8;
        for at in 0..transfer::PAGE_BYTES{
            let value=transfer::pattern_byte(page,at).map_err(|_|"pattern_contract")?;
            unsafe{ptr.add(at).write_volatile(value);}
        }
    }
    fence(Ordering::SeqCst);
    verify_transfer_pattern(vas)
}

#[cfg(feature="qemu-virtio-gpu-scanout-live-smoke")]
fn await_host_capture(stage:&str,ack:u8)->Result<(),&'static str>{
    serial::write_fmt(format_args!(
        "WOLFOS_VIRTIO_GPU_SCANOUT_CAPTURE stage={stage}\n"
    ));
    // The external QEMU-only QMP screendump gate must release this wait
    // with exactly one stage token. No timer-based screenshot guessing.
    for _ in 0..600_000_000u32{
        if let Some(got)=serial::read_byte_nonblocking(){
            if got==ack{return Ok(());}
            return Err("unexpected_capture_ack");
        }
        core::hint::spin_loop();
    }
    Err("capture_timeout")
}

#[cfg(feature="qemu-virtio-gpu-resource2d-smoke")]
fn query_resource2d(
    vas:&[u64;FRAMES], frames:&[u64;FRAMES], notify_port:u64, selected:u16,
) -> Result<(),&'static str> {
    const CREATE_FENCE:u64=0x574f_4c46_3244_4352;
    const UNREF_FENCE:u64=0x574f_4c46_3244_5552;
    #[cfg(feature="qemu-virtio-gpu-attach-backing-smoke")]
    const ATTACH_FENCE:u64=0x574f_4c46_3244_4154;
    #[cfg(feature="qemu-virtio-gpu-attach-backing-smoke")]
    const DETACH_FENCE:u64=0x574f_4c46_3244_4454;
    #[cfg(feature="qemu-virtio-gpu-transfer2d-smoke")]
    const TRANSFER_FENCE:u64=0x574f_4c46_3244_5452;
    #[cfg(feature="qemu-virtio-gpu-scanout-live-smoke")]
    const SET_FENCE:u64=0x574f_4c46_3244_5343;
    #[cfg(feature="qemu-virtio-gpu-scanout-live-smoke")]
    const FLUSH_FENCE:u64=0x574f_4c46_3244_464c;
    #[cfg(feature="qemu-virtio-gpu-scanout-live-smoke")]
    const CLEAR_FENCE:u64=0x574f_4c46_3244_434c;
    #[cfg(feature="qemu-virtio-gpu-scanout-live-smoke")]
    scanout::unique_fences([
        CREATE_FENCE,ATTACH_FENCE,TRANSFER_FENCE,SET_FENCE,FLUSH_FENCE,
        CLEAR_FENCE,DETACH_FENCE,UNREF_FENCE
    ]).map_err(|_|"scanout_fence_reused")?;
    #[cfg(feature="qemu-virtio-gpu-transfer2d-smoke")]
    transfer::distinct_fences([
        CREATE_FENCE,ATTACH_FENCE,TRANSFER_FENCE,DETACH_FENCE,UNREF_FENCE
    ]).map_err(|_|"transfer_fence_reused")?;
    #[cfg(feature="qemu-virtio-gpu-attach-backing-smoke")]
    backing::distinct_fences([CREATE_FENCE,ATTACH_FENCE,DETACH_FENCE,UNREF_FENCE])
        .map_err(|_|"fence_reused")?;
    let create=resource::create(resource::RESOURCE_ID,64,64,CREATE_FENCE)
        .map_err(|_|"create_wire")?;
    send_resource_command(vas,frames,notify_port,selected,3,
        &create.bytes[..create.len],create.fence)?;
    #[cfg(feature="qemu-virtio-gpu-attach-backing-smoke")]
    {
        // Four zeroed, PMM-owned 4KiB pages are disjoint from controlq pages,
        // and remain pinned until detach acknowledgement AND device reset.
        let pages=[frames[5],frames[6],frames[7],frames[8]];
        #[cfg(feature="qemu-virtio-gpu-transfer2d-smoke")]
        paint_transfer_pattern(vas)?;
        let attach=backing::attach(resource::RESOURCE_ID,true,pages,ATTACH_FENCE)
            .map_err(|_|"attach_wire")?;
        send_resource_command(vas,frames,notify_port,selected,4,
            &attach.bytes[..attach.len],attach.fence)?;
        #[cfg(feature="qemu-virtio-gpu-transfer2d-smoke")]
        {
            // Genuine host-read transfer: 64x64x4 bytes, exact offset zero.
            // The device response proves acceptance, NOT host pixel readback.
            let command=transfer::encode(resource::RESOURCE_ID,true,64,64,0,TRANSFER_FENCE)
                .map_err(|_|"transfer_wire")?;
            fence(Ordering::SeqCst);
            send_resource_command(vas,frames,notify_port,selected,5,
                &command.bytes,command.fence)?;
            // The device must not modify our four guest-owned source pages.
            verify_transfer_pattern(vas)?;
        }
        #[cfg(feature="qemu-virtio-gpu-scanout-live-smoke")]
        {
            // First capture the QEMU display BEFORE this driver binds it.
            await_host_capture("baseline",b'B')?;
            let set=scanout::set(resource::RESOURCE_ID,true,0,0,64,64,SET_FENCE)
                .map_err(|_|"scanout_set_wire")?;
            send_resource_command(vas,frames,notify_port,selected,6,
                &set.bytes,set.fence)?;
            let flush=scanout::flush(resource::RESOURCE_ID,true,0,0,64,64,FLUSH_FENCE)
                .map_err(|_|"scanout_flush_wire")?;
            send_resource_command(vas,frames,notify_port,selected,7,
                &flush.bytes,flush.fence)?;
            // Host captures a QMP PPM; kernel only observes the host ACK.
            await_host_capture("active",b'A')?;
            let clear=scanout::disable(true,CLEAR_FENCE)
                .map_err(|_|"scanout_disable_wire")?;
            send_resource_command(vas,frames,notify_port,selected,8,
                &clear.bytes,clear.fence)?;
            // Host verifies the scanout pattern disappears. Original console
            // geometry is NOT restored by resource_id=0 in this QEMU model.
            await_host_capture("disabled",b'D')?;
        }
        let detach=backing::detach(resource::RESOURCE_ID,true,DETACH_FENCE)
            .map_err(|_|"detach_wire")?;
        #[cfg(feature="qemu-virtio-gpu-scanout-live-smoke")]
        let detach_index=9;
        #[cfg(all(feature="qemu-virtio-gpu-transfer2d-smoke",
                  not(feature="qemu-virtio-gpu-scanout-live-smoke")))]
        let detach_index=6;
        #[cfg(not(feature="qemu-virtio-gpu-transfer2d-smoke"))]
        let detach_index=5;
        send_resource_command(vas,frames,notify_port,selected,detach_index,
            &detach.bytes[..detach.len],detach.fence)?;
    }
    // Acknowledged explicit host-resource destruction is mandatory.
    let unref=resource::unref(resource::RESOURCE_ID,true,UNREF_FENCE)
        .map_err(|_|"unref_wire")?;
    #[cfg(feature="qemu-virtio-gpu-scanout-live-smoke")]
    let unref_index=10;
    #[cfg(all(feature="qemu-virtio-gpu-transfer2d-smoke",
              not(feature="qemu-virtio-gpu-scanout-live-smoke")))]
    let unref_index=7;
    #[cfg(all(feature="qemu-virtio-gpu-attach-backing-smoke",
              not(feature="qemu-virtio-gpu-transfer2d-smoke")))]
    let unref_index=6;
    #[cfg(not(feature="qemu-virtio-gpu-attach-backing-smoke"))]
    let unref_index=4;
    send_resource_command(vas,frames,notify_port,selected,unref_index,
        &unref.bytes[..unref.len],unref.fence)?;
    Ok(())
}

const SLOT:u64=0x0000_4000_0000_b000;
#[cfg(feature="qemu-virtio-gpu-attach-backing-smoke")]
const FRAMES:usize=9;
#[cfg(not(feature="qemu-virtio-gpu-attach-backing-smoke"))]
const FRAMES:usize=5;
#[repr(C)]
#[derive(Clone,Copy)]
struct Desc{addr:u64,len:u32,flags:u16,next:u16}
struct TableAllocator;
unsafe impl FrameAllocator<Size4KiB> for TableAllocator{
    fn allocate_frame(&mut self)->Option<PhysFrame>{
        Some(PhysFrame::containing_address(PhysAddr::new(pmm::allocate_frame()?)))
    }
}
fn outside_ram(base:u64,entries:&[&Entry])->bool{
    let Some(end)=base.checked_add(mmio::PAGE_BYTES)else{return false;};
    for e in entries.iter().copied(){
        if !matches!(e.type_,
            MEMMAP_USABLE|MEMMAP_BOOTLOADER_RECLAIMABLE|
            MEMMAP_EXECUTABLE_AND_MODULES|MEMMAP_ACPI_RECLAIMABLE|
            MEMMAP_ACPI_NVS|MEMMAP_FRAMEBUFFER
        ){continue;}
        let Some(stop)=e.base.checked_add(e.length)else{return false;};
        if base<stop&&e.base<end{return false;}
    }
    true
}
fn owned_frames_valid(l:queue::Layout,f:&[u64;FRAMES])->bool{
    if queue::validate_future_regions(l,f[0],f[1],f[2]).is_err(){
        return false;
    }
    for i in 0..FRAMES{
        if f[i]==0||f[i]%queue::PAGE_BYTES!=0||
            f[i].checked_add(queue::PAGE_BYTES).is_none(){
            return false;
        }
        for j in 0..i{
            if f[i]==f[j]{return false;}
        }
    }
    l.selected>=2&&l.selected.is_power_of_two()&&l.desc_pages==1&&
    l.avail_pages==1&&l.used_pages==1
}
pub fn verify(hhdm:u64,entries:&[&Entry],
    common:pci::QemuBarWindow,
    cap:pci::QemuNotifyWindow, layout:queue::Layout)->bool{
    let mut witness=[0u64;FRAMES];
    for (i,f) in witness.iter_mut().enumerate(){*f=(i as u64+1)*4096;}
    if x86_64::instructions::interrupts::are_enabled()||
       !owned_frames_valid(layout,&witness) {
        serial::write_line("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL layout_or_irq");
        return false;
    }
    let span=match mmio::check(mmio::Window{
        bar_base:common.physical_base,bar_bytes:common.aperture_bytes,
        offset:common.common_offset,length:common.common_length,
        is_memory:common.is_memory,
    }){
        Ok(s)=>s,Err(e)=>{
            serial::write_fmt(format_args!("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL common={e:?}\n"));
            return false;
        }
    };
    if !outside_ram(span.physical_page,entries)||
       cap.physical_base!=common.physical_base||
       cap.aperture_bytes!=common.aperture_bytes{
        serial::write_line("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL mmio_aperture");
        return false;
    }
    let (cr3_frame,_)=Cr3::read();
    let Some(pml4_va)=hhdm.checked_add(cr3_frame.start_address().as_u64())
        .and_then(|a|VirtAddr::try_new(a).ok())else{
        serial::write_line("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL cr3");
        return false;
    };
    let Some(hhdm_va)=VirtAddr::try_new(hhdm).ok()else{
        serial::write_line("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL hhdm");
        return false;
    };
    // SAFETY: only BSP, no AP and interrupts disabled; PML4 in RAM HHDM.
    let pml4=unsafe{&mut *pml4_va.as_mut_ptr::<PageTable>()};
    let mut mapper=unsafe{OffsetPageTable::new(pml4,hhdm_va)};
    let target=VirtAddr::new(SLOT);
    if mapper.translate_addr(target).is_some(){
        serial::write_line("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL slot_occupied");
        return false;
    }
    let page=Page::<Size4KiB>::containing_address(target);
    let frame=PhysFrame::<Size4KiB>::containing_address(
        PhysAddr::new(span.physical_page));
    let flags=PageTableFlags::PRESENT|PageTableFlags::WRITABLE|
        PageTableFlags::NO_CACHE|PageTableFlags::WRITE_THROUGH;
    let Ok(flush)=(unsafe{mapper.map_to(page,frame,flags,&mut TableAllocator)})else{
        serial::write_line("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL map");
        return false;
    };
    flush.flush();
    let mapped=mapper.translate_addr(target).map(|p|p.as_u64())==
        Some(span.physical_page);
    let start=SLOT+span.page_offset;
    let rd16=|a:u64|->u16{
        u16::from_le(unsafe{((start+a)as *const u16).read_volatile()})
    };
    let rd32=|a:u64|->u32{
        u32::from_le(unsafe{((start+a)as *const u32).read_volatile()})
    };
    let rd64=|a:u64|->u64{
        u64::from(rd32(a))|(u64::from(rd32(a+4))<<32)
    };
    let wr16=|a:u64,v:u16|{
        unsafe{((start+a)as *mut u16).write_volatile(v.to_le());}
    };
    let wr32=|a:u64,v:u32|{
        unsafe{((start+a)as *mut u32).write_volatile(v.to_le());}
    };
    let wr64=|a:u64,v:u64|{
        wr32(a,v as u32);wr32(a+4,(v>>32)as u32);
    };
    let st=(start+off::DEVICE_STATUS_OFFSET)as *mut u8;
    // Common and notify capabilities may reside on distinct pages of
    // the same measured BAR (QEMU: 0x1000 and 0x3000). Own both PTEs.
    let mut notify_register:Option<u64>=None;
    let mut notify_mapping:Option<(Page<Size4KiB>,u64)>=None;
    let preflight=if mapped{
        let selected=rd16(off::QUEUE_SELECTOR_OFFSET);
        let enable=rd16(off::QUEUE_ENABLE_OFFSET);
        let size=rd16(off::QUEUE_SIZE_OFFSET);
        let queue_off=rd16(queue::QUEUE_NOTIFY_OFF);
        let valid=unsafe{st.read_volatile()}==0&&selected==0&&enable==0&&
            rd32(off::FEATURE_SELECTOR_OFFSET)==0&&rd32(8)==0&&
            size>=layout.selected&&rd16(queue::NUM_QUEUES)>=2&&
            rd64(queue::QUEUE_DESC)==0&&rd64(queue::QUEUE_DRIVER)==0&&
            rd64(queue::QUEUE_DEVICE)==0;
        if valid{
            let c=notify::Capability{
                bar_base:cap.physical_base,bar_bytes:cap.aperture_bytes,
                cap_offset:cap.notify_offset,cap_length:cap.notify_length,
                multiplier:cap.notify_multiplier,
                same_measured_bar:cap.same_measured_bar,
            };
            if let Ok(reg)=notify::resolve(c,queue_off){
                if outside_ram(reg.physical_page,entries){
                    if reg.physical_page==span.physical_page{
                        notify_register=Some(SLOT+reg.page_offset);
                    }else{
                        // Independently map exactly one further validated
                        // MMIO page; never alias common_cfg's virtual slot.
                        let notify_va=VirtAddr::new(SLOT+mmio::PAGE_BYTES);
                        if mapper.translate_addr(notify_va).is_none(){
                            let notify_page=Page::<Size4KiB>::containing_address(notify_va);
                            let notify_frame=PhysFrame::<Size4KiB>::containing_address(
                                PhysAddr::new(reg.physical_page));
                            if let Ok(flush)=unsafe{
                                mapper.map_to(notify_page,notify_frame,flags,&mut TableAllocator)
                            }{
                                flush.flush();
                                // Keep the mapping for unconditional cleanup
                                // even if the translation verification fails.
                                notify_mapping=Some((notify_page,reg.physical_page));
                                if mapper.translate_addr(notify_va).map(|p|p.as_u64())==
                                    Some(reg.physical_page){
                                    notify_register=Some(
                                        SLOT+mmio::PAGE_BYTES+reg.page_offset);
                                }
                            }
                        }
                    }
                }
            }
        }
        valid&&notify_register.is_some()
    }else{false};

    // Baseline after persistent paging table allocations.
    let baseline=pmm::statistics().allocated_frames;
    let mut frames=[0u64;FRAMES];
    let mut acquired=0usize;
    if preflight{
        for f in &mut frames{
            match pmm::allocate_frame(){
                Some(a)=>{*f=a;acquired+=1;}
                None=>break,
            }
        }
    }
    let addresses_ok=acquired==FRAMES&&owned_frames_valid(layout,&frames);
    let mut zeroed=addresses_ok;
    let mut vas=[0u64;FRAMES];
    if addresses_ok{
        for (i,p)in frames.iter().copied().enumerate(){
            let Some(va)=hhdm.checked_add(p).and_then(|a|VirtAddr::try_new(a).ok())else{
                zeroed=false;break;
            };
            vas[i]=va.as_u64();
            // SAFETY: these are FRAMES exclusively PMM-owned, 4KiB
            // HHDM-mapped usable-RAM frames in a single-vCPU QEMU guest.
            let ptr=va.as_mut_ptr::<u8>();
            unsafe{core::ptr::write_bytes(ptr,0,queue::PAGE_BYTES as usize);}
            for n in 0..queue::PAGE_BYTES as usize{
                if unsafe{ptr.add(n).read_volatile()}!=0{
                    zeroed=false;break;
                }
            }
            if !zeroed{break;}
        }
    }
    let mut exposed=false;
    let mut reset_confirmed=false;
    let mut completed=false;
    let mut did_notify=false;
    let mut display_info:Option<display::DisplayOne>=None;
    #[cfg(feature="qemu-virtio-gpu-edid-live-smoke")]
    let mut edid_info:Option<EdidProof>=None;
    #[cfg(feature="qemu-virtio-gpu-resource2d-smoke")]
    let mut resource_done=false;
    if zeroed{
        // Wire layout is 16-byte LE descriptors and a bare 24-byte GPU
        // header; available ring flags=0, head[0]=0, then idx=1.
        // Device may write ONLY into the separate 408-byte response page.
        let descriptors=vas[0] as *mut Desc;
        let first=Desc{
            addr:frames[3].to_le(),len:(display::REQUEST_BYTES as u32).to_le(),
            flags:1u16.to_le(),next:1u16.to_le(),
        };
        let second=Desc{
            addr:frames[4].to_le(),len:(display::RESPONSE_BYTES as u32).to_le(),
            flags:2u16.to_le(),next:0,
        };
        unsafe{
            descriptors.write_volatile(first);
            descriptors.add(1).write_volatile(second);
            (vas[3] as *mut u32).write_volatile(display::CMD_GET_DISPLAY_INFO.to_le());
        }
        fence(Ordering::SeqCst);
        // Modern VirtIO VERSION_1 handshake, ACK→DRIVER→FEATURES_OK.
        unsafe{st.write_volatile(0);}
        let initial_reset=unsafe{st.read_volatile()};
        unsafe{st.write_volatile(1);}
        let ack=unsafe{st.read_volatile()};
        unsafe{st.write_volatile(3);}
        let driver=unsafe{st.read_volatile()};
        #[cfg(feature="qemu-virtio-gpu-edid-live-smoke")]
        let edid_advertised=rd32(off::DEVICE_FEATURE_OFFSET)&off::GPU_FEATURE_EDID!=0;
        #[cfg(feature="qemu-virtio-gpu-edid-live-smoke")]
        {
            wr32(8,0);
            wr32(12,off::GPU_FEATURE_EDID);
        }
        wr32(8,1);let selector_one=rd32(8);
        wr32(12,1);let negotiated=rd32(12);
        wr32(8,0);let selector_zero=rd32(8);
        #[cfg(feature="qemu-virtio-gpu-edid-live-smoke")]
        let edid_accepted=rd32(12)==off::GPU_FEATURE_EDID;
        unsafe{st.write_volatile(11);}
        let features=unsafe{st.read_volatile()};
        let handshake=initial_reset==0&&ack==1&&driver==3&&
            selector_one==1&&negotiated==1&&selector_zero==0&&
            features==11;
        #[cfg(feature="qemu-virtio-gpu-edid-live-smoke")]
        let handshake=handshake&&edid_advertised&&edid_accepted;
        if handshake{
            wr16(off::QUEUE_SELECTOR_OFFSET,0);
            wr16(off::QUEUE_SIZE_OFFSET,layout.selected);
            exposed=true;
            wr64(queue::QUEUE_DESC,frames[0]);
            wr64(queue::QUEUE_DRIVER,frames[1]);
            wr64(queue::QUEUE_DEVICE,frames[2]);
            wr16(off::QUEUE_ENABLE_OFFSET,1);
            let ring_ok=rd16(off::QUEUE_SIZE_OFFSET)==layout.selected&&
                rd64(queue::QUEUE_DESC)==frames[0]&&
                rd64(queue::QUEUE_DRIVER)==frames[1]&&
                rd64(queue::QUEUE_DEVICE)==frames[2]&&
                rd16(off::QUEUE_ENABLE_OFFSET)==1;
            if ring_ok{
                unsafe{st.write_volatile(15);}
                if unsafe{st.read_volatile()}==15{
                    // With driver ready, publish exactly one available head.
                    unsafe{
                        ((vas[1]+4)as *mut u16).write_volatile(0u16.to_le());
                    }
                    fence(Ordering::SeqCst);
                    unsafe{
                        ((vas[1]+2)as *mut u16).write_volatile(1u16.to_le());
                    }
                    fence(Ordering::SeqCst);
                    // VIRTIO_F_NOTIFICATION_DATA was NOT negotiated. The
                    // write-only PCI notify value is queue index 0 (u16).
                    if let Some(port)=notify_register{
                        unsafe{(port as *mut u16).write_volatile(0u16.to_le());}
                        did_notify=true;
                    }
                    // Bounded synchronous QEMU-only wait for exactly one used
                    // completion. No interrupt installation, no unbounded wait.
                    for _ in 0..2_000_000u32{
                        if u16::from_le(unsafe{
                            ((vas[2]+2)as *const u16).read_volatile()
                        })!=0{break;}
                        core::hint::spin_loop();
                    }
                    fence(Ordering::SeqCst);
                    let used_idx=u16::from_le(unsafe{
                        ((vas[2]+2)as *const u16).read_volatile()
                    });
                    let used_head=u32::from_le(unsafe{
                        ((vas[2]+4)as *const u32).read_volatile()
                    });
                    let used_len=u32::from_le(unsafe{
                        ((vas[2]+8)as *const u32).read_volatile()
                    });
                    // Copy untrusted response under DMA-safe lifetime;
                    // device-writable response page remains exclusively
                    // allocated until full device reset confirmation.
                    let mut resp=[0u8;display::RESPONSE_BYTES];
                    if used_idx==1{
                        for (n,b)in resp.iter_mut().enumerate(){
                            *b=unsafe{
                                ((vas[4]+n as u64)as *const u8).read_volatile()
                            };
                        }
                        if let Ok(mode)=display::validate(
                            layout.selected,used_idx,used_head,used_len,&resp
                        ){
                            completed=true;
                            display_info=Some(mode);
                        }
                    }
                    #[cfg(feature="qemu-virtio-gpu-edid-live-smoke")]
                    if completed{
                        if let Some(port)=notify_register{
                            match query_edid(&vas,&frames,port){
                                Ok(info)=>edid_info=Some(info),
                                Err(e)=>serial::write_fmt(format_args!(
                                    "WOLFOS_VIRTIO_GPU_EDID_LIVE_FAIL stage={e}\n"
                                )),
                            }
                        }
                    }
                    #[cfg(feature="qemu-virtio-gpu-resource2d-smoke")]
                    if edid_info.is_some() {
                        if let Some(port)=notify_register {
                            #[cfg(feature="qemu-virtio-gpu-scanout-live-smoke")]
                            let scanout_ok=display_info.as_ref().is_some_and(|m|m.enabled==1);
                            #[cfg(not(feature="qemu-virtio-gpu-scanout-live-smoke"))]
                            let scanout_ok=true;
                            if !scanout_ok {
                                serial::write_line(
                                    "WOLFOS_VIRTIO_GPU_SCANOUT_FAIL stage=disabled_scanout"
                                );
                            } else {
                            match query_resource2d(&vas,&frames,port,layout.selected) {
                                Ok(())=>resource_done=true,
                                Err(e)=>serial::write_fmt(format_args!(
                                    "WOLFOS_VIRTIO_GPU_RESOURCE2D_FAIL stage={e}\n"
                                )),
                            }
                            }
                        }
                    }
                }
            }
        }
        // Even if the GPU rejects or never completes the command, ALWAYS
        // reset after handshake started. No early return after exposure.
        unsafe{st.write_volatile(0);}
        fence(Ordering::SeqCst);
        let mut status=unsafe{st.read_volatile()};
        let mut qenabled=rd16(off::QUEUE_ENABLE_OFFSET);
        for _ in 0..4096{
            if status==0&&qenabled==0{break;}
            core::hint::spin_loop();
            status=unsafe{st.read_volatile()};
            qenabled=rd16(off::QUEUE_ENABLE_OFFSET);
        }
        reset_confirmed=status==0&&qenabled==0;
    }

    // Unmap every PCI MMIO page, including a distinct notify-cap page.
    let mut notify_unmapped_ok=true;
    if let Some((notify_page,physical))=notify_mapping{
        match mapper.unmap(notify_page){
            Ok((frame,flush))=>{
                flush.flush();
                notify_unmapped_ok=frame.start_address().as_u64()==physical&&
                    mapper.translate_addr(notify_page.start_address()).is_none();
            }
            Err(_)=>{notify_unmapped_ok=false;}
        }
    }
    let Ok((unmapped,flush))=mapper.unmap(page)else{
        serial::write_line("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL unmap");
        return false;
    };
    flush.flush();
    let unmapped_ok=mapped&&notify_unmapped_ok&&
        unmapped.start_address().as_u64()==span.physical_page&&
        mapper.translate_addr(target).is_none();

    // If queue addresses were exposed and reset is unproven, quarantine all
    // FRAMES PMM frames until QEMU teardown; never risk reuse while DMA live.
    let may_free=!exposed||reset_confirmed;
    let mut released=0usize;
    let mut errors=0usize;
    if may_free{
        for f in frames[..acquired].iter().rev().copied(){
            if pmm::free_frame(f).is_ok(){released+=1;}else{errors+=1;}
        }
    }
    let after=pmm::statistics().allocated_frames;
    let balanced=acquired==FRAMES&&released==FRAMES&&errors==0&&after==baseline;
    #[cfg(feature="qemu-virtio-gpu-edid-live-smoke")]
    let edid_ok=edid_info.is_some();
    #[cfg(not(feature="qemu-virtio-gpu-edid-live-smoke"))]
    let edid_ok=true;
    #[cfg(feature="qemu-virtio-gpu-resource2d-smoke")]
    let resource_ok=resource_done;
    #[cfg(not(feature="qemu-virtio-gpu-resource2d-smoke"))]
    let resource_ok=true;
    if !preflight||!addresses_ok||!zeroed||!exposed||!did_notify||
        !completed||!edid_ok||!resource_ok||!reset_confirmed||!balanced||!unmapped_ok{
        serial::write_fmt(format_args!(
            "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL preflight={} alloc={} released={} quarantined={} exposed={} notified={} completed={} reset={} map={} balanced={}\n",
            preflight,acquired,released,acquired-released,exposed,
            did_notify,completed,reset_confirmed,unmapped_ok,balanced
        ));
        return false;
    }
    let Some(mode)=display_info else{
        serial::write_line("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL response_missing");
        return false;
    };
    serial::write_fmt(format_args!(
        "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK req=256 resp=4353 used_idx=1 used_head=0 used_len=408 scanout0_enabled={} width={} height={} notify_writes=1 driver_ok=15 reset=0 queue_disabled=1 frames_allocated={} frames_released={} response_dma_verified=1 pmm_leak=0 qemu_only=1\n",
        mode.enabled,mode.width,mode.height,FRAMES,FRAMES
    ));
    #[cfg(feature="qemu-virtio-gpu-edid-live-smoke")]
    if let Some(edid)=edid_info{
        serial::write_fmt(format_args!(
            "WOLFOS_VIRTIO_GPU_EDID_LIVE_OK scanout=0 edid_size={} modes={} preferred_width={} preferred_height={} refresh_millihz={} gpu_timing_proof_required=1 mode_writes=0 used_idx=2 used_head=0 used_len=1056 fence_verified=1 negotiated_edid=1 notify_writes=2 driver_ok=15 reset=0 queue_disabled=1 frames_allocated={} frames_released={} pmm_leak=0 qemu_only=1\n",
            edid.size,edid.modes,edid.width,edid.height,edid.refresh_millihz,FRAMES,FRAMES
        ));
    }
    #[cfg(all(feature="qemu-virtio-gpu-resource2d-smoke",
              not(feature="qemu-virtio-gpu-attach-backing-smoke")))]
    if resource_done {
        serial::write_line(
            "WOLFOS_VIRTIO_GPU_RESOURCE2D_OK resource_id=1 format=2 width=64 height=64 create_type=257 unref_type=258 response_type=4352 used_idx=4 used_head=0 used_len=24 fences_verified=2 notify_writes=4 scanout_writes=0 attach_backing=0 reset=0 queue_disabled=1 frames_allocated=5 frames_released=5 pmm_leak=0 qemu_only=1"
        );
    }
    #[cfg(all(feature="qemu-virtio-gpu-attach-backing-smoke",
              not(feature="qemu-virtio-gpu-transfer2d-smoke")))]
    if resource_done {
        serial::write_line(
            "WOLFOS_VIRTIO_GPU_ATTACH_BACKING_OK resource_id=1 format=2 width=64 height=64 create_type=257 attach_type=262 detach_type=263 unref_type=258 response_type=4352 used_idx=6 used_head=0 used_len=24 fences_verified=4 notify_writes=6 backing_entries=4 backing_bytes=16384 pages_zeroed=4 attach_ack=1 detach_ack=1 unref_ack=1 transfer_writes=0 scanout_writes=0 reset=0 queue_disabled=1 frames_allocated=9 frames_released=9 pmm_leak=0 qemu_only=1"
        );
    }
    #[cfg(all(feature="qemu-virtio-gpu-transfer2d-smoke",
              not(feature="qemu-virtio-gpu-scanout-live-smoke")))]
    if resource_done {
        serial::write_line(
            "WOLFOS_VIRTIO_GPU_TRANSFER2D_OK resource_id=1 format=2 width=64 height=64 create_type=257 attach_type=262 transfer_type=261 detach_type=263 unref_type=258 response_type=4352 used_idx=7 used_head=0 used_len=24 fences_verified=5 notify_writes=7 backing_entries=4 backing_bytes=16384 pattern_nonzero_bytes=16384 guest_pattern_verified=2 transfer_ack=1 detach_ack=1 unref_ack=1 host_readback=0 scanout_writes=0 reset=0 queue_disabled=1 frames_allocated=9 frames_released=9 pmm_leak=0 qemu_only=1"
        );
    }
    #[cfg(feature="qemu-virtio-gpu-scanout-live-smoke")]
    if resource_done {
        serial::write_line(
            "WOLFOS_VIRTIO_GPU_SCANOUT_OK resource_id=1 format=2 width=64 height=64 create_type=257 attach_type=262 transfer_type=261 set_type=259 flush_type=260 clear_type=259 detach_type=263 unref_type=258 response_type=4352 used_idx=10 used_head=0 used_len=24 fences_verified=8 notify_writes=10 backing_entries=4 backing_bytes=16384 guest_pattern_verified=2 set_ack=1 flush_ack=1 clear_ack=1 detach_ack=1 unref_ack=1 capture_acks=3 host_pixels_verified_by_kernel=0 reset=0 queue_disabled=1 frames_allocated=9 frames_released=9 pmm_leak=0 qemu_only=1"
        );
    }
    true
}
