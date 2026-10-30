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
struct EdidProof{
    size:u32,modes:usize,width:u32,height:u32,refresh_millihz:u32,
    // Every advertised connector geometry, retained only so the display mode
    // catalog can prove each one is refused without host-verified GPU proof.
    geometries:[(u32,u32);crate::display_mode_catalog::MAX_CATALOG_ENTRIES],
    geometry_len:usize,
}
/// Real driver observations handed to the display mode catalog stage. None of
/// these fields is GPU timing evidence by itself; the catalog grades each one.
#[derive(Clone,Copy)]
#[allow(dead_code)]
struct CatalogFacts{
    device_width:u32, device_height:u32,
    edid_mode_count:usize, edid_refresh_millihz:u32,
    edid_geometries:[(u32,u32);crate::display_mode_catalog::MAX_CATALOG_ENTRIES],
    edid_geometry_len:usize,
}
impl CatalogFacts{
    const EMPTY:Self=Self{
        device_width:0,device_height:0,edid_mode_count:0,edid_refresh_millihz:0,
        edid_geometries:[(0,0);crate::display_mode_catalog::MAX_CATALOG_ENTRIES],
        edid_geometry_len:0,
    };
}
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
    let mut geometries=[(0u32,0u32);crate::display_mode_catalog::MAX_CATALOG_ENTRIES];
    let mut geometry_len=0usize;
    for m in verified.modes().iter().copied(){
        if geometry_len==geometries.len(){return Err("edid_geometry_overflow");}
        geometries[geometry_len]=(m.width,m.height);
        geometry_len+=1;
    }
    let size=u32::from_le_bytes([data[24],data[25],data[26],data[27]]);
    Ok(EdidProof{
        size,modes:verified.modes().len(),width:preferred.width,
        height:preferred.height,refresh_millihz:preferred.refresh_millihz,
        geometries,geometry_len,
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
    // The upper bound is a flavor constant, so an unexpected completion
    // index is still refused instead of being accepted as this request.
    #[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
    let max_index=resource::DESKTOP_MAX_INDEX;
    #[cfg(not(feature="qemu-virtio-gpu-desktop-scanout-smoke"))]
    let max_index=resource::PROBE_MAX_INDEX;
    if let Err(e)=resource::validate_completion_upto(
        next_idx,max_index,idx,head,len,&response,request_fence
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

#[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
const ACTIVE_NONCE:u64=0x574f_4154_0001;
#[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
const REDUCED_NONCE:u64=0x574f_4152_0002;
#[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
const REEXPANDED_NONCE:u64=0x574f_4158_0003;

/// The driver's own digest of the exact pixels it placed in the resource.
/// Both sides compute the same FNV-1a over canonical RGB, so a corrupted
/// transfer, wrong stride or swapped channel order cannot match.
#[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
fn source_digest(width:u32,height:u32)->Result<u32,&'static str>{
    use crate::display_mode_catalog::rgb_digest;
    let byte=|index:usize|->Result<u8,&'static str>{
        let page=index/transfer::PAGE_BYTES;
        if page>=transfer::BACKING_PAGES{return Err("source_index");}
        transfer::pattern_byte(page,index%transfer::PAGE_BYTES)
            .map_err(|_|"pattern_contract")
    };
    // Validate every index up front: the digest must never be computed over a
    // substituted value, so the host comparison stays meaningful.
    for y in 0..height{
        for x in 0..width{
            let base=(y as usize*64+x as usize)*4;
            for channel in 0..3{byte(base+channel)?;}
        }
    }
    Ok(rgb_digest(width,height,&|x,y|{
        let base=(y as usize*64+x as usize)*4;
        [byte(base+2).unwrap_or(0),byte(base+1).unwrap_or(0),byte(base).unwrap_or(0)]
    }))
}

/// Challenge the QEMU host to prove what it actually displayed. Prints the
/// nonce and source digest, then accepts exactly one reply line bound to this
/// stage. No reply, a replayed nonce, a resized scanout or a differing digest
/// all fail closed and leave the catalog without host-verified evidence.
#[cfg(any(feature="qemu-virtio-gpu-native-rollback-smoke",
          feature="qemu-virtio-gpu-desktop-scanout-smoke"))]
fn await_host_attestation(
    token:u8,nonce:u64,width:u32,height:u32,digest:u32,
)->Result<crate::display_mode_catalog::Attestation,&'static str>{
    use crate::display_mode_catalog::{
        StageChallenge,MAX_REPLY_BYTES,decode_attestation_reply,
    };
    let challenge=StageChallenge::new(token,nonce,width,height,digest)
        .map_err(|_|"attest_challenge")?;
    serial::write_fmt(format_args!(
        "WOLFOS_GPU_STAGE_ATTEST stage={} geometry={}x{} nonce={:016x} source_digest={:08x}\n",
        challenge.stage_label(),width,height,nonce,digest
    ));
    let mut line=[0u8;MAX_REPLY_BYTES+1];
    let mut len=0usize;
    for _ in 0..600_000_000u32{
        if let Some(byte)=serial::read_byte_nonblocking(){
            if len==line.len(){return Err("attest_reply_too_long");}
            line[len]=byte;
            len+=1;
            if byte==b'\n'{break;}
            continue;
        }
        core::hint::spin_loop();
    }
    match decode_attestation_reply(&line[..len],challenge){
        Ok(attestation)=>Ok(attestation),
        Err(e)=>{
            serial::write_fmt(format_args!(
                "WOLFOS_GPU_ATTEST_FAIL stage={} reason={} bytes={} source_digest={:08x}\n",
                challenge.stage_label(),e.label(),len,digest
            ));
            Err("attest_reply")
        }
    }
}

#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
const DESKTOP_NONCE:u64=0x574f_4445_534b_0004;
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
const REDUCED_STAGE_NONCE:u64=0x574f_4445_534b_0005;
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
const APPLIED_STAGE_NONCE:u64=0x574f_4445_534b_0006;
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
const ROLLBACK_STAGE_NONCE:u64=0x574f_4445_534b_0007;
/// Connector generation for the desktop catalog proof. One synthetic
/// generation: this driver performs no hotplug re-read yet, so a stale
/// generation must never be treated as current.
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
const DESKTOP_GENERATION:u64=1;
/// Transaction token for the one real mode change of this scenario.
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
const TX_TOKEN:u64=0x574f_4c46_5458_0001;
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
const TX_FENCE_BASE:u64=0x574f_4c46_5458_0100;
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
const TX_SET_FENCE:u64=0x574f_4c46_5458_0200;
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
const TX_FLUSH_FENCE:u64=0x574f_4c46_5458_0201;
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
const TX_READBACK_FENCE:u64=0x574f_4c46_5458_0202;

/// The two real frames this driver can present from the same resource.
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
#[derive(Clone,Copy,PartialEq,Eq)]
enum Image{Desktop,Reduced}

#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
impl Image{
    const fn height(self)->u32{
        match self{Self::Desktop=>crate::virtio_gpu_desktop_wire::HEIGHT,
                   Self::Reduced=>crate::virtio_gpu_desktop_wire::ALT_HEIGHT}
    }
    const fn bands(self)->usize{
        match self{Self::Desktop=>crate::virtio_gpu_desktop_wire::BANDS,
                   Self::Reduced=>crate::virtio_gpu_desktop_wire::ALT_BANDS}
    }
    fn rgb(self,x:u32,y:u32)->[u8;3]{
        use crate::virtio_gpu_desktop_wire as desk;
        match self{Self::Desktop=>desk::pixel_rgb(x,y),
                   Self::Reduced=>desk::alt_pixel_rgb(x,y)}
    }
    fn word(self,x:u32,y:u32)->u32{
        use crate::virtio_gpu_desktop_wire as desk;
        match self{Self::Desktop=>desk::pixel_word(x,y),
                   Self::Reduced=>desk::alt_pixel_word(x,y)}
    }
}

/// Paint `image` into the real Limine framebuffer, copy exactly the scanlines
/// it owns into the exclusively owned backing pages, and return the digest of
/// the bytes the device will really read. The digest is also compared with the
/// intended image, so a copy bug cannot become a self-consistent wrong frame.
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
fn stage_image(
    fb:&crate::virtio_gpu_desktop_wire::Framebuffer,vas:&[u64;FRAMES],image:Image,
)->Result<u32,&'static str>{
    use crate::virtio_gpu_desktop_wire as desk;
    let height=image.height();
    let base=fb.address as *mut u8;
    for y in 0..height{
        let row=fb.pitch as usize*(y as usize);
        for x in 0..desk::WIDTH{
            // SAFETY: supported() proved a 4-aligned 32-bpp 1024x768
            // framebuffer whose pitch covers every written row inside the
            // validated mapped extent.
            unsafe{base.add(row+x as usize*4).cast::<u32>().write_volatile(image.word(x,y));}
        }
    }
    fence(Ordering::SeqCst);
    for y in 0..height as usize{
        let src=unsafe{base.add(fb.pitch as usize*y)};
        let dst=vas[5+y] as *mut u8;
        for at in 0..desk::ROW_BYTES{
            let byte=unsafe{src.add(at).read_volatile()};
            unsafe{dst.add(at).write_volatile(byte);}
        }
    }
    fence(Ordering::SeqCst);
    let digest=page_digest(vas,height);
    if digest!=crate::display_mode_catalog::rgb_digest(
        desk::WIDTH,height,&|x,y| image.rgb(x,y)
    ){
        return Err("framebuffer_copy_mismatch");
    }
    Ok(digest)
}

/// Digest of the first `height` backing rows, read back from the pages the
/// device will read. Row stride is one page, so row y lives in page y.
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
fn page_digest(vas:&[u64;FRAMES],height:u32)->u32{
    use crate::virtio_gpu_desktop_wire as desk;
    crate::display_mode_catalog::rgb_digest(
        desk::WIDTH,height,
        &|x,y|{
            let page=vas[5+y as usize] as *const u8;
            let at=x as usize*4;
            // SAFETY: page y is one exclusively owned 4 KiB backing frame and
            // x*4+2 stays inside its 4096-byte row.
            unsafe{
                [page.add(at+2).read_volatile(),page.add(at+1).read_volatile(),
                 page.add(at).read_volatile()]
            }
        },
    )
}

/// Upload the leading `bands` bands of `image`, each in its own fenced
/// transfer. Returns the next free control-queue index.
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
fn upload_bands(
    vas:&[u64;FRAMES],frames:&[u64;FRAMES],notify_port:u64,selected:u16,
    first:u16,bands:usize,image:Image,fence_base:u64,
)->Result<u16,&'static str>{
    use crate::virtio_gpu_desktop_wire as desk;
    let mut next=first;
    for band in 0..bands{
        let request_fence=fence_base+band as u64;
        let command=match image{
            Image::Desktop=>desk::transfer(band,request_fence),
            Image::Reduced=>desk::alt_transfer(band,request_fence),
        }.map_err(|_|"transfer_wire")?;
        send_resource_command(vas,frames,notify_port,selected,next,&command,request_fence)?;
        next+=1;
    }
    Ok(next)
}

/// A fresh GET_DISPLAY_INFO after a switch: the device's own statement about
/// the scanout rectangle it now has configured. Fence-bound to this exact
/// request, so an older completion cannot be mistaken for the readback.
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
fn query_display_now(
    vas:&[u64;FRAMES],frames:&[u64;FRAMES],notify_port:u64,selected:u16,index:u16,
)->Result<display::DisplayOne,&'static str>{
    let request_ptr=vas[3] as *mut u8;
    let response_ptr=vas[4] as *mut u8;
    // SAFETY: both pages are exclusively owned and the previous DMA completed
    // before these writes (each send polled its own used index).
    unsafe{
        core::ptr::write_bytes(response_ptr,0,edid::RESPONSE_LEN);
        core::ptr::write_bytes(request_ptr,0,queue::PAGE_BYTES as usize);
        (request_ptr as *mut u32).write_volatile(
            display::CMD_GET_DISPLAY_INFO.to_le()
        );
        (request_ptr.add(4) as *mut u32).write_volatile(
            crate::virtio_gpu_desktop_wire::FLAG_FENCE.to_le());
        (request_ptr.add(8) as *mut u64).write_volatile(TX_READBACK_FENCE.to_le());
        let desc=vas[0] as *mut Desc;
        desc.write_volatile(Desc{
            addr:frames[3].to_le(),len:(display::REQUEST_BYTES as u32).to_le(),
            flags:1u16.to_le(),next:1u16.to_le(),
        });
        desc.add(1).write_volatile(Desc{
            addr:frames[4].to_le(),len:(display::RESPONSE_BYTES as u32).to_le(),
            flags:2u16.to_le(),next:0,
        });
        let slot=resource::ring_slot(index,selected).map_err(|_|"queue_slot")?;
        ((vas[1]+4+u64::from(slot)*2)as *mut u16).write_volatile(0u16.to_le());
    }
    fence(Ordering::SeqCst);
    unsafe{((vas[1]+2)as *mut u16).write_volatile(index.to_le());}
    fence(Ordering::SeqCst);
    unsafe{(notify_port as *mut u16).write_volatile(0u16.to_le());}
    for _ in 0..2_000_000u32{
        if u16::from_le(unsafe{
            ((vas[2]+2)as *const u16).read_volatile()
        })>=index{break;}
        core::hint::spin_loop();
    }
    fence(Ordering::SeqCst);
    let used_index=u16::from_le(unsafe{((vas[2]+2)as *const u16).read_volatile()});
    let slot=resource::ring_slot(index,selected).map_err(|_|"queue_slot")?;
    let used=vas[2]+4+u64::from(slot)*8;
    let head=u32::from_le(unsafe{(used as *const u32).read_volatile()});
    let len=u32::from_le(unsafe{((used+4)as *const u32).read_volatile()});
    let mut response=[0u8;display::RESPONSE_BYTES];
    if used_index==index{
        for (i,b)in response.iter_mut().enumerate(){
            *b=unsafe{response_ptr.add(i).read_volatile()};
        }
    }
    display::validate_index_fenced(
        index,selected,used_index,head,len,&response,TX_READBACK_FENCE
    ).map_err(|_|"display_readback")
}

/// The host's answer for the applied-mode stage: the elapsed time the window is
/// graded against, plus -- only inside the window -- the attestation itself.
/// The guest never invents the elapsed number.
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
use crate::display_mode_catalog::Attestation;

#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
enum StageVerdict{
    InsideWindow(Attestation),
    Expired{elapsed_ms:u64},
}

#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
fn read_reply(capture:&mut [u8])->Result<usize,&'static str>{
    let mut len=0usize;
    for _ in 0..600_000_000u32{
        if let Some(byte)=serial::read_byte_nonblocking(){
            if len==capture.len(){return Err("attest_reply_too_long");}
            capture[len]=byte;
            len+=1;
            if byte==b'\n'{return Ok(len);}
            continue;
        }
        core::hint::spin_loop();
    }
    Err("attest_timeout")
}

/// Prints the applied-mode challenge and accepts the host's verdict:
/// `"X <elapsed_ms>"` means the user confirmed at that real elapsed time and
/// the ordinary nonce-bound attestation follows; `"E <elapsed_ms>"` means the
/// user did not confirm, and the state machine still grades the elapsed time,
/// so an early expiry claim is refused rather than obeyed.
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
fn await_stage_verdict(
    token:u8,nonce:u64,width:u32,height:u32,digest:u32,
)->Result<StageVerdict,&'static str>{
    use crate::display_mode_catalog::{
        StageChallenge,MAX_REPLY_BYTES,decode_attestation_reply,CONFIRM_WINDOW_MS,
    };
    let challenge=StageChallenge::new(token,nonce,width,height,digest)
        .map_err(|_|"attest_challenge")?;
    serial::write_fmt(format_args!(
        "WOLFOS_GPU_STAGE_ATTEST stage={} geometry={}x{} nonce={:016x} source_digest={:08x}\n",
        challenge.stage_label(),width,height,nonce,digest
    ));
    let mut line=[0u8;MAX_REPLY_BYTES+1];
    let len=read_reply(&mut line)?;
    let verdict=line[..len].split(|b|*b==b'\n').next().unwrap_or(&[]);
    let verdict=verdict.strip_suffix(b"\r").unwrap_or(verdict);
    let mut fields=verdict.split(|b|*b==b' ');
    let kind=fields.next().ok_or("verdict_token")?;
    let confirmed=match kind{
        b"X"=>true,
        b"E"=>false,
        _=>return Err("verdict_token"),
    };
    let elapsed=fields.next().ok_or("verdict_missing")?;
    if fields.next().is_some(){return Err("verdict_extra_field");}
    if elapsed.is_empty()||elapsed.len()>12{return Err("verdict_malformed");}
    let mut elapsed_ms=0u64;
    for byte in elapsed.iter().copied(){
        if !byte.is_ascii_digit(){return Err("verdict_malformed");}
        elapsed_ms=elapsed_ms*10+u64::from(byte-b'0');
    }
    // The host says what happened; the state machine still decides whether that
    // verdict is legal for this window.
    if !confirmed||elapsed_ms>=CONFIRM_WINDOW_MS{
        return Ok(StageVerdict::Expired{elapsed_ms});
    }
    let len=read_reply(&mut line)?;
    match decode_attestation_reply(&line[..len],challenge){
        Ok(attestation)=>Ok(StageVerdict::InsideWindow(attestation)),
        Err(e)=>{
            serial::write_fmt(format_args!(
                "WOLFOS_GPU_ATTEST_FAIL stage={} reason={} bytes={} source_digest={:08x}\n",
                challenge.stage_label(),e.label(),len,digest
            ));
            Err("attest_reply")
        }
    }
}

/// What the desktop stage really proved, for the caller's serial evidence.
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
pub(crate) struct DesktopEvidence{
    pub entries:usize,
    pub selectable:usize,
    pub device_reported:usize,
    pub device_claim:&'static str,
    pub device_width:u32,
    pub device_height:u32,
    pub edid_millihz:u32,
    pub automatic_width:u32,
    pub automatic_height:u32,
    pub second_width:u32,
    pub second_height:u32,
    pub refresh:&'static str,
    pub captures:u32,
    pub backing_entries:usize,
    pub used_idx:u16,
    pub tx_state:&'static str,
    pub tx_outcome:&'static str,
    pub tx_from_width:u32,
    pub tx_from_height:u32,
    pub tx_to_width:u32,
    pub tx_to_height:u32,
    pub tx_deadline_ms:u64,
    pub tx_elapsed_ms:u64,
    pub tx_readback:&'static str,
    pub tx_restore:&'static str,
}

/// Present the kernel's REAL 1024x768 Limine framebuffer as the native scanout
/// resource, discover a second real geometry (1024x384) from the same resource
/// and then run ONE transactional mode change back to the desktop mode: plan,
/// apply, device readback, host-attested confirmation, or -- when the host
/// reports the window elapsed -- a verified rollback.
///
/// The host must answer every stage with a nonce-bound digest computed from a
/// real screenshot; the driver never grades itself.
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
fn present_desktop(
    vas:&[u64;FRAMES],frames:&[u64;FRAMES],notify_port:u64,selected:u16,
    fb:&crate::virtio_gpu_desktop_wire::Framebuffer,facts:CatalogFacts,
)->Result<DesktopEvidence,&'static str>{
    use crate::virtio_gpu_desktop_wire as desk;
    use crate::display_mode_catalog::{ModeCatalog,ModeEntry,RefreshEvidence};
    use crate::display_mode_policy::{RefreshChoice,ResolutionChoice,UserChoice};
    use crate::display_mode_transaction::ModeChangeTransaction;
    const CREATE_FENCE:u64=0x574f_4c46_4444_4352;
    const ATTACH_FENCE:u64=0x574f_4c46_4444_4154;
    const SET_FENCE:u64=0x574f_4c46_4444_5343;
    const FLUSH_FENCE:u64=0x574f_4c46_4444_464c;
    const CLEAR_FENCE:u64=0x574f_4c46_4444_434c;
    const DETACH_FENCE:u64=0x574f_4c46_4444_4454;
    const UNREF_FENCE:u64=0x574f_4c46_4444_5552;
    const TRANSFER_BASE:u64=0x574f_4c46_4444_5400;
    fb.supported().map_err(|_|"framebuffer_layout")?;
    let mut fences=[0u64;7+desk::BANDS];
    fences[0]=CREATE_FENCE;fences[1]=ATTACH_FENCE;
    let mut index=0usize;
    while index<desk::BANDS{
        fences[2+index]=TRANSFER_BASE+index as u64;
        index+=1;
    }
    fences[2+desk::BANDS]=SET_FENCE;
    fences[3+desk::BANDS]=FLUSH_FENCE;
    fences[4+desk::BANDS]=CLEAR_FENCE;
    fences[5+desk::BANDS]=DETACH_FENCE;
    fences[6+desk::BANDS]=UNREF_FENCE;
    scanout::unique_fences(fences).map_err(|_|"desktop_fence_reused")?;
    // Every stage that the host had to answer with its own screenshot. Printed
    // as evidence, so a missing capture is visible instead of implied.
    let mut captures=0u32;
    // 1. Real desktop frame: paint VRAM, copy the rows into the backing pages
    //    and prove the copy is the intended image before any device sees it.
    let desktop_digest=stage_image(fb,vas,Image::Desktop)?;
    let create=desk::create(CREATE_FENCE).map_err(|_|"create_wire")?;
    send_resource_command(vas,frames,notify_port,selected,3,
        &create,CREATE_FENCE)?;
    let mut request=[0u8;desk::REQUEST_LIMIT];
    let plan=desk::attach(&frames[5..5+desk::PAGES],&mut request,ATTACH_FENCE)
        .map_err(|_|"attach_wire")?;
    send_resource_command(vas,frames,notify_port,selected,4,
        &request[..plan.len],ATTACH_FENCE)?;
    let mut next=upload_bands(vas,frames,notify_port,selected,5,
        desk::BANDS,Image::Desktop,TRANSFER_BASE)?;
    let set=desk::set_scanout(SET_FENCE).map_err(|_|"scanout_set_wire")?;
    send_resource_command(vas,frames,notify_port,selected,next,&set,SET_FENCE)?;
    next+=1;
    let flush=desk::flush(FLUSH_FENCE).map_err(|_|"scanout_flush_wire")?;
    send_resource_command(vas,frames,notify_port,selected,next,&flush,FLUSH_FENCE)?;
    next+=1;
    let desktop=await_host_attestation(
        b'P',DESKTOP_NONCE,desk::WIDTH,desk::HEIGHT,desktop_digest
    )?;
    captures+=1;
    if desktop.width()!=desk::WIDTH||desktop.height()!=desk::HEIGHT||
        desktop.nonce()!=DESKTOP_NONCE||desktop.digest()!=desktop_digest{
        return Err("attestation_binding");
    }
    // 2. Second real geometry: the same resource presented as 1024x384. Only
    //    the rows it owns are repainted and re-uploaded, so the desktop frame
    //    below row 384 stays byte-identical in device memory.
    let reduced_digest=stage_image(fb,vas,Image::Reduced)?;
    next=upload_bands(vas,frames,notify_port,selected,next,
        desk::ALT_BANDS,Image::Reduced,TX_FENCE_BASE)?;
    let alt_set=desk::alt_set_scanout(TX_SET_FENCE).map_err(|_|"scanout_set_wire")?;
    send_resource_command(vas,frames,notify_port,selected,next,
        &alt_set,TX_SET_FENCE)?;
    next+=1;
    let alt_flush=desk::alt_flush(TX_FLUSH_FENCE).map_err(|_|"scanout_flush_wire")?;
    send_resource_command(vas,frames,notify_port,selected,next,
        &alt_flush,TX_FLUSH_FENCE)?;
    next+=1;
    let reduced=await_host_attestation(
        b'S',REDUCED_STAGE_NONCE,desk::ALT_WIDTH,desk::ALT_HEIGHT,reduced_digest
    )?;
    captures+=1;
    if reduced.width()!=desk::ALT_WIDTH||reduced.height()!=desk::ALT_HEIGHT||
        reduced.nonce()!=REDUCED_STAGE_NONCE||reduced.digest()!=reduced_digest{
        return Err("attestation_binding");
    }
    // 3. The catalog only ever contains what the host proved. The device's own
    //    GET_DISPLAY_INFO geometry and the EDID refresh stay refused.
    let selection=crate::display_mode_catalog::prove_desktop_selection(
        DESKTOP_GENERATION,0,desktop,Some(reduced),
        Some((facts.device_width,facts.device_height)),
        facts.edid_refresh_millihz,
    )?;
    // 4. One real transaction: the device currently shows 1024x384 and the
    //    user asks for the attested desktop mode back.
    let mut modes=ModeCatalog::new(DESKTOP_GENERATION).map_err(|_|"catalog_generation")?;
    modes.record(desktop.entry(0)).map_err(|_|"catalog_record_desktop")?;
    modes.record(reduced.entry(0)).map_err(|_|"catalog_record_reduced")?;
    let current=modes.choose(DESKTOP_GENERATION,UserChoice{
        resolution:ResolutionChoice::Exact{width:desk::ALT_WIDTH,height:desk::ALT_HEIGHT},
        refresh:RefreshChoice::Automatic,
    }).map_err(|_|"catalog_current_mode")?;
    let mut tx=ModeChangeTransaction::begin(
        &modes,DESKTOP_GENERATION,current,
        UserChoice{
            resolution:ResolutionChoice::Exact{
                width:desk::WIDTH,height:desk::HEIGHT,
            },
            refresh:RefreshChoice::Automatic,
        },
        TX_TOKEN,0,
    ).map_err(|_|"mode_tx_plan")?.ok_or("mode_tx_noop")?;
    if tx.previous()!=current||tx.requested()!=desktop.entry(0){
        return Err("mode_tx_endpoints");
    }
    // 5. Apply for real: repaint the desktop rows and re-upload exactly the
    //    bands the reduced mode overwrote, then present the desktop rect.
    let restored_digest=stage_image(fb,vas,Image::Desktop)?;
    if restored_digest!=desktop_digest{return Err("desktop_restore_not_identical");}
    next=upload_bands(vas,frames,notify_port,selected,next,
        desk::ALT_BANDS,Image::Desktop,TX_FENCE_BASE+0x40)?;
    let set=desk::set_scanout(TX_SET_FENCE+1).map_err(|_|"scanout_set_wire")?;
    send_resource_command(vas,frames,notify_port,selected,next,
        &set,TX_SET_FENCE+1)?;
    next+=1;
    let flush=desk::flush(TX_FLUSH_FENCE+1).map_err(|_|"scanout_flush_wire")?;
    send_resource_command(vas,frames,notify_port,selected,next,
        &flush,TX_FLUSH_FENCE+1)?;
    next+=1;
    // 6. The device must really report the requested rectangle now.
    let readback=query_display_now(vas,frames,notify_port,selected,next)?;
    next+=1;
    // The device's own statement, printed before it is graded so a mismatch is
    // visible instead of implied.
    serial::write_fmt(format_args!(
        "WOLFOS_VIRTIO_GPU_DISPLAY_READBACK index={} enabled={} x={} y={} width={} height={} flags={}\n",
        next-1,readback.enabled,readback.x,readback.y,readback.width,
        readback.height,readback.flags
    ));
    // This device answers GET_DISPLAY_INFO with its *console* geometry (the
    // boot-time VGA mode) instead of the scanout rectangle the driver set, so
    // the readback is graded for exactly what it can prove:
    //  * our rectangle          -> the device really switched (strong),
    //  * the stable console one -> scanout attached and enabled (weak, named),
    //  * anything else          -> contradiction, never confirmed.
    if (readback.width,readback.height)==(facts.device_width,facts.device_height){
        if let Err(e)=tx.observe_scanout_enabled(readback.enabled==1){
            serial::write_fmt(format_args!(
                "WOLFOS_VIRTIO_GPU_MODE_TX_FAIL stage={} state={} enabled={}\n",
                e.label(),tx.state().label(),readback.enabled
            ));
            return Err("mode_tx_readback_enabled");
        }
    }else{
        let observed=ModeEntry::device_reported(0,readback.width,readback.height,
            RefreshEvidence::Unavailable);
        if let Err(e)=tx.observe_applied(observed){
            serial::write_fmt(format_args!(
                "WOLFOS_VIRTIO_GPU_MODE_TX_FAIL stage={} state={} readback={}x{}\n",
                e.label(),tx.state().label(),readback.width,readback.height
            ));
            return Err("mode_tx_readback_geometry");
        }
    }
    // 7. The user's verdict, measured by the host and graded by the state
    //    machine: an early or late claim is refused, not obeyed.
    let verdict=await_stage_verdict(
        b'T',APPLIED_STAGE_NONCE,desk::WIDTH,desk::HEIGHT,desktop_digest
    )?;
    captures+=1;
    let mut elapsed_ms=0u64;
    let mut restore="unused";
    match verdict{
        StageVerdict::InsideWindow(attestation)=>{
            if attestation.width()!=desk::WIDTH||
                attestation.height()!=desk::HEIGHT||
                attestation.nonce()!=APPLIED_STAGE_NONCE||
                attestation.digest()!=desktop_digest{
                return Err("attestation_binding");
            }
            // Elapsed 0 is the host's own inside-window verdict: the attestation
            // arrived before the window closed.
            if let Err(e)=tx.confirm(
                TX_TOKEN,DESKTOP_GENERATION,attestation.entry(0),0
            ){
                serial::write_fmt(format_args!(
                    "WOLFOS_VIRTIO_GPU_MODE_TX_FAIL stage={} state={}\n",
                    e.label(),tx.state().label()
                ));
                return Err("mode_tx_confirm");
            }
        }
        StageVerdict::Expired{elapsed_ms:host_elapsed}=>{
            elapsed_ms=host_elapsed;
            if let Err(e)=tx.expire(host_elapsed){
                serial::write_fmt(format_args!(
                    "WOLFOS_VIRTIO_GPU_MODE_TX_FAIL stage={} state={} elapsed_ms={}\n",
                    e.label(),tx.state().label(),host_elapsed
                ));
                return Err("mode_tx_expiry");
            }
            // Roll back for real, then require host pixels again.
            let rollback_digest=stage_image(fb,vas,Image::Reduced)?;
            if rollback_digest!=reduced_digest{return Err("rollback_restore_not_identical");}
            next=upload_bands(vas,frames,notify_port,selected,next,
                desk::ALT_BANDS,Image::Reduced,TX_FENCE_BASE+0x80)?;
            let set=desk::alt_set_scanout(TX_SET_FENCE+2).map_err(|_|"scanout_set_wire")?;
            send_resource_command(vas,frames,notify_port,selected,next,
                &set,TX_SET_FENCE+2)?;
            next+=1;
            let flush=desk::alt_flush(TX_FLUSH_FENCE+2).map_err(|_|"scanout_flush_wire")?;
            send_resource_command(vas,frames,notify_port,selected,next,
                &flush,TX_FLUSH_FENCE+2)?;
            next+=1;
            let restored=await_host_attestation(
                b'R',ROLLBACK_STAGE_NONCE,desk::ALT_WIDTH,desk::ALT_HEIGHT,reduced_digest
            )?;
            captures+=1;
            tx.complete_rollback(restored.entry(0)).map_err(|_|"mode_tx_rollback")?;
            restore="verified";
        }
    }
    if !tx.resources_may_be_released(){
        return Err("mode_tx_open_transaction");
    }
    if tx.settled_mode()!=Some(tx.previous())&&
        tx.settled_mode()!=Some(tx.requested()){
        return Err("mode_tx_settled_mode");
    }
    let outcome=tx.outcome();
    let state=tx.state().label();
    // Bounded teardown of exactly this resource. The caller still resets the
    // device before any pinned frame may be freed.
    let clear=scanout::disable(true,CLEAR_FENCE).map_err(|_|"scanout_disable_wire")?;
    send_resource_command(vas,frames,notify_port,selected,next,&clear.bytes,CLEAR_FENCE)?;
    next+=1;
    let detach=desk::detach(DETACH_FENCE).map_err(|_|"detach_wire")?;
    send_resource_command(vas,frames,notify_port,selected,next,&detach,DETACH_FENCE)?;
    next+=1;
    let unref=desk::unref(UNREF_FENCE).map_err(|_|"unref_wire")?;
    send_resource_command(vas,frames,notify_port,selected,next,&unref,UNREF_FENCE)?;
    next+=1;
    Ok(DesktopEvidence{
        entries:selection.entries,
        selectable:selection.selectable,
        device_reported:selection.device_reported,
        device_claim:selection.device_claim,
        device_width:facts.device_width,
        device_height:facts.device_height,
        edid_millihz:facts.edid_refresh_millihz,
        automatic_width:selection.automatic_width,
        automatic_height:selection.automatic_height,
        second_width:selection.second_width,
        second_height:selection.second_height,
        refresh:selection.refresh.label(),
        captures,
        backing_entries:plan.entries,
        used_idx:next-1,
        tx_state:state,
        tx_outcome:outcome,
        tx_from_width:tx.previous().width,
        tx_from_height:tx.previous().height,
        tx_to_width:tx.requested().width,
        tx_to_height:tx.requested().height,
        tx_deadline_ms:tx.deadline_ms(),
        tx_elapsed_ms:elapsed_ms,
        tx_readback:tx.applied_label(),
        tx_restore:restore,
    })
}

#[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
fn verify_mode_catalog(
    vas:&[u64;FRAMES],facts:CatalogFacts,
    attestations:&[Option<crate::display_mode_catalog::Attestation>;3],
)->Result<(),&'static str>{
    use crate::display_mode_catalog::{
        CatalogError,ModeCatalog,ModeEntry,RefreshEvidence,
    };
    const GENERATION:u64=1;
    const TOKEN:u64=0x574f_4c46_4d4f_4445;
    // Any GPU command would advance the device's used index. Catalog work is
    // pure policy: it must consume no completion and touch no register.
    let read_used=||{
        fence(Ordering::SeqCst);
        u16::from_le(unsafe{((vas[2]+2)as *const u16).read_volatile()})
    };
    let before=read_used();
    let mut modes=ModeCatalog::new(GENERATION).map_err(|_|"catalog_generation")?;
    // Only geometry the host really attested with a nonce-bound pixel digest.
    // The driver cannot assert HostVerifiedApplied on its own any more.
    let mut attested=0usize;
    for attestation in attestations.iter().copied(){
        let Some(attestation)=attestation else{continue;};
        modes.record(attestation.entry(0)).map_err(|_|"catalog_record_attested")?;
        attested+=1;
    }
    let unattested=attestations.len()-attested;
    // Fail closed: with no genuine host attestation nothing may be selectable.
    if attested==0{
        if modes.choose(GENERATION,mode_policy::UserChoice::AUTOMATIC)
            !=Err(CatalogError::NoSelectableMode){
            return Err("catalog_selectable_without_attestation");
        }
    }
    // A subset must not inherit an unattested geometry: drop the 64x64 active
    // attestation and the automatic choice must fall back to 32x32, proving
    // the selection really depends on host evidence rather than a constant.
    if let Some(reduced)=attestations[1]{
        let mut reduced_only=ModeCatalog::new(GENERATION).map_err(|_|"catalog_generation")?;
        reduced_only.record(reduced.entry(0))
            .map_err(|_|"catalog_record_subset")?;
        let subset=reduced_only.choose(GENERATION,mode_policy::UserChoice::AUTOMATIC)
            .map_err(|_|"catalog_subset_automatic")?;
        if subset.width!=32||subset.height!=32{
            return Err("catalog_automatic_ignored_attestation_subset");
        }
    }
    // GET_DISPLAY_INFO's own claim is recorded but stays non-selectable.
    modes.record(ModeEntry::device_reported(0,facts.device_width,
        facts.device_height,RefreshEvidence::Unavailable))
        .map_err(|_|"catalog_record_device")?;
    let automatic=modes.choose(GENERATION,mode_policy::UserChoice::AUTOMATIC)
        .map_err(|_|"catalog_automatic")?;
    if automatic.width!=64||automatic.height!=64{
        return Err("catalog_automatic_unproven_geometry");
    }
    if automatic.refresh!=RefreshEvidence::Unavailable{
        return Err("catalog_automatic_invented_refresh");
    }
    let manual=modes.choose(GENERATION,mode_policy::UserChoice{
        resolution:mode_policy::ResolutionChoice::Exact{width:32,height:32},
        refresh:mode_policy::RefreshChoice::Automatic,
    }).map_err(|_|"catalog_manual_32x32")?;
    if manual.width!=32||manual.height!=32{return Err("catalog_manual_geometry");}
    if manual.refresh!=RefreshEvidence::Unavailable{
        return Err("catalog_manual_invented_refresh");
    }
    // The device's own reported scanout must never authorize a switch.
    if modes.choose(GENERATION,mode_policy::UserChoice{
        resolution:mode_policy::ResolutionChoice::Exact{
            width:facts.device_width,height:facts.device_height,
        },
        refresh:mode_policy::RefreshChoice::Automatic,
    })!=Err(CatalogError::UnprovenGpuTiming){
        return Err("catalog_device_reported_accepted");
    }
    // Every advertised EDID geometry must be refused as unproven.
    let mut edid_refused=0usize;
    for (width,height) in facts.edid_geometries[..facts.edid_geometry_len].iter().copied(){
        match modes.choose(GENERATION,mode_policy::UserChoice{
            resolution:mode_policy::ResolutionChoice::Exact{width,height},
            refresh:mode_policy::RefreshChoice::Automatic,
        }){
            Err(CatalogError::UnprovenGpuTiming)=>edid_refused+=1,
            _=>return Err("catalog_edid_only_mode_accepted"),
        }
    }
    // An EDID hertz value is monitor data, not a programmable GPU rate.
    if modes.choose(GENERATION,mode_policy::UserChoice{
        resolution:mode_policy::ResolutionChoice::Automatic,
        refresh:mode_policy::RefreshChoice::ExactMilliHz(facts.edid_refresh_millihz),
    })!=Err(CatalogError::RefreshNotProgrammable){
        return Err("catalog_edid_refresh_accepted");
    }
    let plan=modes.plan_change(GENERATION,automatic,mode_policy::UserChoice{
        resolution:mode_policy::ResolutionChoice::Exact{width:32,height:32},
        refresh:mode_policy::RefreshChoice::Automatic,
    },TOKEN,1_000).map_err(|_|"catalog_plan")?.ok_or("catalog_plan_missing")?;
    if plan.rollback_target()!=automatic{return Err("catalog_plan_rollback_target");}
    if plan.confirm(TOKEN,GENERATION,manual,2_000)!=Ok(manual){
        return Err("catalog_confirm_readback");
    }
    if plan.confirm(TOKEN,GENERATION,automatic,2_000)!=Err(CatalogError::DeviceDidNotApply){
        return Err("catalog_confirm_unapplied_mode");
    }
    if modes.plan_change(GENERATION,automatic,mode_policy::UserChoice::AUTOMATIC,
        TOKEN,1_000)!=Ok(None){
        return Err("catalog_automatic_change_not_noop");
    }
    let after=read_used();
    if after!=before{return Err("catalog_consumed_gpu_command");}
    serial::write_fmt(format_args!(
        "WOLFOS_DISPLAY_CATALOG_OK generation={} entries={} selectable={} attested={} unattested={} device_reported={} device_width={} device_height={} automatic_width={} automatic_height={} automatic_refresh={} automatic_change_required=0 manual_32x32=accepted manual_32x32_refresh={} device_reported_mode=rejected:{} edid_advertised={} edid_refused={} edid_hz_request=rejected:{} plan=some plan_confirm=accepted plan_wrong_readback=rejected:{} confirmation_window_ms={} gpu_commands_sent=0 used_idx_before={} used_idx_after={} refusal_capture_acks=1 host_pixels_verified_by_kernel=0\n",
        GENERATION,modes.entries().len(),modes.selectable_count(),attested,unattested,
        modes.device_reported_count(),facts.device_width,facts.device_height,
        automatic.width,automatic.height,automatic.refresh_label(),
        manual.refresh_label(),CatalogError::UnprovenGpuTiming.label(),
        facts.edid_mode_count,edid_refused,
        CatalogError::RefreshNotProgrammable.label(),
        CatalogError::DeviceDidNotApply.label(),
        crate::display_mode_catalog::CONFIRM_WINDOW_MS,before,after
    ));
    Ok(())
}

#[cfg(feature="qemu-virtio-gpu-resource2d-smoke")]
fn query_resource2d(
    vas:&[u64;FRAMES], frames:&[u64;FRAMES], notify_port:u64, selected:u16,
    _facts:CatalogFacts,
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
    #[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
    const SHRINK_SET_FENCE:u64=0x574f_4c46_4e53_5431;
    #[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
    const SHRINK_FLUSH_FENCE:u64=0x574f_4c46_4e46_4c31;
    #[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
    const EXPAND_SET_FENCE:u64=0x574f_4c46_4e53_5432;
    #[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
    const EXPAND_FLUSH_FENCE:u64=0x574f_4c46_4e46_4c32;
    #[cfg(all(feature="qemu-virtio-gpu-scanout-live-smoke",
              not(feature="qemu-virtio-gpu-native-rollback-smoke")))]
    scanout::unique_fences([
        CREATE_FENCE,ATTACH_FENCE,TRANSFER_FENCE,SET_FENCE,FLUSH_FENCE,
        CLEAR_FENCE,DETACH_FENCE,UNREF_FENCE
    ]).map_err(|_|"scanout_fence_reused")?;
    #[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
    scanout::unique_fences([
        CREATE_FENCE,ATTACH_FENCE,TRANSFER_FENCE,SET_FENCE,FLUSH_FENCE,
        SHRINK_SET_FENCE,SHRINK_FLUSH_FENCE,EXPAND_SET_FENCE,
        EXPAND_FLUSH_FENCE,CLEAR_FENCE,DETACH_FENCE,UNREF_FENCE
    ]).map_err(|_|"native_rollback_fence_reused")?;
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
            // Host captures a QMP PPM and answers with a nonce-bound pixel
            // digest. Without that reply the catalog gets no evidence at all.
            #[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
            let mut attestations=[None;3];
            #[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
            {
                attestations[0]=Some(await_host_attestation(
                    b'A',ACTIVE_NONCE,64,64,source_digest(64,64)?
                )?);
            }
            #[cfg(not(feature="qemu-virtio-gpu-native-rollback-smoke"))]
            await_host_capture("active",b'A')?;
            #[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
            {
                // Native VirtIO rectangle change: same pinned 64x64 resource,
                // no reset, DMA replacement, detach or extra PMM allocations.
                let shrink=scanout::set_32(
                    resource::RESOURCE_ID,true,SHRINK_SET_FENCE
                ).map_err(|_|"native_shrink_wire")?;
                send_resource_command(vas,frames,notify_port,selected,8,
                    &shrink.bytes,shrink.fence)?;
                let shrunk_flush=scanout::flush_32(
                    resource::RESOURCE_ID,true,SHRINK_FLUSH_FENCE
                ).map_err(|_|"native_shrink_flush_wire")?;
                send_resource_command(vas,frames,notify_port,selected,9,
                    &shrunk_flush.bytes,shrunk_flush.fence)?;
                attestations[1]=Some(await_host_attestation(
                    b'M',REDUCED_NONCE,32,32,source_digest(32,32)?
                )?);
                let expand=scanout::set(resource::RESOURCE_ID,true,
                    0,0,64,64,EXPAND_SET_FENCE
                ).map_err(|_|"native_expand_wire")?;
                send_resource_command(vas,frames,notify_port,selected,10,
                    &expand.bytes,expand.fence)?;
                let expanded_flush=scanout::flush(resource::RESOURCE_ID,true,
                    0,0,64,64,EXPAND_FLUSH_FENCE
                ).map_err(|_|"native_expand_flush_wire")?;
                send_resource_command(vas,frames,notify_port,selected,11,
                    &expanded_flush.bytes,expanded_flush.fence)?;
                attestations[2]=Some(await_host_attestation(
                    b'E',REEXPANDED_NONCE,64,64,source_digest(64,64)?
                )?);
                // Pure-policy catalog evidence: refuses every EDID-only and
                // device-reported geometry, and must not alter the display.
                verify_mode_catalog(vas,_facts,&attestations)?;
                await_host_capture("refused",b'F')?;
            }
            let clear=scanout::disable(true,CLEAR_FENCE)
                .map_err(|_|"scanout_disable_wire")?;
            #[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
            let clear_index=12;
            #[cfg(not(feature="qemu-virtio-gpu-native-rollback-smoke"))]
            let clear_index=8;
            send_resource_command(vas,frames,notify_port,selected,clear_index,
                &clear.bytes,clear.fence)?;
            // Host verifies the scanout pattern disappears. Original console
            // geometry is NOT restored by resource_id=0 in this QEMU model.
            await_host_capture("disabled",b'D')?;
        }
        let detach=backing::detach(resource::RESOURCE_ID,true,DETACH_FENCE)
            .map_err(|_|"detach_wire")?;
        #[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
        let detach_index=13;
        #[cfg(all(feature="qemu-virtio-gpu-scanout-live-smoke",
                  not(feature="qemu-virtio-gpu-native-rollback-smoke")))]
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
    #[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
    let unref_index=14;
    #[cfg(all(feature="qemu-virtio-gpu-scanout-live-smoke",
              not(feature="qemu-virtio-gpu-native-rollback-smoke")))]
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
// Desktop scanout pins a real 3 MiB resource: 5 controlq pages plus the 768
// backing pages that hold the framebuffer rows.
#[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
const FRAMES:usize=5+crate::virtio_gpu_desktop_wire::PAGES;
#[cfg(all(feature="qemu-virtio-gpu-attach-backing-smoke",
          not(feature="qemu-virtio-gpu-desktop-scanout-smoke")))]
const FRAMES:usize=9;
#[cfg(all(not(feature="qemu-virtio-gpu-attach-backing-smoke"),
          not(feature="qemu-virtio-gpu-desktop-scanout-smoke")))]
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
    cap:pci::QemuNotifyWindow, layout:queue::Layout,
    fb:&crate::virtio_gpu_desktop_wire::Framebuffer)->bool{
    #[cfg(not(feature="qemu-virtio-gpu-desktop-scanout-smoke"))]
    let _=fb;
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
    #[cfg(feature="qemu-virtio-gpu-scanout-reset-smoke")]
    let mut reset_capture_ok=false;
    let mut completed=false;
    let mut did_notify=false;
    let mut display_info:Option<display::DisplayOne>=None;
    #[cfg(feature="qemu-virtio-gpu-edid-live-smoke")]
    let mut edid_info:Option<EdidProof>=None;
    #[cfg(feature="qemu-virtio-gpu-resource2d-smoke")]
    let mut resource_done=false;
    #[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
    let mut desktop_entries=0usize;
    #[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
    let mut desktop_used_idx=0u16;
    #[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
    let mut desktop_captures=0u32;
    #[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
    let mut desktop_catalog=false;
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
                            let facts=match (display_info.as_ref(),edid_info.as_ref()){
                                (Some(display),Some(edid))=>CatalogFacts{
                                    device_width:display.width,
                                    device_height:display.height,
                                    edid_mode_count:edid.modes,
                                    edid_refresh_millihz:edid.refresh_millihz,
                                    edid_geometries:edid.geometries,
                                    edid_geometry_len:edid.geometry_len,
                                },
                                _=>CatalogFacts::EMPTY,
                            };
                            #[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
                            let outcome=present_desktop(
                                &vas,&frames,port,layout.selected,fb,facts
                            ).map(|evidence|{
                                desktop_entries=evidence.backing_entries;
                                desktop_used_idx=evidence.used_idx;
                                desktop_captures=evidence.captures;
                                // Attest first, catalog second. Every selectable
                                // mode here came from the host's own pixel
                                // proof, and the device/EDID data below can
                                // never authorize a switch.
                                desktop_catalog=true;
                                serial::write_fmt(format_args!(
                                    "WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_OK generation={} entries={} selectable={} attested=2 device_reported={} device_width={} device_height={} selected={}x{} selected_refresh={} second={}x{} device_claim={} edid_millihz={} edid_hz_request=rejected:{} applied_change_plan=none unattested_catalog=rejected:{} gpu_commands_sent=0\n",
                                    DESKTOP_GENERATION,evidence.entries,
                                    evidence.selectable,evidence.device_reported,
                                    evidence.device_width,evidence.device_height,
                                    evidence.automatic_width,evidence.automatic_height,
                                    evidence.refresh,
                                    evidence.second_width,evidence.second_height,
                                    evidence.device_claim,
                                    evidence.edid_millihz,
                                    crate::display_mode_catalog::CatalogError::
                                        RefreshNotProgrammable.label(),
                                    crate::display_mode_catalog::CatalogError::
                                        NoSelectableMode.label()
                                ));
                                serial::write_fmt(format_args!(
                                    "WOLFOS_VIRTIO_GPU_MODE_TX_OK generation={} token={:016x} from={}x{} to={}x{} deadline_ms={} verdict_elapsed_ms={} readback={} state={} outcome={} restore={} window_enforced_by=host host_pixels_verified_by_kernel=0\n",
                                    DESKTOP_GENERATION,TX_TOKEN,
                                    evidence.tx_from_width,evidence.tx_from_height,
                                    evidence.tx_to_width,evidence.tx_to_height,
                                    evidence.tx_deadline_ms,evidence.tx_elapsed_ms,
                                    evidence.tx_readback,evidence.tx_state,
                                    evidence.tx_outcome,evidence.tx_restore
                                ));
                            });
                            #[cfg(not(feature="qemu-virtio-gpu-desktop-scanout-smoke"))]
                            let outcome=query_resource2d(
                                &vas,&frames,port,layout.selected,facts
                            );
                            match outcome {
                                Ok(())=>resource_done=true,
                                Err(e)=>{
                                    #[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
                                    {
                                        // The screen was not proven, so nothing
                                        // may be selectable: report the empty
                                        // catalog explicitly instead of leaving
                                        // the absence of evidence unstated.
                                        serial::write_fmt(format_args!(
                                            "WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_FAIL stage={e} entries=0 selectable=0 mode={}\n",
                                            crate::display_mode_catalog::CatalogError::
                                                NoSelectableMode.label()
                                        ));
                                        serial::write_fmt(format_args!(
                                            "WOLFOS_VIRTIO_GPU_DESKTOP_FAIL stage={e}\n"
                                        ));
                                    }
                                    #[cfg(not(feature="qemu-virtio-gpu-desktop-scanout-smoke"))]
                                    serial::write_fmt(format_args!(
                                        "WOLFOS_VIRTIO_GPU_RESOURCE2D_FAIL stage={e}\n"
                                    ));
                                }
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
        // VirtIO-GPU VGA compatibility returns on device reset, not on
        // SET_SCANOUT(resource_id=0). The host independently captures the
        // screen while all DMA frames are still exclusively owned.
        #[cfg(feature="qemu-virtio-gpu-scanout-reset-smoke")]
        if reset_confirmed&&resource_done{
            match await_host_capture("restored",b'R'){
                Ok(())=>reset_capture_ok=true,
                Err(e)=>serial::write_fmt(format_args!(
                    "WOLFOS_VIRTIO_GPU_SCANOUT_RESET_FAIL capture={e}\n"
                )),
            }
        }
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
    #[cfg(feature="qemu-virtio-gpu-scanout-reset-smoke")]
    let reset_capture_proven=reset_capture_ok;
    #[cfg(not(feature="qemu-virtio-gpu-scanout-reset-smoke"))]
    let reset_capture_proven=true;
    #[cfg(feature="qemu-virtio-gpu-edid-live-smoke")]
    let edid_ok=edid_info.is_some();
    #[cfg(not(feature="qemu-virtio-gpu-edid-live-smoke"))]
    let edid_ok=true;
    #[cfg(feature="qemu-virtio-gpu-resource2d-smoke")]
    let resource_ok=resource_done;
    #[cfg(not(feature="qemu-virtio-gpu-resource2d-smoke"))]
    let resource_ok=true;
    if !preflight||!addresses_ok||!zeroed||!exposed||!did_notify||
        !completed||!edid_ok||!resource_ok||!reset_confirmed||!balanced||
        !unmapped_ok||!reset_capture_proven{
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
    #[cfg(all(feature="qemu-virtio-gpu-scanout-live-smoke",
              not(feature="qemu-virtio-gpu-native-rollback-smoke"),
              not(feature="qemu-virtio-gpu-desktop-scanout-smoke")))]
    if resource_done {
        serial::write_line(
            "WOLFOS_VIRTIO_GPU_SCANOUT_OK resource_id=1 format=2 width=64 height=64 create_type=257 attach_type=262 transfer_type=261 set_type=259 flush_type=260 clear_type=259 detach_type=263 unref_type=258 response_type=4352 used_idx=10 used_head=0 used_len=24 fences_verified=8 notify_writes=10 backing_entries=4 backing_bytes=16384 guest_pattern_verified=2 set_ack=1 flush_ack=1 clear_ack=1 detach_ack=1 unref_ack=1 capture_acks=3 host_pixels_verified_by_kernel=0 reset=0 queue_disabled=1 frames_allocated=9 frames_released=9 pmm_leak=0 qemu_only=1"
        );
    }
    #[cfg(all(feature="qemu-virtio-gpu-scanout-reset-smoke",
              not(feature="qemu-virtio-gpu-native-rollback-smoke"),
              not(feature="qemu-virtio-gpu-desktop-scanout-smoke")))]
    if resource_done&&reset_capture_ok{
        serial::write_line(
            "WOLFOS_VIRTIO_GPU_SCANOUT_RESET_OK reset_to_vga_ack=1 capture_acks=4 geometry_and_pixels_verified_by_kernel=0 reset=0 queue_disabled=1 frames_allocated=9 frames_released=9 pmm_leak=0 qemu_only=1"
        );
    }
    #[cfg(feature="qemu-virtio-gpu-desktop-scanout-smoke")]
    if resource_done&&reset_capture_ok&&desktop_catalog{
        // Every count here is the driver's own control-queue accounting; the
        // host validates the exact values against its own capture sequence.
        let fences=desktop_used_idx.saturating_sub(2);
        serial::write_fmt(format_args!(
            "WOLFOS_VIRTIO_GPU_DESKTOP_SCANOUT_OK resource_id=1 width=1024 height=768 format=2 create_type=257 attach_type=262 transfer_type=261 set_type=259 flush_type=260 clear_type=259 detach_type=263 unref_type=258 response_type=4352 used_idx={} used_head=0 used_len=24 fences_verified={} notify_writes={} backing_entries={} backing_bytes=3145728 transfer_bands=12 band_rows=64 alt=1024x384 alt_bands=6 pixels=786432 guest_copy_verified=1 host_pixels_verified_by_kernel=0 capture_acks={} reset_to_vga_ack=1 reset=0 queue_disabled=1 frames_allocated={FRAMES} frames_released={FRAMES} pmm_leak=0 qemu_only=1\n",
            desktop_used_idx,fences,desktop_used_idx,desktop_entries,desktop_captures
        ));
    }
    #[cfg(feature="qemu-virtio-gpu-native-rollback-smoke")]
    if resource_done&&reset_capture_ok{
        serial::write_line(
            "WOLFOS_VIRTIO_GPU_NATIVE_ROLLBACK_OK resource_id=1 width_before=64 width_changed=32 width_restored=64 height_before=64 height_changed=32 height_restored=64 set_type=259 flush_type=260 response_type=4352 used_idx=14 used_head=0 used_len=24 fences_verified=12 notify_writes=14 guest_pattern_verified=2 native_switch_acks=4 reset_to_vga_ack=1 capture_acks=7 host_pixels_verified_by_kernel=0 reset=0 queue_disabled=1 frames_allocated=9 frames_released=9 pmm_leak=0 qemu_only=1"
        );
    }
    true
}
