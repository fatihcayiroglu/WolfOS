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
const SLOT:u64=0x0000_4000_0000_b000;
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
    if x86_64::instructions::interrupts::are_enabled()||
       !owned_frames_valid(layout,&[0x1000,0x2000,0x3000,0x4000,0x5000]) {
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
            // SAFETY: these are five exclusively PMM-owned, 4KiB
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
        wr32(8,1);let selector_one=rd32(8);
        wr32(12,1);let negotiated=rd32(12);
        wr32(8,0);let selector_zero=rd32(8);
        unsafe{st.write_volatile(11);}
        let features=unsafe{st.read_volatile()};
        let handshake=initial_reset==0&&ack==1&&driver==3&&
            selector_one==1&&negotiated==1&&selector_zero==0&&
            features==11;
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
    // five PMM frames until QEMU teardown; never risk reuse while DMA live.
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
    if !preflight||!addresses_ok||!zeroed||!exposed||!did_notify||
        !completed||!reset_confirmed||!balanced||!unmapped_ok{
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
        "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK req=256 resp=4353 used_idx=1 used_head=0 used_len=408 scanout0_enabled={} width={} height={} notify_writes=1 driver_ok=15 reset=0 queue_disabled=1 frames_allocated=5 frames_released=5 response_dma_verified=1 pmm_leak=0 qemu_only=1\n",
        mode.enabled,mode.width,mode.height
    ));
    true
}
