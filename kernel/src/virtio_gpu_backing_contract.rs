//! QEMU-only VirtIO-GPU attach/detach of four exclusively owned RAM frames.
//! No scanout, transfer, host-visible pixels, physical GPU or disk writes.
pub const ATTACH: u32 = 0x0106;
pub const DETACH: u32 = 0x0107;
pub const FRAME_BYTES: u32 = 4096;
pub const ENTRIES: usize = 4;
pub const PIXEL_BYTES: u32 = 64 * 64 * 4;
pub const ATTACH_BYTES: usize = 32 + ENTRIES * 16;
pub const DETACH_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NoCreateAck, NoAttachAck, InvalidResource, InvalidFence,
    DuplicateFence, InvalidBackingFrame, DuplicateBackingFrame, ExtentMismatch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub bytes: [u8; ATTACH_BYTES],
    pub len: usize,
    pub fence: u64,
}
fn header(ty:u32, fence:u64)->Result<[u8;ATTACH_BYTES],Error>{
    if fence==0{return Err(Error::InvalidFence);}
    let mut r=[0u8;ATTACH_BYTES];
    r[..4].copy_from_slice(&ty.to_le_bytes());
    r[4..8].copy_from_slice(&1u32.to_le_bytes()); // VIRTIO_GPU_FLAG_FENCE
    r[8..16].copy_from_slice(&fence.to_le_bytes());
    Ok(r)
}
pub fn distinct_fences(fences:[u64;4])->Result<(),Error>{
    for i in 0..4{
        if fences[i]==0{return Err(Error::InvalidFence);}
        for j in 0..i{
            if fences[j]==fences[i]{return Err(Error::DuplicateFence);}
        }
    }
    Ok(())
}
pub fn attach(resource:u32, create_ack:bool, pages:[u64;ENTRIES], fence:u64)
    ->Result<Request,Error>{
    if !create_ack{return Err(Error::NoCreateAck);}
    if resource==0{return Err(Error::InvalidResource);}
    let mut total=0u32;
    for i in 0..ENTRIES{
        if pages[i]==0||pages[i]%u64::from(FRAME_BYTES)!=0||
           pages[i].checked_add(u64::from(FRAME_BYTES)).is_none(){
            return Err(Error::InvalidBackingFrame);
        }
        for j in 0..i{
            if pages[i]==pages[j]{return Err(Error::DuplicateBackingFrame);}
        }
        total=total.checked_add(FRAME_BYTES).ok_or(Error::ExtentMismatch)?;
    }
    if total!=PIXEL_BYTES{return Err(Error::ExtentMismatch);}
    let mut bytes=header(ATTACH,fence)?;
    bytes[24..28].copy_from_slice(&resource.to_le_bytes());
    bytes[28..32].copy_from_slice(&(ENTRIES as u32).to_le_bytes());
    for (i,physical) in pages.iter().enumerate(){
        let at=32+i*16;
        bytes[at..at+8].copy_from_slice(&physical.to_le_bytes());
        bytes[at+8..at+12].copy_from_slice(&FRAME_BYTES.to_le_bytes());
        // entries' 32-bit reserved padding remains zero.
    }
    Ok(Request{bytes,len:ATTACH_BYTES,fence})
}
pub fn detach(resource:u32,attach_ack:bool,fence:u64)->Result<Request,Error>{
    if !attach_ack{return Err(Error::NoAttachAck);}
    if resource==0{return Err(Error::InvalidResource);}
    let mut bytes=header(DETACH,fence)?;
    bytes[24..28].copy_from_slice(&resource.to_le_bytes());
    Ok(Request{bytes,len:DETACH_BYTES,fence})
}

#[cfg(test)]
mod tests{
    use super::*;
    fn u32at(x:&[u8],i:usize)->u32{u32::from_le_bytes(x[i..i+4].try_into().unwrap())}
    fn u64at(x:&[u8],i:usize)->u64{u64::from_le_bytes(x[i..i+8].try_into().unwrap())}
    const P:[u64;4]=[0x1000,0x3000,0x5000,0x7000];
    #[test] fn exact_attach_wire_four_disjoint_frames(){
        let q=attach(1,true,P,0x1234_5678_9abc_def0).unwrap();
        assert_eq!(q.len,96);
        assert_eq!(u32at(&q.bytes,0),0x0106);
        assert_eq!(u32at(&q.bytes,4),1);
        assert_eq!(u64at(&q.bytes,8),q.fence);
        assert_eq!(u64at(&q.bytes,16),0);
        assert_eq!(u32at(&q.bytes,24),1);
        assert_eq!(u32at(&q.bytes,28),4);
        for (i,physical) in P.iter().enumerate(){
            let at=32+i*16;
            assert_eq!(u64at(&q.bytes,at),*physical);
            assert_eq!(u32at(&q.bytes,at+8),4096);
            assert_eq!(u32at(&q.bytes,at+12),0);
        }
    }
    #[test] fn refuse_attach_before_real_create_ack(){
        assert_eq!(attach(1,false,P,1),Err(Error::NoCreateAck));
        assert_eq!(attach(0,true,P,1),Err(Error::InvalidResource));
        assert_eq!(attach(1,true,P,0),Err(Error::InvalidFence));
    }
    #[test] fn refuse_unowned_unaligned_or_repeated_pages(){
        for bad in [[0,0x3000,0x5000,0x7000],[0x1001,0x3000,0x5000,0x7000],
                    [0x1000,0x1000,0x5000,0x7000],[u64::MAX-4094,0x3000,0x5000,0x7000]]{
            assert!(attach(1,true,bad,1).is_err());
        }
    }
    #[test] fn detach_requires_ack_and_exact_wire(){
        assert_eq!(detach(1,false,2),Err(Error::NoAttachAck));
        assert_eq!(detach(0,true,2),Err(Error::InvalidResource));
        assert_eq!(detach(1,true,0),Err(Error::InvalidFence));
        let q=detach(1,true,0x8877_6655_4433_2211).unwrap();
        assert_eq!(q.len,32);
        assert_eq!(u32at(&q.bytes,0),0x0107);
        assert_eq!(u32at(&q.bytes,4),1);
        assert_eq!(u64at(&q.bytes,8),q.fence);
        assert_eq!(u32at(&q.bytes,24),1);
        assert_eq!(u32at(&q.bytes,28),0);
        assert!(q.bytes[32..].iter().all(|x|*x==0));
    }
    #[test] fn refuse_duplicate_or_zero_lifecycle_fences(){
        assert_eq!(distinct_fences([1,2,3,4]),Ok(()));
        assert_eq!(distinct_fences([1,2,2,4]),Err(Error::DuplicateFence));
        assert_eq!(distinct_fences([1,0,3,4]),Err(Error::InvalidFence));
    }
    #[test] fn extent_and_request_bytes_are_strict(){
        assert_eq!(ENTRIES*FRAME_BYTES as usize,PIXEL_BYTES as usize);
        assert_eq!(ATTACH_BYTES,96);
        assert_eq!(DETACH_BYTES,32);
    }
}
