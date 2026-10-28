//! QEMU-only 64x64 B8G8R8X8 guest-buffer to host-resource 2D transfer.
//! The 56-byte request only proves host acceptance, NOT host pixel readback
//! or scanout. The four PMM-owned pages remain pinned until device reset.

pub const COMMAND: u32 = 0x0105; // VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D
pub const REQUEST_BYTES: usize = 56;
pub const WIDTH: u32 = 64;
pub const HEIGHT: u32 = 64;
pub const PIXEL_BYTES: usize = 4;
pub const BACKING_PAGES: usize = 4;
pub const PAGE_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NoAttachAck, InvalidResource, InvalidFence, RepeatedFence,
    InvalidExtent, InvalidOffset, OutsideBacking,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub bytes: [u8; REQUEST_BYTES],
    pub fence: u64,
}

pub fn distinct_fences(fences:[u64;5])->Result<(),Error>{
    for i in 0..fences.len(){
        if fences[i]==0{return Err(Error::InvalidFence);}
        for j in 0..i{
            if fences[i]==fences[j]{return Err(Error::RepeatedFence);}
        }
    }
    Ok(())
}

/// Full-resource transfer only: no out-of-bounds rectangle, offset or stride
/// is accepted in this deliberately narrow QEMU-only stage.
pub fn encode(resource:u32,attach_ack:bool,width:u32,height:u32,
              offset:u64,fence:u64)->Result<Request,Error>{
    if !attach_ack{return Err(Error::NoAttachAck);}
    if resource==0{return Err(Error::InvalidResource);}
    if width!=WIDTH||height!=HEIGHT{return Err(Error::InvalidExtent);}
    if offset!=0{return Err(Error::InvalidOffset);}
    if fence==0{return Err(Error::InvalidFence);}
    if (width as usize).checked_mul(height as usize)
        .and_then(|v|v.checked_mul(PIXEL_BYTES))
        !=Some(BACKING_PAGES*PAGE_BYTES){
        return Err(Error::OutsideBacking);
    }
    let mut bytes=[0u8;REQUEST_BYTES];
    bytes[0..4].copy_from_slice(&COMMAND.to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes()); // FENCE flag
    bytes[8..16].copy_from_slice(&fence.to_le_bytes());
    // ctx_id/padding = 0; x=y=0, x/y are not host-backed offsets.
    bytes[32..36].copy_from_slice(&width.to_le_bytes());
    bytes[36..40].copy_from_slice(&height.to_le_bytes());
    // offset u64 @40 is 0, resource @48, padding @52 remains 0.
    bytes[48..52].copy_from_slice(&resource.to_le_bytes());
    Ok(Request{bytes,fence})
}

/// Deterministic nonzero byte pattern; no heap, no physical GPU, no DMA writes.
/// Page 0..3 maps exactly to the four scatter-gather PMM backing entries.
pub fn pattern_byte(page:usize,at:usize)->Result<u8,Error>{
    if page>=BACKING_PAGES||at>=PAGE_BYTES{return Err(Error::OutsideBacking);}
    Ok((((page as u32)*37+(at as u32)*17+1)%251+1) as u8)
}

#[cfg(test)]
mod tests{
    use super::*;
    fn u32at(s:&[u8],n:usize)->u32{u32::from_le_bytes(s[n..n+4].try_into().unwrap())}
    fn u64at(s:&[u8],n:usize)->u64{u64::from_le_bytes(s[n..n+8].try_into().unwrap())}
    #[test] fn exact_56_byte_full_resource_transfer_wire(){
        let req=encode(1,true,64,64,0,0x0123_4567_89ab_cdef).unwrap();
        assert_eq!(req.bytes.len(),56);
        assert_eq!(u32at(&req.bytes,0),0x0105);
        assert_eq!(u32at(&req.bytes,4),1);
        assert_eq!(u64at(&req.bytes,8),req.fence);
        assert_eq!(u32at(&req.bytes,16),0);
        assert_eq!(u32at(&req.bytes,20),0);
        assert_eq!(u32at(&req.bytes,24),0);
        assert_eq!(u32at(&req.bytes,28),0);
        assert_eq!(u32at(&req.bytes,32),64);
        assert_eq!(u32at(&req.bytes,36),64);
        assert_eq!(u64at(&req.bytes,40),0);
        assert_eq!(u32at(&req.bytes,48),1);
        assert_eq!(u32at(&req.bytes,52),0);
    }
    #[test] fn missing_attach_ack_or_bad_resource_fails_closed(){
        assert_eq!(encode(1,false,64,64,0,1),Err(Error::NoAttachAck));
        assert_eq!(encode(0,true,64,64,0,1),Err(Error::InvalidResource));
        assert_eq!(encode(1,true,64,64,0,0),Err(Error::InvalidFence));
    }
    #[test] fn no_smaller_larger_or_shifted_rectangle_and_offset(){
        for (w,h,off) in [(63,64,0),(64,63,0),(65,64,0),(64,65,0),
                          (0,64,0),(64,0,0)]{
            assert_eq!(encode(1,true,w,h,off,1),Err(Error::InvalidExtent));
        }
        assert_eq!(encode(1,true,64,64,1,1),Err(Error::InvalidOffset));
        assert_eq!(encode(1,true,64,64,4096,1),Err(Error::InvalidOffset));
    }
    #[test] fn five_lifecycle_fences_nonzero_and_unique(){
        assert_eq!(distinct_fences([1,2,3,4,5]),Ok(()));
        assert_eq!(distinct_fences([1,2,3,4,1]),Err(Error::RepeatedFence));
        assert_eq!(distinct_fences([1,0,3,4,5]),Err(Error::InvalidFence));
    }
    #[test] fn all_four_pages_have_deterministic_nonzero_bounded_pattern(){
        let mut total=0usize;
        for page in 0..4{
            for at in 0..4096{
                assert!(pattern_byte(page,at).unwrap()!=0);
                total+=1;
            }
        }
        assert_eq!(total,64*64*4);
        assert_ne!(pattern_byte(0,0),pattern_byte(1,0));
        assert_eq!(pattern_byte(4,0),Err(Error::OutsideBacking));
        assert_eq!(pattern_byte(0,4096),Err(Error::OutsideBacking));
    }
}
