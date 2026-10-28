//! Pure VirtIO-GPU 1.2 single GET_DISPLAY_INFO response contract.
//! One 24-byte request, one 408-byte response, split ring with 2 descriptors.
pub const REQUEST_BYTES:usize=24;
pub const RESPONSE_BYTES:usize=24+16*24;
pub const CMD_GET_DISPLAY_INFO:u32=0x0100;
pub const RESP_OK_DISPLAY_INFO:u32=0x1101;
pub const QUEUE_SIZE_MIN:u16=2;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct DisplayOne {
    pub x:u32,pub y:u32,pub width:u32,pub height:u32,
    pub enabled:u32,pub flags:u32,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Error{
    QueueTooSmall,BadUsedIndex,BadUsedHead,BadUsedLength,
    BadResponseType,BadResponseFlags,BadDimensions,BadEnabled,
}
fn u32le(bytes:&[u8;RESPONSE_BYTES],offset:usize)->u32{
    u32::from_le_bytes([
        bytes[offset],bytes[offset+1],bytes[offset+2],bytes[offset+3]
    ])
}
pub fn validate(selected:u16,used_idx:u16,head:u32,written:u32,
    response:&[u8;RESPONSE_BYTES])->Result<DisplayOne,Error>{
    if selected<QUEUE_SIZE_MIN{return Err(Error::QueueTooSmall);}
    if used_idx!=1{return Err(Error::BadUsedIndex);}
    if head!=0{return Err(Error::BadUsedHead);}
    if written!=RESPONSE_BYTES as u32{return Err(Error::BadUsedLength);}
    if u32le(response,0)!=RESP_OK_DISPLAY_INFO{
        return Err(Error::BadResponseType);
    }
    // No FENCE or INFO_RING_IDX requested; QEMU reply should be plain.
    if u32le(response,4)!=0{return Err(Error::BadResponseFlags);}
    let info=DisplayOne{
        x:u32le(response,24),y:u32le(response,28),
        width:u32le(response,32),height:u32le(response,36),
        enabled:u32le(response,40),flags:u32le(response,44),
    };
    if info.enabled>1{return Err(Error::BadEnabled);}
    if info.width>16384 || info.height>16384{
        return Err(Error::BadDimensions);
    }
    if info.enabled==1 && (info.width==0 || info.height==0){
        return Err(Error::BadDimensions);
    }
    Ok(info)
}
#[cfg(test)]
mod tests{
    use super::*;
    fn good()->[u8;RESPONSE_BYTES]{
        let mut r=[0u8;RESPONSE_BYTES];
        r[..4].copy_from_slice(&RESP_OK_DISPLAY_INFO.to_le_bytes());
        r[32..36].copy_from_slice(&1024u32.to_le_bytes());
        r[36..40].copy_from_slice(&768u32.to_le_bytes());
        r[40..44].copy_from_slice(&1u32.to_le_bytes());r
    }
    fn check(r:&[u8;RESPONSE_BYTES])->Result<DisplayOne,Error>{
        validate(256,1,0,RESPONSE_BYTES as u32,r)
    }
    #[test] fn exact_virtio_response_layout(){
        assert_eq!(REQUEST_BYTES,24);
        assert_eq!(RESPONSE_BYTES,408);
        assert_eq!(check(&good()).unwrap().width,1024);
    }
    #[test] fn accepts_valid_but_disabled_headless_scanout(){
        let mut r=good();r[32..44].fill(0);
        let x=check(&r).unwrap();assert_eq!(x.enabled,0);
    }
    #[test] fn refuses_missing_completion(){
        assert_eq!(validate(256,0,0,408,&good()),Err(Error::BadUsedIndex));
    }
    #[test] fn refuses_wrong_head_or_size(){
        assert_eq!(validate(256,1,1,408,&good()),Err(Error::BadUsedHead));
        assert_eq!(validate(256,1,0,24,&good()),Err(Error::BadUsedLength));
        assert_eq!(validate(1,1,0,408,&good()),Err(Error::QueueTooSmall));
    }
    #[test] fn refuses_wrong_response_type_or_flags(){
        let mut r=good();r[..4].copy_from_slice(&0x1200u32.to_le_bytes());
        assert_eq!(check(&r),Err(Error::BadResponseType));
        let mut r=good();r[4]=1;
        assert_eq!(check(&r),Err(Error::BadResponseFlags));
    }
    #[test] fn refuses_nonsensical_scanout_state(){
        let mut r=good();r[40]=2;assert_eq!(check(&r),Err(Error::BadEnabled));
        let mut r=good();r[32..36].fill(0);
        assert_eq!(check(&r),Err(Error::BadDimensions));
        let mut r=good();r[32..36].copy_from_slice(&65535u32.to_le_bytes());
        assert_eq!(check(&r),Err(Error::BadDimensions));
    }
}
