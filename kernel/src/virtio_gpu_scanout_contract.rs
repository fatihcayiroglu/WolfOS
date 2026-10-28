//! Opt-in QEMU-only 64x64 scanout/flush/disable wire contract.
//! This does not assert reversible display state without independent host
//! before/after QMP PPM pixel comparison.
pub const CMD_SET_SCANOUT:u32=0x0103;
pub const CMD_RESOURCE_FLUSH:u32=0x0104;
pub const REQUEST_BYTES:usize=48;
pub const WIDTH:u32=64;
pub const HEIGHT:u32=64;
pub const SCANOUT_ID:u32=0;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Error{NoTransferAck,NoSetAck,NoFlushAck,InvalidResource,InvalidFence,
    ReusedFence,WrongRectangle,UnexpectedOffset}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Request{pub bytes:[u8;REQUEST_BYTES],pub fence:u64}
fn header(cmd:u32,fence:u64)->Result<[u8;REQUEST_BYTES],Error>{
    if fence==0{return Err(Error::InvalidFence);}
    let mut b=[0u8;REQUEST_BYTES];
    b[..4].copy_from_slice(&cmd.to_le_bytes());
    b[4..8].copy_from_slice(&1u32.to_le_bytes()); // fence
    b[8..16].copy_from_slice(&fence.to_le_bytes());
    Ok(b)
}
pub fn unique_fences<const N:usize>(f:[u64;N])->Result<(),Error>{
    for i in 0..f.len(){
        if f[i]==0{return Err(Error::InvalidFence);}
        for j in 0..i{if f[i]==f[j]{return Err(Error::ReusedFence);}}
    }
    Ok(())
}
pub fn set(resource:u32,transfer_ack:bool,x:u32,y:u32,w:u32,h:u32,
           fence:u64)->Result<Request,Error>{
    if !transfer_ack{return Err(Error::NoTransferAck);}
    if resource==0{return Err(Error::InvalidResource);}
    if x!=0||y!=0||w!=WIDTH||h!=HEIGHT{return Err(Error::WrongRectangle);}
    let mut b=header(CMD_SET_SCANOUT,fence)?;
    b[32..36].copy_from_slice(&w.to_le_bytes());
    b[36..40].copy_from_slice(&h.to_le_bytes());
    b[40..44].copy_from_slice(&SCANOUT_ID.to_le_bytes());
    b[44..48].copy_from_slice(&resource.to_le_bytes());
    Ok(Request{bytes:b,fence})
}
pub fn flush(resource:u32,set_ack:bool,x:u32,y:u32,w:u32,h:u32,
             fence:u64)->Result<Request,Error>{
    if !set_ack{return Err(Error::NoSetAck);}
    if resource==0{return Err(Error::InvalidResource);}
    if x!=0||y!=0||w!=WIDTH||h!=HEIGHT{return Err(Error::WrongRectangle);}
    let mut b=header(CMD_RESOURCE_FLUSH,fence)?;
    b[32..36].copy_from_slice(&w.to_le_bytes());
    b[36..40].copy_from_slice(&h.to_le_bytes());
    b[40..44].copy_from_slice(&resource.to_le_bytes());
    Ok(Request{bytes:b,fence})
}
// QEMU-only native scanout rectangle change. A 32x32 view is fully covered
// by the one pinned 64x64 resource; no new DMA mapping or backing lifetime.
pub fn set_32(resource:u32,transfer_ack:bool,fence:u64)->Result<Request,Error>{
    if !transfer_ack{return Err(Error::NoTransferAck);}
    if resource==0{return Err(Error::InvalidResource);}
    let mut b=header(CMD_SET_SCANOUT,fence)?;
    b[32..36].copy_from_slice(&32u32.to_le_bytes());
    b[36..40].copy_from_slice(&32u32.to_le_bytes());
    b[40..44].copy_from_slice(&SCANOUT_ID.to_le_bytes());
    b[44..48].copy_from_slice(&resource.to_le_bytes());
    Ok(Request{bytes:b,fence})
}
pub fn flush_32(resource:u32,set_ack:bool,fence:u64)->Result<Request,Error>{
    if !set_ack{return Err(Error::NoSetAck);}
    if resource==0{return Err(Error::InvalidResource);}
    let mut b=header(CMD_RESOURCE_FLUSH,fence)?;
    b[32..36].copy_from_slice(&32u32.to_le_bytes());
    b[36..40].copy_from_slice(&32u32.to_le_bytes());
    b[40..44].copy_from_slice(&resource.to_le_bytes());
    Ok(Request{bytes:b,fence})
}
pub fn disable(flush_ack:bool,fence:u64)->Result<Request,Error>{
    if !flush_ack{return Err(Error::NoFlushAck);}
    let b=header(CMD_SET_SCANOUT,fence)?;
    // full rect, scanout 0 and resource 0: disable, not a new modeset.
    Ok(Request{bytes:b,fence})
}
#[cfg(test)]
mod tests{
    use super::*;
    fn get32(b:&[u8],at:usize)->u32{u32::from_le_bytes(b[at..at+4].try_into().unwrap())}
    #[test]fn strict_scanout_wire(){
        let q=set(1,true,0,0,64,64,7).unwrap();
        assert_eq!(q.bytes.len(),48);
        assert_eq!(get32(&q.bytes,0),0x103);
        assert_eq!(get32(&q.bytes,4),1);
        assert_eq!(get32(&q.bytes,16),0);
        assert_eq!(get32(&q.bytes,20),0);
        assert_eq!(get32(&q.bytes,24),0);
        assert_eq!(get32(&q.bytes,28),0);
        assert_eq!(get32(&q.bytes,32),64);
        assert_eq!(get32(&q.bytes,36),64);
        assert_eq!(get32(&q.bytes,40),0);
        assert_eq!(get32(&q.bytes,44),1);
    }
    #[test]fn strict_flush_and_disable(){
        let q=flush(1,true,0,0,64,64,8).unwrap();
        assert_eq!(get32(&q.bytes,0),0x104);
        assert_eq!(get32(&q.bytes,40),1);
        assert_eq!(get32(&q.bytes,44),0);
        let q=disable(true,9).unwrap();
        assert_eq!(get32(&q.bytes,0),0x103);
        assert_eq!(&q.bytes[24..],&[0u8;24]);
    }
    #[test]fn no_missing_acks_or_outside_rect(){
        assert_eq!(set(1,false,0,0,64,64,1),Err(Error::NoTransferAck));
        assert_eq!(set(0,true,0,0,64,64,1),Err(Error::InvalidResource));
        assert_eq!(set(1,true,1,0,64,64,1),Err(Error::WrongRectangle));
        assert_eq!(set(1,true,0,0,65,64,1),Err(Error::WrongRectangle));
        assert_eq!(flush(1,false,0,0,64,64,1),Err(Error::NoSetAck));
        assert_eq!(flush(1,true,0,0,64,63,1),Err(Error::WrongRectangle));
        assert_eq!(disable(false,1),Err(Error::NoFlushAck));
        assert_eq!(disable(true,0),Err(Error::InvalidFence));
    }
    #[test]fn strict_native_resize_wire_and_ack_gate(){
        let a=set_32(1,true,41).unwrap();
        assert_eq!(get32(&a.bytes,0),CMD_SET_SCANOUT);
        assert_eq!(get32(&a.bytes,32),32);
        assert_eq!(get32(&a.bytes,36),32);
        assert_eq!(get32(&a.bytes,40),0);
        assert_eq!(get32(&a.bytes,44),1);
        let f=flush_32(1,true,42).unwrap();
        assert_eq!(get32(&f.bytes,0),CMD_RESOURCE_FLUSH);
        assert_eq!(get32(&f.bytes,32),32);
        assert_eq!(get32(&f.bytes,36),32);
        assert_eq!(get32(&f.bytes,40),1);
        assert_eq!(set_32(1,false,41),Err(Error::NoTransferAck));
        assert_eq!(set_32(0,true,41),Err(Error::InvalidResource));
        assert_eq!(flush_32(1,false,42),Err(Error::NoSetAck));
        assert_eq!(flush_32(0,true,42),Err(Error::InvalidResource));
        assert_eq!(set_32(1,true,0),Err(Error::InvalidFence));
        assert_eq!(flush_32(1,true,0),Err(Error::InvalidFence));
        assert_eq!(unique_fences([1,2,3,4,5,6,7,8,9,10,11,12]),Ok(()));
        assert_eq!(unique_fences([1,2,3,4,5,6,7,8,9,10,11,2]),
                   Err(Error::ReusedFence));
    }
    #[test]fn all_eight_fences_unique_and_nonzero(){
        assert_eq!(unique_fences([1,2,3,4,5,6,7,8]),Ok(()));
        assert_eq!(unique_fences([1,2,3,4,5,6,7,1]),Err(Error::ReusedFence));
        assert_eq!(unique_fences([1,2,0,4,5,6,7,8]),Err(Error::InvalidFence));
    }
}
