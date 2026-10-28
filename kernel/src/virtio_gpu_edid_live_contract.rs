//! Strict second split-ring completion contract for real QEMU GET_EDID.
//! Host-testable, no MMIO or DMA, never treats a sent request as completion.
pub const EDID_RESPONSE_BYTES:u32=1056;
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Error{PriorNotCompleted,MissingSecondCompletion,WrongDescriptor,WrongLength}
pub fn validate(first_done:bool,used_idx:u16,used_id:u32,used_len:u32)->Result<(),Error>{
    if !first_done{return Err(Error::PriorNotCompleted);}
    if used_idx!=2{return Err(Error::MissingSecondCompletion);}
    if used_id!=0{return Err(Error::WrongDescriptor);}
    if used_len!=EDID_RESPONSE_BYTES{return Err(Error::WrongLength);}
    Ok(())
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]fn exact_second_completion(){assert_eq!(validate(true,2,0,1056),Ok(()));}
    #[test]fn cannot_mistake_first_completion_for_edid(){
        assert_eq!(validate(true,1,0,1056),Err(Error::MissingSecondCompletion));
        assert_eq!(validate(false,2,0,1056),Err(Error::PriorNotCompleted));
    }
    #[test]fn cannot_accept_stale_or_truncated_dma(){
        assert_eq!(validate(true,2,1,1056),Err(Error::WrongDescriptor));
        assert_eq!(validate(true,2,0,32),Err(Error::WrongLength));
        assert_eq!(validate(true,3,0,1056),Err(Error::MissingSecondCompletion));
    }
}
