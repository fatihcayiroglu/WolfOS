//! Pure PCI VirtIO 1.2 queue-notify address contract.
//! Checks the actual notify capability against the previously sized common BAR;
//! never reads the write-only notification register or submits work.
pub const PAGE:u64=4096;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Capability {
    pub bar_base:u64,
    pub bar_bytes:u64,
    pub cap_offset:u32,
    pub cap_length:u32,
    pub multiplier:u32,
    pub same_measured_bar:bool,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Resolved {
    pub register:u64,
    pub physical_page:u64,
    pub page_offset:u64,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Error {
    SeparateUnmeasuredBar, BadAperture, Unassigned, BadAlignment,
    BadMultiplier, RangeTooSmall, Overflow, OutsideCap, OutsideBar,
    CrossesPage,
}
pub fn resolve(c:Capability,queue_off:u16)->Result<Resolved,Error>{
    if !c.same_measured_bar{return Err(Error::SeparateUnmeasuredBar);}
    if c.bar_base==0{return Err(Error::Unassigned);}
    if c.bar_bytes<PAGE || !c.bar_bytes.is_power_of_two()
        || c.bar_base%c.bar_bytes!=0 {return Err(Error::BadAperture);}
    if c.cap_offset%2!=0{return Err(Error::BadAlignment);}
    // This first implementation supports QEMU's normal nonzero multiplier
    // only. Other spec-compliant 0 / notification-data modes need dedicated
    // proof before actual queue notifications.
    if c.multiplier==0 || !c.multiplier.is_power_of_two()
        || c.multiplier<2 {return Err(Error::BadMultiplier);}
    if c.cap_length<2{return Err(Error::RangeTooSmall);}
    let delta=u64::from(queue_off).checked_mul(u64::from(c.multiplier))
        .ok_or(Error::Overflow)?;
    if delta.checked_add(2).ok_or(Error::Overflow)? >u64::from(c.cap_length)
       {return Err(Error::OutsideCap);}
    let cap_start=c.bar_base.checked_add(u64::from(c.cap_offset))
        .ok_or(Error::Overflow)?;
    let cap_end=cap_start.checked_add(u64::from(c.cap_length))
        .ok_or(Error::Overflow)?;
    let reg=cap_start.checked_add(delta).ok_or(Error::Overflow)?;
    let reg_end=reg.checked_add(2).ok_or(Error::Overflow)?;
    let bar_end=c.bar_base.checked_add(c.bar_bytes).ok_or(Error::Overflow)?;
    if cap_end>bar_end || reg_end>bar_end {return Err(Error::OutsideBar);}
    if reg%2!=0{return Err(Error::BadAlignment);}
    let physical_page=reg&!(PAGE-1);
    if physical_page<c.bar_base ||
        physical_page.checked_add(PAGE).ok_or(Error::Overflow)? >bar_end
    {return Err(Error::CrossesPage);}
    if reg_end>physical_page+PAGE{return Err(Error::CrossesPage);}
    Ok(Resolved{register:reg,physical_page,page_offset:reg-physical_page})
}
#[cfg(test)]
mod tests{
    use super::*;
    fn cap()->Capability{
        Capability{bar_base:0x8000_0000,bar_bytes:PAGE,
          cap_offset:0x300,cap_length:16,multiplier:4,same_measured_bar:true}
    }
    #[test] fn real_qemu_shape_queue_zero(){
        assert_eq!(resolve(cap(),0),Ok(Resolved{
            register:0x8000_0300,physical_page:0x8000_0000,page_offset:0x300
        }));
    }
    #[test] fn respects_queue_off_and_multiplier(){
        assert_eq!(resolve(cap(),2).unwrap().register,0x8000_0308);
    }
    #[test] fn rejects_unmeasured_second_bar(){
        let mut c=cap();c.same_measured_bar=false;
        assert_eq!(resolve(c,0),Err(Error::SeparateUnmeasuredBar));
    }
    #[test] fn rejects_null_and_invalid_apertures(){
        let mut c=cap();c.bar_base=0;
        assert_eq!(resolve(c,0),Err(Error::Unassigned));
        let mut c=cap();c.bar_bytes=123;
        assert_eq!(resolve(c,0),Err(Error::BadAperture));
    }
    #[test] fn refuses_bad_multiplier_and_alignment(){
        let mut c=cap();c.multiplier=0;
        assert_eq!(resolve(c,0),Err(Error::BadMultiplier));
        let mut c=cap();c.multiplier=3;
        assert_eq!(resolve(c,0),Err(Error::BadMultiplier));
        let mut c=cap();c.cap_offset=0x301;
        assert_eq!(resolve(c,0),Err(Error::BadAlignment));
    }
    #[test] fn refuses_outside_notification_cap(){
        assert_eq!(resolve(cap(),4),Err(Error::OutsideCap));
        let mut c=cap();c.cap_length=1;
        assert_eq!(resolve(c,0),Err(Error::RangeTooSmall));
    }
    #[test] fn refuses_outside_measured_bar(){
        let mut c=cap();c.cap_offset=0xff0;c.cap_length=32;
        assert_eq!(resolve(c,0),Err(Error::OutsideBar));
    }
    #[test] fn accepts_last_two_bytes_in_page(){
        let mut c=cap();c.bar_bytes=PAGE;c.cap_offset=0xffe;
        c.cap_length=2;
        assert!(resolve(c,0).is_ok());
    }
    #[test] fn refuses_arithmetic_overflow(){
        let mut c=cap();c.bar_base=u64::MAX-0xfff;
        assert_eq!(resolve(c,0),Err(Error::Overflow));
    }
}
