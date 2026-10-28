//! Pure, no-heap QEMU VirtIO-GPU common MMIO window and register contract.
//! Never assume a PCI BAR is mapped by Limine HHDM. Physical aperture and
//! preferred capability must already have passed genuine BAR sizing/rollback.

pub const PAGE_BYTES:u64=4096;
pub const COMMON_NUM_QUEUES:u64=0x12;
pub const COMMON_DEVICE_STATUS:u64=0x14;
pub const COMMON_CONFIG_GENERATION:u64=0x15;

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Window {
    pub bar_base:u64,
    pub bar_bytes:u64,
    pub offset:u32,
    pub length:u32,
    pub is_memory:bool,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Span {
    pub physical_page:u64,
    pub page_offset:u64,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum WindowError {
    NotMmio, Unassigned, BadAperture, Overflow, OutsideBar,
    CrossesPage, TooShort, BadQueues, BadStatus,
}

pub fn check(window:Window)->Result<Span,WindowError> {
    if !window.is_memory {return Err(WindowError::NotMmio);}
    if window.bar_base==0 {return Err(WindowError::Unassigned);}
    if window.bar_bytes==0 || !window.bar_bytes.is_power_of_two()
        || window.bar_base%window.bar_bytes!=0
    {return Err(WindowError::BadAperture);}
    if window.length<56 {return Err(WindowError::TooShort);}
    let bar_end=window.bar_base.checked_add(window.bar_bytes)
        .ok_or(WindowError::Overflow)?;
    let begin=window.bar_base.checked_add(u64::from(window.offset))
        .ok_or(WindowError::Overflow)?;
    let end=begin.checked_add(u64::from(window.length))
        .ok_or(WindowError::Overflow)?;
    if end>bar_end {return Err(WindowError::OutsideBar);}
    let physical_page=begin & !(PAGE_BYTES-1);
    let page_offset=begin-physical_page;
    if page_offset+u64::from(window.length)>PAGE_BYTES
        || physical_page<window.bar_base
        || physical_page.checked_add(PAGE_BYTES).ok_or(WindowError::Overflow)? > bar_end
    {return Err(WindowError::CrossesPage);}
    Ok(Span{physical_page,page_offset})
}

pub fn validate_readonly(queues:u16,status:u8)->Result<(),WindowError> {
    if queues==0 || queues>256 {return Err(WindowError::BadQueues);}
    // VIRTIO spec: ACK 1, DRIVER 2, DRIVER_OK 4, FEATURES_OK 8,
    // DEVICE_NEEDS_RESET 0x40, FAILED 0x80. Other bits reserved.
    if status & !0xcf !=0 {return Err(WindowError::BadStatus);}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn win()->Window {
        Window{bar_base:0x8000_0000,bar_bytes:0x4000,offset:0x100,
               length:56,is_memory:true}
    }
    #[test]
    fn permits_bounded_one_page_readonly_common_cfg() {
        assert_eq!(check(win()),Ok(Span{physical_page:0x8000_0000,page_offset:256}));
    }
    #[test]
    fn refuses_io_or_unassigned_bar() {
        let mut w=win();w.is_memory=false;
        assert_eq!(check(w),Err(WindowError::NotMmio));
        let mut w=win();w.bar_base=0;
        assert_eq!(check(w),Err(WindowError::Unassigned));
    }
    #[test]
    fn refuses_non_power_two_or_misaligned_aperture() {
        let mut w=win();w.bar_bytes=0x3000;
        assert_eq!(check(w),Err(WindowError::BadAperture));
        let mut w=win();w.bar_base+=0x1000;
        assert_eq!(check(w),Err(WindowError::BadAperture));
    }
    #[test]
    fn refuses_too_short_common_region() {
        let mut w=win();w.length=55;
        assert_eq!(check(w),Err(WindowError::TooShort));
    }
    #[test]
    fn refuses_region_exceeding_measured_bar() {
        let mut w=win();w.offset=0x3ff0;
        assert_eq!(check(w),Err(WindowError::OutsideBar));
    }
    #[test]
    fn refuses_region_straddling_page() {
        let mut w=win();w.offset=0xff0;
        assert_eq!(check(w),Err(WindowError::CrossesPage));
    }
    #[test]
    fn refuses_small_bar_that_cannot_hold_whole_page() {
        let mut w=win();w.bar_bytes=0x100;
        assert_eq!(check(w),Err(WindowError::OutsideBar));
    }
    #[test]
    fn refuses_overflowed_physical_spans() {
        let mut w=win();w.bar_base=u64::MAX-0x3fff;
        assert_eq!(check(w),Err(WindowError::Overflow));
    }
    #[test]
    fn accept_only_bounded_real_queue_counts() {
        assert_eq!(validate_readonly(2,0),Ok(()));
        assert_eq!(validate_readonly(0,0),Err(WindowError::BadQueues));
        assert_eq!(validate_readonly(257,0),Err(WindowError::BadQueues));
    }
    #[test]
    fn reject_reserved_status_bits() {
        assert_eq!(validate_readonly(2,0x10),Err(WindowError::BadStatus));
        assert_eq!(validate_readonly(2,0xcf),Ok(()));
    }
    #[test]
    fn common_field_offsets_are_stable() {
        assert_eq!((COMMON_NUM_QUEUES,COMMON_DEVICE_STATUS,
                    COMMON_CONFIG_GENERATION),(18,20,21));
    }
}
