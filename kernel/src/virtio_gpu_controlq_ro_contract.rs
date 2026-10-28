//! QEMU VirtIO-GPU control queue zero-state and split-ring layout contract.
//! VirtIO 1.2 §§2.7 and 4.1.4.3. Never allocates or enables a real virtqueue.
pub const NUM_QUEUES:u64 = 0x12;
pub const QUEUE_NOTIFY_OFF:u64 = 0x1e;
pub const QUEUE_DESC:u64 = 0x20;
pub const QUEUE_DRIVER:u64 = 0x28;
pub const QUEUE_DEVICE:u64 = 0x30;
pub const PAGE_BYTES:u64 = 4096;
pub const MAX_SELECTED:u16 = 256;
pub const MAX_ADVERTISED:u16 = 32768;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Snapshot {
    pub num_queues:u16,
    pub queue_select:u16,
    pub queue_size:u16,
    pub queue_enable:u16,
    pub queue_notify_off:u16,
    pub desc:u64,
    pub driver:u64,
    pub device:u64,
    pub status:u8,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Layout {
    pub selected:u16,
    pub desc_bytes:u64,
    pub avail_bytes:u64,
    pub used_bytes:u64,
    pub desc_pages:u64,
    pub avail_pages:u64,
    pub used_pages:u64,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Error { MissingControlOrCursor, WrongSelection, NotPowerOfTwo,
    QueueEnabled, AddressesAlreadySet, DeviceActive, Arithmetic, Unaligned,
    AddressOverlaps, NullAddress }
fn pages(n:u64)->Option<u64> {
    n.checked_add(PAGE_BYTES-1).map(|x|x/PAGE_BYTES)
}
pub fn layout(advertised:u16)->Result<Layout,Error>{
    if advertised < 2 || advertised > MAX_ADVERTISED || !advertised.is_power_of_two() {
        return Err(Error::NotPowerOfTwo);
    }
    let selected=advertised.min(MAX_SELECTED);
    let n=u64::from(selected);
    let desc_bytes=16u64.checked_mul(n).ok_or(Error::Arithmetic)?;
    // EVENT_IDX not negotiated in #310: split queue exact core sizes.
    let avail_bytes=6u64.checked_add(2*n).ok_or(Error::Arithmetic)?;
    let used_bytes=6u64.checked_add(8*n).ok_or(Error::Arithmetic)?;
    Ok(Layout {
        selected,desc_bytes,avail_bytes,used_bytes,
        desc_pages:pages(desc_bytes).ok_or(Error::Arithmetic)?,
        avail_pages:pages(avail_bytes).ok_or(Error::Arithmetic)?,
        used_pages:pages(used_bytes).ok_or(Error::Arithmetic)?,
    })
}
pub fn verify(s:Snapshot)->Result<Layout,Error>{
    if s.num_queues < 2 {return Err(Error::MissingControlOrCursor);}
    if s.queue_select != 0 {return Err(Error::WrongSelection);}
    let proposed=layout(s.queue_size)?;
    if s.status != 0 {return Err(Error::DeviceActive);}
    if s.queue_enable != 0 {return Err(Error::QueueEnabled);}
    if s.desc != 0 || s.driver != 0 || s.device != 0 {
        return Err(Error::AddressesAlreadySet);
    }
    Ok(proposed)
}
fn separate(a:u64,alen:u64,b:u64,blen:u64)->bool {
    let Some(aend)=a.checked_add(alen) else {return false;};
    let Some(bend)=b.checked_add(blen) else {return false;};
    aend<=b || bend<=a
}
pub fn validate_future_regions(l:Layout,desc:u64,avail:u64,used:u64)->Result<(),Error>{
    if desc==0 || avail==0 || used==0 {return Err(Error::NullAddress);}
    if [desc,avail,used].iter().any(|a| *a%PAGE_BYTES!=0) {
        return Err(Error::Unaligned);
    }
    let db=l.desc_pages.checked_mul(PAGE_BYTES).ok_or(Error::Arithmetic)?;
    let ab=l.avail_pages.checked_mul(PAGE_BYTES).ok_or(Error::Arithmetic)?;
    let ub=l.used_pages.checked_mul(PAGE_BYTES).ok_or(Error::Arithmetic)?;
    if !separate(desc,db,avail,ab) || !separate(desc,db,used,ub)
        || !separate(avail,ab,used,ub) {return Err(Error::AddressOverlaps);}
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn example()->Snapshot {
        Snapshot {num_queues:2,queue_select:0,queue_size:256,queue_enable:0,
          queue_notify_off:1,desc:0,driver:0,device:0,status:0}
    }
    #[test] fn virtio_split_256_bytes() {
        let l=verify(example()).unwrap();
        assert_eq!((l.selected,l.desc_bytes,l.avail_bytes,l.used_bytes),(256,4096,518,2054));
        assert_eq!((l.desc_pages,l.avail_pages,l.used_pages),(1,1,1));
    }
    #[test] fn cap_large_offered_queue() {
        let l=layout(32768).unwrap();assert_eq!(l.selected,256);
    }
    #[test] fn minimal_two_entry_split() {
        let l=layout(2).unwrap();
        assert_eq!((l.desc_bytes,l.avail_bytes,l.used_bytes),(32,10,22));
    }
    #[test] fn refuses_unavailable_and_nonpower() {
        for n in [0,1,3,255,32767] {assert_eq!(layout(n),Err(Error::NotPowerOfTwo));}
    }
    #[test] fn requires_control_and_cursor() {
        let mut s=example();s.num_queues=1;
        assert_eq!(verify(s),Err(Error::MissingControlOrCursor));
    }
    #[test] fn requires_unclaimed_controlq() {
        let mut s=example();s.queue_select=1;
        assert_eq!(verify(s),Err(Error::WrongSelection));
    }
    #[test] fn refuses_enabled_queue() {
        let mut s=example();s.queue_enable=1;
        assert_eq!(verify(s),Err(Error::QueueEnabled));
    }
    #[test] fn refuses_existing_descriptor() {
        let mut s=example();s.desc=4096;
        assert_eq!(verify(s),Err(Error::AddressesAlreadySet));
    }
    #[test] fn refuses_existing_driver_and_device_addresses() {
        let mut s=example();s.driver=8192;
        assert_eq!(verify(s),Err(Error::AddressesAlreadySet));
        let mut s=example();s.device=12288;
        assert_eq!(verify(s),Err(Error::AddressesAlreadySet));
    }
    #[test] fn refuses_started_device() {
        let mut s=example();s.status=1;
        assert_eq!(verify(s),Err(Error::DeviceActive));
    }
    #[test] fn safe_future_three_physical_regions() {
        assert_eq!(validate_future_regions(layout(256).unwrap(),
                         0x1000,0x2000,0x3000),Ok(()));
    }
    #[test] fn refuses_overlapping_future_regions() {
        assert_eq!(validate_future_regions(layout(256).unwrap(),
                   0x1000,0x1000,0x3000),Err(Error::AddressOverlaps));
    }
    #[test] fn refuses_nonpage_aligned_or_null_region() {
        let l=layout(256).unwrap();
        assert_eq!(validate_future_regions(l,0x1001,0x2000,0x3000),Err(Error::Unaligned));
        assert_eq!(validate_future_regions(l,0,0x2000,0x3000),Err(Error::NullAddress));
    }
    #[test] fn overflow_physical_address_is_rejected() {
        let l=layout(256).unwrap();
        assert_eq!(validate_future_regions(l,u64::MAX&!4095,0x2000,0x3000),
                   Err(Error::AddressOverlaps));
    }
    #[test] fn offsets_match_common_cfg_layout(){
        assert_eq!((NUM_QUEUES,QUEUE_NOTIFY_OFF,QUEUE_DESC,QUEUE_DRIVER,QUEUE_DEVICE),
                   (18,30,32,40,48));
    }
}
