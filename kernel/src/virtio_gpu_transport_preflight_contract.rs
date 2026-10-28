//! QEMU-only VirtIO PCI common configuration read-only transport preflight.
//! Spec: VirtIO 1.2 section 4.1.4.3, GPU feature bit EDID=1.
//! No feature selector writes, driver status writes or queue provisioning.

pub const FEATURE_SELECTOR_OFFSET:u64=0;
pub const DEVICE_FEATURE_OFFSET:u64=4;
pub const DEVICE_STATUS_OFFSET:u64=0x14;
pub const QUEUE_SELECTOR_OFFSET:u64=0x16;
pub const QUEUE_SIZE_OFFSET:u64=0x18;
pub const QUEUE_ENABLE_OFFSET:u64=0x1c;
pub const GPU_FEATURE_EDID:u32=1<<1;
pub const MAX_SPLIT_QUEUE_SIZE:u16=32768;

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Snapshot {
    pub feature_selector:u32,
    pub feature_word:u32,
    pub status:u8,
    pub queue_selector:u16,
    pub queue_size:u16,
    pub queue_enabled:u16,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Preflight {
    pub queue_size:u16,
    pub feature_word:u32,
    pub edid:bool,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum PreflightError {
    FeatureBankNotZero, QueueNotZero, BadQueueSize,
    AlreadyEnabled, DeviceAlreadyStarted,
}
pub fn validate(s:Snapshot)->Result<Preflight,PreflightError> {
    // No selector write is permitted: only bank zero yields the EDID bit.
    if s.feature_selector != 0 {return Err(PreflightError::FeatureBankNotZero);}
    if s.queue_selector != 0 {return Err(PreflightError::QueueNotZero);}
    if s.queue_size == 0 || s.queue_size > MAX_SPLIT_QUEUE_SIZE {
        return Err(PreflightError::BadQueueSize);
    }
    if s.queue_enabled != 0 {return Err(PreflightError::AlreadyEnabled);}
    // The QEMU smoke expects an unclaimed VirtIO device, never a
    // pre-existing firmware/OS GPU transport. Fail closed if active.
    if s.status != 0 {return Err(PreflightError::DeviceAlreadyStarted);}
    Ok(Preflight {
        queue_size:s.queue_size,
        feature_word:s.feature_word,
        edid:(s.feature_word & GPU_FEATURE_EDID) != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn example()->Snapshot {
        Snapshot{feature_selector:0,feature_word:0b10,status:0,
                 queue_selector:0,queue_size:256,queue_enabled:0}
    }
    #[test]
    fn accepts_realistic_unclaimed_queue_zero() {
        assert_eq!(validate(example()),Ok(Preflight{
            queue_size:256,feature_word:2,edid:true
        }));
    }
    #[test]
    fn edid_is_optional_and_never_faked() {
        let mut s=example(); s.feature_word=0;
        assert_eq!(validate(s).unwrap().edid,false);
    }
    #[test]
    fn refuses_unknown_selected_feature_bank() {
        let mut s=example();s.feature_selector=1;
        assert_eq!(validate(s),Err(PreflightError::FeatureBankNotZero));
    }
    #[test]
    fn refuses_nonzero_selected_queue_without_writing_selector() {
        let mut s=example();s.queue_selector=1;
        assert_eq!(validate(s),Err(PreflightError::QueueNotZero));
    }
    #[test]
    fn rejects_zero_or_oversized_queue_capacity() {
        let mut s=example();s.queue_size=0;
        assert_eq!(validate(s),Err(PreflightError::BadQueueSize));
        s.queue_size=32769;
        assert_eq!(validate(s),Err(PreflightError::BadQueueSize));
    }
    #[test]
    fn permits_exact_maximum_queue_capacity() {
        let mut s=example();s.queue_size=MAX_SPLIT_QUEUE_SIZE;
        assert!(validate(s).is_ok());
    }
    #[test]
    fn rejects_already_active_queue() {
        let mut s=example();s.queue_enabled=1;
        assert_eq!(validate(s),Err(PreflightError::AlreadyEnabled));
    }
    #[test]
    fn rejects_any_previously_negotiated_device_state() {
        let mut s=example();s.status=1;
        assert_eq!(validate(s),Err(PreflightError::DeviceAlreadyStarted));
    }
    #[test]
    fn field_offsets_and_feature_number_match_virtio_12() {
        assert_eq!((FEATURE_SELECTOR_OFFSET,DEVICE_FEATURE_OFFSET,
                    DEVICE_STATUS_OFFSET,QUEUE_SELECTOR_OFFSET,
                    QUEUE_SIZE_OFFSET,QUEUE_ENABLE_OFFSET,GPU_FEATURE_EDID),
                   (0,4,20,22,24,28,2));
    }
}
