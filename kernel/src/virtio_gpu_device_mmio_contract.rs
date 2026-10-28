//! VirtIO 1.2 §5.7.4 GPU-specific device-config read-only semantics.
//! Never access the events_clear W1C field; no queue or command transport.

pub const EVENTS_READ:u64=0;
pub const NUM_SCANOUTS:u64=8;
pub const NUM_CAPSETS:u64=12;
pub const MIN_DEVICE_BYTES:u32=16;

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum DeviceError {
    ReservedEventBit,
    BadScanoutCount,
}

pub fn validate(events_read:u32, scanouts:u32, _capsets:u32)->Result<(),DeviceError> {
    // VIRTIO_GPU_EVENT_DISPLAY is the only event defined in v1.2.
    if events_read & !1 != 0 {return Err(DeviceError::ReservedEventBit);}
    if !(1..=16).contains(&scanouts) {return Err(DeviceError::BadScanoutCount);}
    // The spec does not assign an upper bound to num_capsets; reading it
    // is harmless because this diagnostic never allocates or negotiates.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accepts_virtio_spec_minimum_and_maximum_scanouts() {
        assert_eq!(validate(0,1,0),Ok(()));
        assert_eq!(validate(1,16,1),Ok(()));
    }
    #[test]
    fn rejects_zero_scanouts() {
        assert_eq!(validate(0,0,0),Err(DeviceError::BadScanoutCount));
    }
    #[test]
    fn rejects_more_than_sixteen_scanouts() {
        assert_eq!(validate(0,17,0),Err(DeviceError::BadScanoutCount));
    }
    #[test]
    fn rejects_reserved_event_bits() {
        assert_eq!(validate(2,1,0),Err(DeviceError::ReservedEventBit));
        assert_eq!(validate(0x8000_0000,1,0),Err(DeviceError::ReservedEventBit));
    }
    #[test]
    fn does_not_arbitrarily_limit_capset_count_for_readonly_proof() {
        assert_eq!(validate(0,2,u32::MAX),Ok(()));
    }
    #[test]
    fn offsets_exactly_match_virtio_gpu_config() {
        assert_eq!((EVENTS_READ,NUM_SCANOUTS,NUM_CAPSETS,MIN_DEVICE_BYTES),
                   (0,8,12,16));
    }
}
