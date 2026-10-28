//! Pure VirtIO-GPU 2D resource create/unref wire and completion contract.
//! QEMU-only 64x64 probe: no backing attachment, set-scanout or mode writes.
//! All commands are bounded and require a real used-ring completion/fence.

pub const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const CMD_RESOURCE_UNREF: u32 = 0x0102;
pub const RESP_OK_NODATA: u32 = 0x1100;
pub const FORMAT_B8G8R8X8_UNORM: u32 = 2;
pub const CREATE_BYTES: usize = 40;
pub const UNREF_BYTES: usize = 32;
pub const RESPONSE_BYTES: usize = 24;
pub const MAX_PROBE_SIDE: u32 = 64;
pub const RESOURCE_ID: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidResource,
    InvalidDimensions,
    InvalidFence,
    InvalidQueueSize,
    UnrefBeforeCreateAck,
    MissingCompletion,
    WrongHead,
    WrongLength,
    WrongResponseType,
    WrongResponseHeader,
    WrongFence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub bytes: [u8; CREATE_BYTES],
    pub len: usize,
    pub fence: u64,
}

fn header(command: u32, fence: u64) -> Result<[u8; CREATE_BYTES], Error> {
    if fence == 0 { return Err(Error::InvalidFence); }
    let mut out = [0u8; CREATE_BYTES];
    out[0..4].copy_from_slice(&command.to_le_bytes());
    out[4..8].copy_from_slice(&1u32.to_le_bytes()); // VIRTIO_GPU_FLAG_FENCE
    out[8..16].copy_from_slice(&fence.to_le_bytes());
    Ok(out)
}

pub fn create(resource: u32, width: u32, height: u32, fence: u64)
    -> Result<Request, Error>
{
    if resource == 0 { return Err(Error::InvalidResource); }
    if !(1..=MAX_PROBE_SIDE).contains(&width)
        || !(1..=MAX_PROBE_SIDE).contains(&height)
    { return Err(Error::InvalidDimensions); }
    let mut bytes = header(CMD_RESOURCE_CREATE_2D, fence)?;
    bytes[24..28].copy_from_slice(&resource.to_le_bytes());
    bytes[28..32].copy_from_slice(&FORMAT_B8G8R8X8_UNORM.to_le_bytes());
    bytes[32..36].copy_from_slice(&width.to_le_bytes());
    bytes[36..40].copy_from_slice(&height.to_le_bytes());
    Ok(Request { bytes, len: CREATE_BYTES, fence })
}

pub fn unref(resource: u32, created_acknowledged: bool, fence: u64)
    -> Result<Request, Error>
{
    if !created_acknowledged { return Err(Error::UnrefBeforeCreateAck); }
    if resource == 0 { return Err(Error::InvalidResource); }
    let mut bytes = header(CMD_RESOURCE_UNREF, fence)?;
    bytes[24..28].copy_from_slice(&resource.to_le_bytes());
    Ok(Request { bytes, len: UNREF_BYTES, fence })
}

/// The resource lifecycle commands must use the correct split-ring slot even if
/// the device selected only two queue entries (wrap slots 0/1).
pub fn ring_slot(next_index: u16, selected: u16) -> Result<u16, Error> {
    if selected < 2 || selected > 256 || !selected.is_power_of_two() || next_index == 0 {
        return Err(Error::InvalidQueueSize);
    }
    Ok((next_index - 1) % selected)
}

fn u32le(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([data[at], data[at+1], data[at+2], data[at+3]])
}
fn u64le(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        data[at],data[at+1],data[at+2],data[at+3],
        data[at+4],data[at+5],data[at+6],data[at+7],
    ])
}

/// A sent request or plausible 24-byte DMA buffer is never completion.
/// Require exact used idx/head/len plus the echoed nonzero request fence.
pub fn validate_completion(
    expected_index: u16, used_index: u16, used_id: u32, used_len: u32,
    response: &[u8], expected_fence: u64,
) -> Result<(), Error> {
    if !(3..=7).contains(&expected_index) { return Err(Error::MissingCompletion); }
    if used_index != expected_index { return Err(Error::MissingCompletion); }
    if used_id != 0 { return Err(Error::WrongHead); }
    if used_len != RESPONSE_BYTES as u32 || response.len() != RESPONSE_BYTES {
        return Err(Error::WrongLength);
    }
    if u32le(response,0) != RESP_OK_NODATA { return Err(Error::WrongResponseType); }
    if u32le(response,4) != 1 || u32le(response,16) != 0
        || u32le(response,20) != 0
    { return Err(Error::WrongResponseHeader); }
    if expected_fence == 0 || u64le(response,8) != expected_fence {
        return Err(Error::WrongFence);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(fence: u64) -> [u8; RESPONSE_BYTES] {
        let mut r=[0u8; RESPONSE_BYTES];
        r[0..4].copy_from_slice(&RESP_OK_NODATA.to_le_bytes());
        r[4..8].copy_from_slice(&1u32.to_le_bytes());
        r[8..16].copy_from_slice(&fence.to_le_bytes());
        r
    }
    #[test]
    fn spec_create_2d_is_exact_40_bytes_no_scanout_or_backing() {
        let q=create(1,64,64,0x1122334455667788).unwrap();
        assert_eq!(q.len,40);
        assert_eq!(u32le(&q.bytes,0),0x0101);
        assert_eq!(u32le(&q.bytes,4),1);
        assert_eq!(u64le(&q.bytes,8),0x1122334455667788);
        assert_eq!(u32le(&q.bytes,16),0);
        assert_eq!(u32le(&q.bytes,20),0);
        assert_eq!(u32le(&q.bytes,24),1);
        assert_eq!(u32le(&q.bytes,28),2);
        assert_eq!(u32le(&q.bytes,32),64);
        assert_eq!(u32le(&q.bytes,36),64);
    }
    #[test]
    fn spec_unref_only_after_verified_create_ack() {
        assert_eq!(unref(1,false,2),Err(Error::UnrefBeforeCreateAck));
        let q=unref(1,true,0x8877665544332211).unwrap();
        assert_eq!(q.len,32);
        assert_eq!(u32le(&q.bytes,0),0x0102);
        assert_eq!(u32le(&q.bytes,24),1);
        assert_eq!(u32le(&q.bytes,28),0);
        assert_eq!(&q.bytes[32..],&[0u8;8]);
    }
    #[test]
    fn reject_invalid_resource_fence_or_large_probe() {
        assert_eq!(create(0,64,64,1),Err(Error::InvalidResource));
        assert_eq!(create(1,65,64,1),Err(Error::InvalidDimensions));
        assert_eq!(create(1,0,64,1),Err(Error::InvalidDimensions));
        assert_eq!(create(1,64,64,0),Err(Error::InvalidFence));
        assert_eq!(unref(0,true,1),Err(Error::InvalidResource));
        assert_eq!(unref(1,true,0),Err(Error::InvalidFence));
    }
    #[test]
    fn queue_slots_wrap_when_selected_is_two() {
        assert_eq!(ring_slot(3,2),Ok(0));
        assert_eq!(ring_slot(4,2),Ok(1));
        assert_eq!(ring_slot(3,256),Ok(2));
        assert_eq!(ring_slot(4,256),Ok(3));
        assert_eq!(ring_slot(3,0),Err(Error::InvalidQueueSize));
        assert_eq!(ring_slot(3,3),Err(Error::InvalidQueueSize));
        assert_eq!(ring_slot(3,512),Err(Error::InvalidQueueSize));
    }
    #[test]
    fn exact_real_completion_and_fence_required_for_both_commands() {
        let fence=0x123456789abcdef0;
        assert_eq!(validate_completion(3,3,0,24,&response(fence),fence),Ok(()));
        assert_eq!(validate_completion(4,4,0,24,&response(fence),fence),Ok(()));
        assert_eq!(validate_completion(5,5,0,24,&response(fence),fence),Ok(()));
        assert_eq!(validate_completion(6,6,0,24,&response(fence),fence),Ok(()));
        assert_eq!(validate_completion(7,7,0,24,&response(fence),fence),Ok(()));
        assert_eq!(validate_completion(8,8,0,24,&response(fence),fence),Err(Error::MissingCompletion));
        assert_eq!(validate_completion(3,2,0,24,&response(fence),fence),
                   Err(Error::MissingCompletion));
        assert_eq!(validate_completion(4,3,0,24,&response(fence),fence),
                   Err(Error::MissingCompletion));
        assert_eq!(validate_completion(3,3,1,24,&response(fence),fence),
                   Err(Error::WrongHead));
        assert_eq!(validate_completion(3,3,0,23,&response(fence),fence),
                   Err(Error::WrongLength));
        assert_eq!(validate_completion(3,3,0,24,&response(fence)[..23],fence),
                   Err(Error::WrongLength));
    }
    #[test]
    fn device_error_reserved_header_or_stale_fence_never_looks_successful() {
        let fence=0x123456789abcdef0;
        let mut r=response(fence);r[0]^=1; // 0x1100 -> 0x1101, actually corrupts type
        assert_eq!(validate_completion(3,3,0,24,&r,fence),Err(Error::WrongResponseType));
        let mut r=response(fence);r[4]=0;
        assert_eq!(validate_completion(3,3,0,24,&r,fence),Err(Error::WrongResponseHeader));
        let mut r=response(fence);r[16]=1;
        assert_eq!(validate_completion(3,3,0,24,&r,fence),Err(Error::WrongResponseHeader));
        let mut r=response(fence);r[8]^=1;
        assert_eq!(validate_completion(3,3,0,24,&r,fence),Err(Error::WrongFence));
    }
}
