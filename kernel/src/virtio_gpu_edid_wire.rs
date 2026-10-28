//! VirtIO-GPU GET_EDID wire contract (no PCI, DMA or virtqueue I/O here).
//! This module can only decode bytes supplied by a real, negotiated driver.
//! QEMU Bochs VGA does not expose a refresh clock; no guessed modes or writes.

use crate::display_edid_cta::{self, ConnectorModes, FullEdidError};
use crate::display_mode_policy::{self, DisplayMode, ModeError, PipelineLimits, UserChoice};

pub const VIRTIO_GPU_F_EDID: u64 = 1 << 1;
pub const VIRTIO_GPU_CMD_GET_EDID: u32 = 0x010a;
pub const VIRTIO_GPU_RESP_OK_EDID: u32 = 0x1104;
pub const VIRTIO_GPU_FLAG_FENCE: u32 = 1;
pub const VIRTIO_GPU_EVENT_DISPLAY: u32 = 1;
pub const MAX_SCANOUTS: u32 = 16;
pub const REQUEST_LEN: usize = 32;
pub const RESPONSE_LEN: usize = 24 + 8 + 1024;
pub const EDID_OFFSET: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioEdidError {
    EdidFeatureNotNegotiated,
    InvalidScanout,
    InvalidGeneration,
    InvalidFence,
    WrongResponseLength,
    WrongResponseType,
    WrongResponseHeader,
    WrongFence,
    InvalidEdidSize,
    StaleConnector,
    GenerationOverflow,
    ParsedEdid(FullEdidError),
    UnsupportedSelection(ModeError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GetEdidRequest {
    pub scanout: u32,
    pub generation: u64,
    pub fence: u64,
    pub bytes: [u8; REQUEST_LEN],
}

/// Device negotiation and num_scanouts MUST come from an independently
/// authenticated VirtIO driver state, never from an untrusted EDID blob.
/// Emits a 32-byte little-endian VirtIO-GPU control-queue request with a
/// nonzero fence to bind completion to this exact request.
pub fn encode_get_edid(
    negotiated_features: u64,
    num_scanouts: u32,
    scanout: u32,
    generation: u64,
    fence: u64,
) -> Result<GetEdidRequest, VirtioEdidError> {
    if negotiated_features & VIRTIO_GPU_F_EDID == 0 {
        return Err(VirtioEdidError::EdidFeatureNotNegotiated);
    }
    if num_scanouts == 0 || num_scanouts > MAX_SCANOUTS || scanout >= num_scanouts {
        return Err(VirtioEdidError::InvalidScanout);
    }
    if generation == 0 { return Err(VirtioEdidError::InvalidGeneration); }
    if fence == 0 { return Err(VirtioEdidError::InvalidFence); }
    let mut bytes = [0u8; REQUEST_LEN];
    bytes[0..4].copy_from_slice(&VIRTIO_GPU_CMD_GET_EDID.to_le_bytes());
    bytes[4..8].copy_from_slice(&VIRTIO_GPU_FLAG_FENCE.to_le_bytes());
    bytes[8..16].copy_from_slice(&fence.to_le_bytes());
    bytes[24..28].copy_from_slice(&scanout.to_le_bytes());
    Ok(GetEdidRequest { scanout, generation, fence, bytes })
}

fn u32le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at],bytes[at+1],bytes[at+2],bytes[at+3]])
}
fn u64le(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        bytes[at],bytes[at+1],bytes[at+2],bytes[at+3],
        bytes[at+4],bytes[at+5],bytes[at+6],bytes[at+7],
    ])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedScanout {
    pub scanout: u32,
    pub generation: u64,
    modes: ConnectorModes,
}
impl VerifiedScanout {
    pub fn modes(&self) -> &[DisplayMode] { self.modes.modes() }

    /// Re-check generation immediately before using this list. Downstream
    /// modeset code must still validate GPU link limits and real register
    /// readback, and must apply its own 15-second rollback on user changes.
    pub fn choose(
        &self,
        current_generation: u64,
        pipeline: PipelineLimits,
        choice: UserChoice,
    ) -> Result<DisplayMode, VirtioEdidError> {
        if current_generation != self.generation {
            return Err(VirtioEdidError::StaleConnector);
        }
        display_mode_policy::choose(self.modes(), pipeline, choice)
            .map_err(VirtioEdidError::UnsupportedSelection)
    }
}

/// Accept only a full VirtIO-GPU OK_EDID response, including an echo of our
/// requested fence; no stale or cross-scanout completion is accepted.
/// The driver must supply the actual virtqueue *used length* and freshly
/// initialized DMA buffer, not the advertised buffer capacity alone.
pub fn decode_get_edid(
    request: GetEdidRequest,
    current_generation: u64,
    response: &[u8],
) -> Result<VerifiedScanout, VirtioEdidError> {
    if current_generation == 0 || current_generation != request.generation {
        return Err(VirtioEdidError::StaleConnector);
    }
    if response.len() != RESPONSE_LEN {
        return Err(VirtioEdidError::WrongResponseLength);
    }
    if u32le(response, 0) != VIRTIO_GPU_RESP_OK_EDID {
        return Err(VirtioEdidError::WrongResponseType);
    }
    if u32le(response, 4) != VIRTIO_GPU_FLAG_FENCE
        || u32le(response, 16) != 0
        || response[20..24].iter().any(|b| *b != 0)
        || u32le(response, 28) != 0
    {
        return Err(VirtioEdidError::WrongResponseHeader);
    }
    if u64le(response, 8) != request.fence {
        return Err(VirtioEdidError::WrongFence);
    }
    let edid_size = u32le(response, 24) as usize;
    if edid_size < 128 || edid_size > 1024 || edid_size % 128 != 0 {
        return Err(VirtioEdidError::InvalidEdidSize);
    }
    let edid = &response[EDID_OFFSET..EDID_OFFSET + edid_size];
    let modes = display_edid_cta::parse_complete(edid)
        .map_err(VirtioEdidError::ParsedEdid)?;
    Ok(VerifiedScanout {
        scanout: request.scanout,
        generation: request.generation,
        modes,
    })
}

/// When a VirtIO-GPU DISPLAY event arrives, bump the scanout generation.
/// Every previously issued GET_EDID response and manual mode confirmation
/// from that connector becomes stale. The real driver must re-query
/// GET_DISPLAY_INFO + GET_EDID on the control queue.
pub fn generation_after_event(
    current_generation: u64,
    events_read: u32,
) -> Result<u64, VirtioEdidError> {
    if current_generation == 0 {
        return Err(VirtioEdidError::InvalidGeneration);
    }
    if events_read & VIRTIO_GPU_EVENT_DISPLAY == 0 {
        return Ok(current_generation);
    }
    current_generation.checked_add(1)
        .ok_or(VirtioEdidError::GenerationOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display_mode_policy::{ResolutionChoice,RefreshChoice};

    fn checksum(bytes: &mut [u8]) {
        bytes[127]=0;
        let sum = bytes.iter().fold(0u8,|s,b|s.wrapping_add(*b));
        bytes[127]=0u8.wrapping_sub(sum);
    }
    fn base() -> [u8;128] {
        let mut b=[0u8;128];b[..8].copy_from_slice(&[0,255,255,255,255,255,255,0]);
        b[18]=1;b[19]=4;b[24]=2;
        b[54..62].copy_from_slice(&[2,58,128,24,113,56,45,64]);
        checksum(&mut b);b
    }
    fn cta() -> [u8;128] {
        let mut c=[0u8;128];c[0]=2;c[1]=3;c[2]=7;
        c[4]=0x42;c[5]=16;c[6]=97;checksum(&mut c);c
    }
    fn request() -> GetEdidRequest {
        encode_get_edid(VIRTIO_GPU_F_EDID,2,1,9,0x1122334455667788).unwrap()
    }
    fn response(edid: &[u8]) -> [u8;RESPONSE_LEN] {
        let mut r=[0u8;RESPONSE_LEN];
        r[..4].copy_from_slice(&VIRTIO_GPU_RESP_OK_EDID.to_le_bytes());
        r[4..8].copy_from_slice(&VIRTIO_GPU_FLAG_FENCE.to_le_bytes());
        r[8..16].copy_from_slice(&request().fence.to_le_bytes());
        r[24..28].copy_from_slice(&(edid.len() as u32).to_le_bytes());
        r[EDID_OFFSET..EDID_OFFSET+edid.len()].copy_from_slice(edid);
        r
    }
    fn gpu() -> PipelineLimits {
        PipelineLimits {
            max_width:3840,max_height:2160,
            max_pixel_clock_khz:600_000,max_refresh_millihz:144_000,
            supports_interlaced:false,
        }
    }
    #[test]
    fn request_has_spec_exact_32_byte_le_layout() {
        let r=request();assert_eq!(r.bytes.len(),32);
        assert_eq!(u32le(&r.bytes,0),0x010a);
        assert_eq!(u32le(&r.bytes,4),1);
        assert_eq!(u64le(&r.bytes,8),0x1122334455667788);
        assert_eq!(u32le(&r.bytes,16),0);
        assert_eq!(u32le(&r.bytes,24),1);
        assert_eq!(u32le(&r.bytes,28),0);
        assert!(r.bytes[20..24].iter().all(|b|*b==0));
    }
    #[test]
    fn feature_must_be_negotiated_not_just_advertised() {
        assert_eq!(encode_get_edid(0,1,0,1,1),Err(VirtioEdidError::EdidFeatureNotNegotiated));
        assert!(encode_get_edid(2,1,0,1,1).is_ok());
    }
    #[test]
    fn scanout_id_and_count_must_fit_device_limit() {
        for (count,scanout) in [(0,0),(17,0),(1,1),(2,16)] {
            assert_eq!(encode_get_edid(2,count,scanout,1,1),Err(VirtioEdidError::InvalidScanout));
        }
        assert!(encode_get_edid(2,16,15,1,1).is_ok());
    }
    #[test]
    fn generation_and_fence_must_be_nonzero() {
        assert_eq!(encode_get_edid(2,1,0,0,1),Err(VirtioEdidError::InvalidGeneration));
        assert_eq!(encode_get_edid(2,1,0,1,0),Err(VirtioEdidError::InvalidFence));
    }
    #[test]
    fn valid_base_response_chooses_firmware_advertised_1080p60_only() {
        let trusted=decode_get_edid(request(),9,&response(&base())).unwrap();
        assert_eq!((trusted.scanout,trusted.generation,trusted.modes().len()),(1,9,1));
        assert_eq!(trusted.choose(9,gpu(),UserChoice::AUTOMATIC).unwrap().refresh_millihz,60_000);
        assert_eq!(trusted.choose(9,gpu(),UserChoice{
            resolution: ResolutionChoice::Automatic,refresh:RefreshChoice::ExactMilliHz(165_000),
        }),Err(VirtioEdidError::UnsupportedSelection(ModeError::UnsupportedSelection)));
    }
    #[test]
    fn full_cta_edid_response_selects_4k60() {
        let mut b=base();b[126]=1;checksum(&mut b);
        let mut edid=[0u8;256];edid[..128].copy_from_slice(&b);
        edid[128..].copy_from_slice(&cta());
        let verified=decode_get_edid(request(),9,&response(&edid)).unwrap();
        assert_eq!(verified.modes().len(),2);
        assert_eq!(verified.choose(9,gpu(),UserChoice{
            resolution: ResolutionChoice::Exact{width:3840,height:2160},
            refresh:RefreshChoice::ExactMilliHz(60_000),
        }).unwrap().pixel_clock_khz,594_000);
    }
    #[test]
    fn hotplug_invalidates_old_response_before_parsing() {
        let generation=generation_after_event(9,VIRTIO_GPU_EVENT_DISPLAY).unwrap();
        assert_eq!(generation,10);
        assert_eq!(decode_get_edid(request(),generation,&response(&base())),
                   Err(VirtioEdidError::StaleConnector));
    }
    #[test]
    fn hotplug_invalidates_previous_manual_options() {
        let trusted=decode_get_edid(request(),9,&response(&base())).unwrap();
        assert_eq!(trusted.choose(10,gpu(),UserChoice::AUTOMATIC),
                   Err(VirtioEdidError::StaleConnector));
    }
    #[test]
    fn unrelated_virtio_event_does_not_invalidate_modes() {
        assert_eq!(generation_after_event(9,2),Ok(9));
        assert_eq!(generation_after_event(9,0),Ok(9));
        assert_eq!(generation_after_event(9,3),Ok(10));
    }
    #[test]
    fn generation_overflow_fails_closed() {
        assert_eq!(generation_after_event(0,1),Err(VirtioEdidError::InvalidGeneration));
        assert_eq!(generation_after_event(u64::MAX,1),Err(VirtioEdidError::GenerationOverflow));
    }
    #[test]
    fn short_dma_completion_is_not_padded_into_a_fake_success() {
        assert_eq!(decode_get_edid(request(),9,&response(&base())[..1055]),
                   Err(VirtioEdidError::WrongResponseLength));
        assert_eq!(decode_get_edid(request(),9,&response(&base())[..32]),
                   Err(VirtioEdidError::WrongResponseLength));
    }
    #[test]
    fn reject_wrong_response_kind_even_if_edid_is_valid() {
        let mut r=response(&base());r[..4].copy_from_slice(&0x1100u32.to_le_bytes());
        assert_eq!(decode_get_edid(request(),9,&r),
                   Err(VirtioEdidError::WrongResponseType));
    }
    #[test]
    fn reject_wrong_response_fence_even_with_valid_edid() {
        let mut r=response(&base());r[8]^=1;
        assert_eq!(decode_get_edid(request(),9,&r),Err(VirtioEdidError::WrongFence));
    }
    #[test]
    fn reject_unfenced_or_unexpected_response_flags() {
        let mut r=response(&base());r[4..8].fill(0);
        assert_eq!(decode_get_edid(request(),9,&r),
                   Err(VirtioEdidError::WrongResponseHeader));
        r[4]=3;
        assert_eq!(decode_get_edid(request(),9,&r),
                   Err(VirtioEdidError::WrongResponseHeader));
    }
    #[test]
    fn reject_response_ctx_ring_and_reserved_nonzero_bytes() {
        let mut r=response(&base());r[16]=1;
        assert_eq!(decode_get_edid(request(),9,&r),
                   Err(VirtioEdidError::WrongResponseHeader));
        let mut r=response(&base());r[20]=1;
        assert_eq!(decode_get_edid(request(),9,&r),
                   Err(VirtioEdidError::WrongResponseHeader));
        let mut r=response(&base());r[28]=1;
        assert_eq!(decode_get_edid(request(),9,&r),
                   Err(VirtioEdidError::WrongResponseHeader));
    }
    #[test]
    fn reject_absent_misaligned_and_oversized_edid() {
        for len in [0u32,127,129,257,1025,u32::MAX] {
            let mut r=response(&base());r[24..28].copy_from_slice(&len.to_le_bytes());
            assert_eq!(decode_get_edid(request(),9,&r),
                       Err(VirtioEdidError::InvalidEdidSize));
        }
    }
    #[test]
    fn reject_checksum_corruption_from_gpu_reply() {
        let mut b=base();b[54]^=1;
        assert_eq!(decode_get_edid(request(),9,&response(&b)),
                   Err(VirtioEdidError::ParsedEdid(
                       FullEdidError::Base(crate::display_edid_base::EdidError::InvalidChecksum)
                   )));
    }
    #[test]
    fn reject_claimed_extensions_not_supplied_in_virtio_edid_size() {
        let mut b=base();b[126]=1;checksum(&mut b);
        assert_eq!(decode_get_edid(request(),9,&response(&b)),
                   Err(VirtioEdidError::ParsedEdid(FullEdidError::WrongLength)));
    }
    #[test]
    fn reject_displayid_extension_not_silently_ignored() {
        let mut b=base();b[126]=1;checksum(&mut b);
        let mut ext=cta();ext[0]=0x70;checksum(&mut ext);
        let mut edid=[0u8;256];
        edid[..128].copy_from_slice(&b);edid[128..].copy_from_slice(&ext);
        assert_eq!(decode_get_edid(request(),9,&response(&edid)),
                   Err(VirtioEdidError::ParsedEdid(FullEdidError::UnsupportedExtension)));
    }
    #[test]
    fn device_may_fail_without_ever_advertising_edid_modes() {
        let r=[0u8;RESPONSE_LEN];
        assert_eq!(decode_get_edid(request(),9,&r),Err(VirtioEdidError::WrongResponseType));
    }
}
