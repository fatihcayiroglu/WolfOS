//! Pure, no-I/O proof that Limine's writable RGB framebuffer corresponds to
//! the *enabled* Bochs VBE scanout observed from QEMU PCI stdvga 1234:1111.
//! Attestation is deliberately strict and is NOT a GPU driver or mode setter.

use crate::qemu_dispi_contract::DispiObservation;

/// May be called only after a trusted Limine framebuffer response and exact
/// read-only QEMU Bochs VBE device observation. Does not dereference memory.
pub fn matches_scanout(
    dispi: DispiObservation, width: u64, height: u64, pitch: u64, bpp: u16,
) -> bool {
    if !dispi.valid() || dispi.enable & 1 == 0 || dispi.bpp != 32 || bpp != 32 {
        return false;
    }
    if width == 0 || height == 0
        || width != u64::from(dispi.xres) || height != u64::from(dispi.yres)
    {
        return false;
    }
    let Some(row_bytes) = width.checked_mul(4) else { return false };
    if pitch < row_bytes || pitch % 4 != 0 { return false; }
    let Some(bytes) = pitch.checked_mul(height) else { return false };
    bytes <= u64::from(dispi.vram64k) * 65536
        && bytes <= isize::MAX as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    const OBS: DispiObservation = DispiObservation {
        selector_before: 10, selector_after: 10,
        id: 0xb0c5, xres: 1280, yres: 800, bpp: 32,
        enable: 65, vram64k: 256,
    };
    #[test]
    fn qemu_1280x800_matches() {
        assert!(matches_scanout(OBS, 1280, 800, 5120, 32));
    }
    #[test]
    fn width_must_match_device() {
        assert!(!matches_scanout(OBS, 1024, 800, 5120, 32));
        assert!(!matches_scanout(OBS, 1281, 800, 5124, 32));
    }
    #[test]
    fn height_must_match_device() {
        assert!(!matches_scanout(OBS, 1280, 768, 5120, 32));
        assert!(!matches_scanout(OBS, 1280, 801, 5120, 32));
    }
    #[test]
    fn unknown_or_disabled_hardware_is_not_attested() {
        assert!(!matches_scanout(DispiObservation { enable: 0, ..OBS }, 1280, 800, 5120, 32));
        assert!(!matches_scanout(DispiObservation { id: 0, ..OBS }, 1280, 800, 5120, 32));
    }
    #[test]
    fn unsupported_bit_depth_is_refused() {
        assert!(!matches_scanout(OBS, 1280, 800, 5120, 24));
        assert!(!matches_scanout(DispiObservation { bpp: 24, ..OBS }, 1280, 800, 5120, 32));
    }
    #[test]
    fn packed_stride_bounds_are_enforced() {
        assert!(!matches_scanout(OBS, 1280, 800, 5116, 32));
        assert!(!matches_scanout(OBS, 1280, 800, 5121, 32));
        assert!(matches_scanout(OBS, 1280, 800, 5184, 32));
    }
    #[test]
    fn stride_must_fit_hardware_video_ram() {
        assert!(!matches_scanout(OBS, 1280, 800, 25000, 32));
        assert!(!matches_scanout(DispiObservation { vram64k: 1, ..OBS }, 1280, 800, 5120, 32));
    }
    #[test]
    fn massive_or_empty_framebuffer_is_refused() {
        for dims in [(0,800,5120), (1280,0,5120), (1280,800,u64::MAX)] {
            assert!(!matches_scanout(OBS, dims.0, dims.1, dims.2, 32));
        }
    }
    #[test]
    fn index_restoration_is_essential() {
        assert!(!matches_scanout(DispiObservation { selector_after: 1, ..OBS }, 1280,800,5120,32));
    }
    #[test]
    fn scanout_does_not_depend_on_enable_unrelated_bits() {
        assert!(matches_scanout(DispiObservation { enable: 1, ..OBS }, 1280,800,5120,32));
        assert!(matches_scanout(DispiObservation { enable: 0x41, ..OBS }, 1280,800,5120,32));
    }
}
