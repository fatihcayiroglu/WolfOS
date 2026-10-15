//! Pure FXSAVE64 image preparation for synthetic kernel task bootstrap.
//!
//! A synthesized IRETQ frame may enable IF BEFORE the task's first instruction
//! executes. Its initial XMM0 must therefore already match the sentinel
//! expected by the interrupt-time switcher's FXSAVE64 verification.
//! This helper edits only XMM0's low 64 bits in an already valid 512-byte
//! FXSAVE64 image; it does NOT initialize an image or access the live FPU.

pub const IMAGE_BYTES: usize = 512;
pub const XMM0_OFFSET: usize = 160;

pub fn seed_xmm0(image: &mut [u8; IMAGE_BYTES], tag: u64) {
    image[XMM0_OFFSET..XMM0_OFFSET + 8].copy_from_slice(&tag.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_exactly_low_xmm0_lane_with_little_endian_tag() {
        let mut image = [0x9bu8; IMAGE_BYTES];
        let tag = 0x22ff_4400_bb66_7788u64;
        seed_xmm0(&mut image, tag);
        assert_eq!(&image[XMM0_OFFSET..XMM0_OFFSET + 8], &tag.to_le_bytes());
        assert!(image[..XMM0_OFFSET].iter().all(|byte| *byte == 0x9b));
        assert!(image[XMM0_OFFSET + 8..].iter().all(|byte| *byte == 0x9b));
    }

    #[test]
    fn independently_seeds_two_tasks_without_touching_mxcsr_or_upper_lanes() {
        let baseline = [0x43u8; IMAGE_BYTES];
        let mut a = baseline;
        let mut b = baseline;
        seed_xmm0(&mut a, 0x11ee_3300_aa55_6677);
        seed_xmm0(&mut b, 0x22ff_4400_bb66_7788);
        assert_ne!(&a[XMM0_OFFSET..XMM0_OFFSET + 8], &b[XMM0_OFFSET..XMM0_OFFSET + 8]);
        assert_eq!(&a[24..32], &baseline[24..32]); // MXCSR + MXCSR_MASK
        assert_eq!(&b[24..32], &baseline[24..32]);
        assert_eq!(&a[XMM0_OFFSET + 8..XMM0_OFFSET + 16],
            &baseline[XMM0_OFFSET + 8..XMM0_OFFSET + 16]);
        assert_eq!(&b[XMM0_OFFSET + 8..XMM0_OFFSET + 16],
            &baseline[XMM0_OFFSET + 8..XMM0_OFFSET + 16]);
    }
}
