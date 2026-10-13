//! Pure layout math for scalable physical-frame metadata.
//! Compiled both into the no_std kernel and as host-side Rust unit tests.

pub const PAGE_SIZE: usize = 4096;

/// Exactly one bit per managed 4-KiB frame, rounded up to a full byte.
pub const fn bitmap_bytes_for_frames(frames: usize) -> Option<usize> {
    if frames == 0 { return None; }
    match frames.checked_add(7) {
        Some(n) => Some(n / 8),
        None => None,
    }
}

/// Metadata occupies whole physical frames so the backing memory stays reserved.
pub const fn metadata_pages_for_frames(frames: usize) -> Option<usize> {
    let bytes = match bitmap_bytes_for_frames(frames) {
        Some(bytes) => bytes,
        None => return None,
    };
    match bytes.checked_add(PAGE_SIZE - 1) {
        Some(n) => Some(n / PAGE_SIZE),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const GIB: usize = 1024 * 1024 * 1024;

    #[test]
    fn bitmap_scales_to_terabytes_without_a_64_gib_cap() {
        for (gib, expected_mib) in [(64, 2), (128, 4), (256, 8), (1024, 32), (4096, 128)] {
            let frames = gib * GIB / PAGE_SIZE;
            assert_eq!(bitmap_bytes_for_frames(frames), Some(expected_mib * 1024 * 1024));
            assert_eq!(metadata_pages_for_frames(frames), Some(expected_mib * 256));
        }
    }

    #[test]
    fn handles_small_inputs_and_overflows() {
        assert_eq!(bitmap_bytes_for_frames(0), None);
        assert_eq!(metadata_pages_for_frames(0), None);
        assert_eq!(bitmap_bytes_for_frames(1), Some(1));
        assert_eq!(metadata_pages_for_frames(1), Some(1));
        assert_eq!(bitmap_bytes_for_frames(9), Some(2));
        assert_eq!(bitmap_bytes_for_frames(usize::MAX), None);
        assert_eq!(metadata_pages_for_frames(usize::MAX), None);
    }
}
