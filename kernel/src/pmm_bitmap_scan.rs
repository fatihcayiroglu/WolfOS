//! Pure, allocation-free first-free-frame bitmap scanner.
//!
//! Scan one 64-bit bitmap word at a time, including misaligned start/end
//! bounds and a short final word. This is *selection only*: the caller still
//! holds the exclusive allocator lock and marks the selected bit before
//! returning the physical frame. A clear bit does not establish PMM ownership.

/// Lowest clear bit in the half-open range `[start, end)`, if any.
///
/// Returns `None` on an empty/invalid range or an impossible bitmap capacity.
/// All tail bits outside `end` are masked, never returned as real frames.
pub fn first_clear_bit(bitmap: &[u8], start: usize, end: usize) -> Option<usize> {
    let capacity = bitmap.len().checked_mul(8)?;
    if start >= end || end > capacity {
        return None;
    }
    let mut at = start;
    while at < end {
        let word_base = at & !63usize;
        let byte_base = word_base / 8;
        // The last word can contain fewer than eight physical bitmap bytes.
        // Absent bytes are all used (0xff), never free phantom frames.
        let available = (bitmap.len() - byte_base).min(8);
        let mut bytes = [0xffu8; 8];
        bytes[..available].copy_from_slice(&bitmap[byte_base..byte_base + available]);
        let word = u64::from_le_bytes(bytes);
        let first = at - word_base; // 0..=63
        let beyond = (end - word_base).min(64); // 1..=64
        let allowed = (u64::MAX << first) & (u64::MAX >> (64 - beyond));
        let candidates = !word & allowed;
        if candidates != 0 {
            return Some(word_base + candidates.trailing_zeros() as usize);
        }
        // All of this word is allocated or masked. The checked advance
        // also handles a theoretical near-usize::MAX upper bound.
        at = word_base.checked_add(64).unwrap_or(end);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::first_clear_bit;

    fn clear(bitmap: &mut [u8], frame: usize) {
        bitmap[frame / 8] &= !(1 << (frame % 8));
    }

    #[test]
    fn rejects_empty_invalid_and_out_of_capacity_ranges() {
        assert_eq!(first_clear_bit(&[], 0, 0), None);
        assert_eq!(first_clear_bit(&[], 0, 1), None);
        let bitmap = [0u8; 2];
        for (start, end) in [(0, 0), (8, 8), (12, 11), (16, 17), (usize::MAX, usize::MAX)] {
            assert_eq!(first_clear_bit(&bitmap, start, end), None);
        }
    }

    #[test]
    fn honors_partial_byte_and_word_boundaries() {
        let mut bitmap = [0xffu8; 25];
        for frame in [4, 63, 64, 127, 128, 199] {
            clear(&mut bitmap, frame);
        }
        let before = bitmap;
        for (start, end, expected) in [
            (0, 4, None), (0, 5, Some(4)), (5, 64, Some(63)),
            (63, 64, Some(63)), (64, 65, Some(64)),
            (65, 128, Some(127)), (127, 128, Some(127)),
            (128, 129, Some(128)), (129, 199, None),
            (129, 200, Some(199)), (199, 200, Some(199)),
        ] {
            assert_eq!(first_clear_bit(&bitmap, start, end), expected);
        }
        assert_eq!(bitmap, before, "scanner must never modify PMM metadata");
    }

    #[test]
    fn final_short_word_never_leaks_nonexistent_frame_bits() {
        let mut bitmap = [0xffu8; 9]; // only 72 representable frame bits
        clear(&mut bitmap, 71);
        assert_eq!(first_clear_bit(&bitmap, 0, 71), None);
        assert_eq!(first_clear_bit(&bitmap, 64, 72), Some(71));
        assert_eq!(first_clear_bit(&bitmap, 72, 80), None);
        assert_eq!(first_clear_bit(&bitmap, 0, 73), None);
    }

    #[test]
    fn caller_can_wrap_without_skipping_early_freed_frames() {
        let mut bitmap = [0xffu8; 16];
        clear(&mut bitmap, 0);
        clear(&mut bitmap, 119);
        assert_eq!(first_clear_bit(&bitmap, 120, 128), None);
        assert_eq!(first_clear_bit(&bitmap, 0, 120), Some(0));
        assert_eq!(first_clear_bit(&bitmap, 1, 120), Some(119));
    }

    #[test]
    fn sixty_four_gib_bitmap_can_find_last_free_frame_without_real_ram() {
        // A 64-GiB PMM has 16,777,216 4-KiB frames but needs only 2 MiB
        // of metadata; this host test does NOT allocate 64 GiB of RAM.
        const FRAMES: usize = 64 * 1024 * 1024 * 1024 / 4096;
        let mut bitmap = vec![0xffu8; FRAMES / 8];
        clear(&mut bitmap, FRAMES - 1);
        assert_eq!(first_clear_bit(&bitmap, 0, FRAMES), Some(FRAMES - 1));
        assert_eq!(first_clear_bit(&bitmap, 0, FRAMES - 1), None);
        clear(&mut bitmap, 63);
        assert_eq!(first_clear_bit(&bitmap, 64, FRAMES), Some(FRAMES - 1));
        assert_eq!(first_clear_bit(&bitmap, 0, FRAMES), Some(63));
    }

    #[test]
    fn bounded_scanner_matches_a_bit_by_bit_reference() {
        let mut state = 0x9e37_79b9u32;
        for len in 1..=19 {
            let mut bitmap = vec![0u8; len];
            for _ in 0..24 {
                for byte in &mut bitmap {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    *byte = state as u8;
                }
                let capacity = len * 8;
                for start in 0..capacity {
                    for end in start + 1..=capacity {
                        let slow = (start..end)
                            .find(|&bit| bitmap[bit / 8] & (1 << (bit % 8)) == 0);
                        assert_eq!(first_clear_bit(&bitmap, start, end), slow,
                            "len={len} start={start} end={end}");
                    }
                }
            }
        }
    }
}
