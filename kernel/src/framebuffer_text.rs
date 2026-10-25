//! Allocation-free clipped 5x7 uppercase text for an early 32-bpp framebuffer.
//! The caller owns the memory mapping. This module validates byte offsets and
//! never dereferences raw hardware pointers itself.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    width: u64,
    height: u64,
    pitch: u64,
    bytes: u64,
}

impl Layout {
    pub fn new(width: u64, height: u64, pitch: u64) -> Option<Self> {
        if width == 0 || height == 0 || pitch % 4 != 0 {
            return None;
        }
        let row_pixels = width.checked_mul(4)?;
        if pitch < row_pixels {
            return None;
        }
        let bytes = pitch.checked_mul(height)?;
        if bytes > isize::MAX as u64 {
            return None;
        }
        Some(Self { width, height, pitch, bytes })
    }

    pub fn pixel_offset(self, x: u64, y: u64) -> Option<usize> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let offset = y.checked_mul(self.pitch)?
            .checked_add(x.checked_mul(4)?)?;
        if offset.checked_add(4)? > self.bytes {
            return None;
        }
        usize::try_from(offset).ok()
    }

    /// Emits foreground pixels through a caller-provided safe/volatile writer.
    /// Unsupported bytes render '?' and lines do not wrap automatically.
    pub fn draw_text<F: FnMut(usize, u32)>(
        self, x: u64, y: u64, text: &str, foreground: u32, mut pixel: F,
    ) -> usize {
        let mut written = 0usize;
        for (index, byte) in text.bytes().enumerate() {
            let Some(dx) = (index as u64).checked_mul(6).and_then(|n| x.checked_add(n)) else {
                break;
            };
            if dx >= self.width {
                break;
            }
            for (row, bits) in glyph(byte).iter().copied().enumerate() {
                let Some(gy) = y.checked_add(row as u64) else { continue };
                for col in 0..5u64 {
                    if bits & (1u8 << (4 - col as u8)) == 0 {
                        continue;
                    }
                    let Some(gx) = dx.checked_add(col) else { continue };
                    if let Some(offset) = self.pixel_offset(gx, gy) {
                        pixel(offset, foreground);
                        written += 1;
                    }
                }
            }
        }
        written
    }
}

/// Five high-order bits per row, top to bottom (ASCII uppercase, digits,
/// and essential diagnostic punctuation). No font file or allocation.
fn glyph(byte: u8) -> [u8; 7] {
    match byte {
        b'A' => [14,17,17,31,17,17,17],
        b'B' => [30,17,17,30,17,17,30],
        b'C' => [14,17,16,16,16,17,14],
        b'D' => [30,17,17,17,17,17,30],
        b'E' => [31,16,16,30,16,16,31],
        b'F' => [31,16,16,30,16,16,16],
        b'G' => [14,17,16,23,17,17,15],
        b'H' => [17,17,17,31,17,17,17],
        b'I' => [31,4,4,4,4,4,31],
        b'J' => [7,2,2,2,18,18,12],
        b'K' => [17,18,20,24,20,18,17],
        b'L' => [16,16,16,16,16,16,31],
        b'M' => [17,27,21,21,17,17,17],
        b'N' => [17,25,21,19,17,17,17],
        b'O' => [14,17,17,17,17,17,14],
        b'P' => [30,17,17,30,16,16,16],
        b'Q' => [14,17,17,17,21,18,13],
        b'R' => [30,17,17,30,20,18,17],
        b'S' => [15,16,16,14,1,1,30],
        b'T' => [31,4,4,4,4,4,4],
        b'U' => [17,17,17,17,17,17,14],
        b'V' => [17,17,17,17,17,10,4],
        b'W' => [17,17,17,21,21,21,10],
        b'X' => [17,17,10,4,10,17,17],
        b'Y' => [17,17,10,4,4,4,4],
        b'Z' => [31,1,2,4,8,16,31],
        b'0' => [14,17,19,21,25,17,14],
        b'1' => [4,12,4,4,4,4,14],
        b'2' => [14,17,1,2,4,8,31],
        b'3' => [30,1,1,14,1,1,30],
        b'4' => [2,6,10,18,31,2,2],
        b'5' => [31,16,16,30,1,1,30],
        b'6' => [14,16,16,30,17,17,14],
        b'7' => [31,1,2,4,8,8,8],
        b'8' => [14,17,17,14,17,17,14],
        b'9' => [14,17,17,15,1,1,14],
        b' ' => [0; 7],
        b':' => [0,4,4,0,4,4,0],
        b'.' => [0,0,0,0,0,12,12],
        b'-' => [0,0,0,31,0,0,0],
        b'_' => [0,0,0,0,0,0,31],
        b'/' => [1,1,2,4,8,16,16],
        b'>' => [16,8,4,2,4,8,16],
        b'?' => [14,17,1,2,4,0,4],
        _ => [14,17,1,2,4,0,4],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_geometry_and_overflow() {
        for dims in [
            (0, 10, 40), (10, 0, 40), (10, 10, 39),
            (10, 10, 36), (u64::MAX, 2, u64::MAX),
            (1, u64::MAX, 4), (1, (isize::MAX as u64 / 4) + 1, 4),
        ] {
            assert!(Layout::new(dims.0, dims.1, dims.2).is_none(), "{dims:?}");
        }
        let g = Layout::new(7, 9, 40).unwrap();
        assert_eq!(g.pixel_offset(6, 8), Some(344));
        assert_eq!(g.pixel_offset(7, 8), None);
        assert_eq!(g.pixel_offset(6, 9), None);
    }

    #[test]
    fn writes_only_visible_foreground_pixels_not_stride_padding() {
        let g = Layout::new(5, 7, 32).unwrap();
        let mut memory = [0u8; 7 * 32];
        let mut touched = [false; 7 * 32];
        let count = g.draw_text(0, 0, "W", 0x1234_5678, |offset, color| {
            assert!(offset + 4 <= memory.len());
            memory[offset..offset+4].copy_from_slice(&color.to_le_bytes());
            touched[offset] = true;
        });
        assert!(count >= 10);
        assert!(touched[0]); // First pixel in a W is lit.
        assert!(!touched[4]); // Second pixel in its top row is dark.
        for row in 0..7 {
            assert_eq!(&memory[row * 32 + 20..row * 32 + 32], &[0u8; 12]);
        }
    }

    #[test]
    fn clips_right_bottom_and_rejects_out_of_bounds_origin() {
        let g = Layout::new(9, 9, 40).unwrap();
        let mut offsets = std::vec::Vec::new();
        let count = g.draw_text(7, 7, "WOLFOS", 1, |offset, _| offsets.push(offset));
        assert_eq!(count, offsets.len());
        assert!(count > 0);
        assert!(offsets.iter().all(|o| *o < 9 * 40));
        assert_eq!(g.draw_text(9, 0, "W", 1, |_, _| panic!("offscreen")), 0);
        assert_eq!(g.draw_text(0, 9, "W", 1, |_, _| panic!("offscreen")), 0);
    }

    #[test]
    fn core_letter_digit_and_space_shapes_are_defined() {
        for c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" {
            assert!(glyph(*c).iter().any(|row| *row != 0));
        }
        assert!(glyph(b' ').iter().all(|row| *row == 0));
        assert_eq!(glyph(b'@'), glyph(b'?'));
    }
}
