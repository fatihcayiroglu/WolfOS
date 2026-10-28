//! Bounded early graphical text-console buffer. No heap, device input, IRQ,
//! userspace launch or mutable global framebuffer state.
//! Rendering takes an external writer and is intentionally BSP-only.

use crate::framebuffer_text::Layout;

pub const MAX_COLS: usize = 80;
pub const MAX_ROWS: usize = 25;

pub struct TextConsole {
    layout: Layout,
    origin_x: u64,
    origin_y: u64,
    cols: usize,
    rows: usize,
    cursor_col: usize,
    cursor_row: usize,
    scrolls: usize,
    cells: [u8; MAX_COLS * MAX_ROWS],
}

impl TextConsole {
    /// Reject incomplete cells and coordinates outside the mapped framebuffer
    /// before any pixel is written. A fixed 80x25 backing buffer bounds memory.
    pub fn new(layout: Layout, x: u64, y: u64, cols: usize, rows: usize) -> Option<Self> {
        if cols == 0 || cols > MAX_COLS || rows == 0 || rows > MAX_ROWS {
            return None;
        }
        let right = x.checked_add((cols as u64).checked_mul(6)?)?.checked_sub(1)?;
        let bottom = y.checked_add((rows as u64).checked_mul(8)?)?.checked_sub(1)?;
        layout.pixel_offset(right, bottom)?;
        Some(Self {
            layout, origin_x: x, origin_y: y, cols, rows,
            cursor_col: 0, cursor_row: 0, scrolls: 0,
            cells: [b' '; MAX_COLS * MAX_ROWS],
        })
    }

    pub fn cursor(&self) -> (usize, usize) {
        (self.cursor_col, self.cursor_row)
    }

    pub fn scroll_count(&self) -> usize {
        self.scrolls
    }

    pub fn cell(&self, col: usize, row: usize) -> Option<u8> {
        if col >= self.cols || row >= self.rows {
            None
        } else {
            Some(self.cells[row * MAX_COLS + col])
        }
    }

    fn newline(&mut self) {
        self.cursor_col = 0;
        if self.cursor_row + 1 < self.rows {
            self.cursor_row += 1;
            return;
        }
        // Move only active rows; unused backing rows remain inaccessible.
        self.cells.copy_within(MAX_COLS..self.rows * MAX_COLS, 0);
        self.cells[(self.rows - 1) * MAX_COLS..self.rows * MAX_COLS].fill(b' ');
        self.scrolls = self.scrolls.saturating_add(1);
    }

    pub fn backspace(&mut self) -> bool {
        if self.cursor_col == 0 { return false; }
        self.cursor_col -= 1;
        self.cells[self.cursor_row * MAX_COLS + self.cursor_col] = b' ';
        true
    }

    pub fn write(&mut self, text: &str) {
        for byte in text.bytes() {
            match byte {
                b'\n' => self.newline(),
                b'\r' => self.cursor_col = 0,
                _ => {
                    // Non-ASCII and control input never enters hardware logic.
                    let normalized = match byte {
                        b'a'..=b'z' => byte - 32,
                        0x20..=0x7e => byte,
                        _ => b'?',
                    };
                    // Deferred wrap: a newline after the rightmost character
                    // advances only one line, not two.
                    if self.cursor_col == self.cols {
                        self.newline();
                    }
                    let index = self.cursor_row * MAX_COLS + self.cursor_col;
                    self.cells[index] = normalized;
                    self.cursor_col += 1;
                }
            }
        }
    }

    /// Redraw the whole bounded console with opaque foreground/background.
    /// The caller supplies volatile hardware stores; no unsynchronized AP
    /// rendering is allowed. Returned count is checked pixel writes.
    pub fn render<F: FnMut(usize, u32)>(&self, foreground: u32, background: u32, mut pixel: F) -> usize {
        let mut count = 0;
        for row in 0..self.rows {
            let y = self.origin_y + row as u64 * 8;
            for col in 0..self.cols {
                let x = self.origin_x + col as u64 * 6;
                count += self.layout.draw_cell(
                    x, y, self.cells[row * MAX_COLS + col], foreground, background,
                    |offset, color| pixel(offset, color),
                );
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_terminal_size_and_partial_cells() {
        let layout = Layout::new(12, 16, 64).unwrap();
        for (x,y,w,h) in [
            (0,0,0,1), (0,0,1,0), (0,0,81,1), (0,0,1,26),
            (1,0,2,1), (0,1,1,2), (u64::MAX,0,1,1),
        ] {
            assert!(TextConsole::new(layout,x,y,w,h).is_none(), "{x} {y} {w} {h}");
        }
        assert!(TextConsole::new(layout,0,0,2,2).is_some());
    }

    #[test]
    fn deferred_wrap_newline_scrolls_once_and_drops_oldest_row() {
        let layout = Layout::new(18, 16, 80).unwrap();
        let mut t = TextConsole::new(layout, 0, 0, 3, 2).unwrap();
        t.write("abc\ndef");
        assert_eq!(t.scroll_count(), 0);
        assert_eq!(t.cursor(), (3, 1));
        assert_eq!([t.cell(0,0),t.cell(1,0),t.cell(2,0)],
                   [Some(b'A'),Some(b'B'),Some(b'C')]);
        assert_eq!(t.cell(2,1),Some(b'F'));
        t.write("g");
        assert_eq!(t.scroll_count(),1);
        assert_eq!(t.cursor(),(1,1));
        assert_eq!(t.cell(0,0),Some(b'D'));
        assert_eq!(t.cell(0,1),Some(b'G'));
        assert_eq!(t.cell(1,1),Some(b' '));
        t.write("\rZ");
        assert_eq!(t.cell(0,1),Some(b'Z'));
        assert_eq!(t.cursor(),(1,1));
    }

    #[test]
    fn rendering_overwrites_glyphs_and_respects_pitch_padding() {
        let layout = Layout::new(12, 16, 64).unwrap();
        let mut t = TextConsole::new(layout, 0, 0, 2, 2).unwrap();
        let mut surface = [0x5au8; 16 * 64];
        t.write("B\nC");
        let count = t.render(0x0000ffff, 0, |offset, color| {
            assert!(offset + 4 <= surface.len());
            surface[offset..offset+4].copy_from_slice(&color.to_le_bytes());
        });
        assert_eq!(count, 2 * 2 * 6 * 8);
        assert_eq!(&surface[0..4], &0x0000ffffu32.to_le_bytes());
        assert_eq!(&surface[64 * 8..64 * 8 + 4], &0u32.to_le_bytes());
        assert_eq!(&surface[64 * 8 + 4..64 * 8 + 8], &0x0000ffffu32.to_le_bytes());
        for row in 0..16 {
            assert!(surface[row * 64 + 48..(row + 1) * 64].iter().all(|v| *v == 0x5a));
        }
        t.write("\r ");
        t.render(0x0000ffff, 0, |offset, color| {
            assert!(offset + 4 <= surface.len());
            surface[offset..offset+4].copy_from_slice(&color.to_le_bytes());
        });
        // C top-row second pixel had been lit; replacing C with a space
        // must clear it as well as the glyph foreground.
        assert_eq!(&surface[64 * 8 + 4..64 * 8 + 8], &0u32.to_le_bytes());
    }

    #[test]
    fn input_backspace_clears_last_cell_but_never_crosses_line_start() {
        let layout = Layout::new(24, 16, 112).unwrap();
        let mut c = TextConsole::new(layout, 0, 0, 4, 2).unwrap();
        assert!(!c.backspace());
        c.write("abc");
        assert_eq!(c.cursor(), (3, 0));
        assert!(c.backspace());
        assert_eq!(c.cursor(), (2, 0));
        assert_eq!(c.cell(2, 0), Some(b' '));
        c.write("d\n");
        assert_eq!(c.cell(2, 0), Some(b'D'));
        assert_eq!(c.cursor(), (0, 1));
        assert!(!c.backspace());
        assert_eq!(c.cell(2, 0), Some(b'D'));
    }

    #[test]
    fn overflow_input_is_display_data_not_an_executable_command() {
        let layout = Layout::new(6, 8, 32).unwrap();
        let mut t = TextConsole::new(layout,0,0,1,1).unwrap();
        t.write("\0é\n?");
        assert!(t.scroll_count() >= 1);
        assert_eq!(t.cell(0,0),Some(b'?'));
        assert_eq!(t.cell(1,0),None);
    }
}
