//! Bounded QEMU PS/2 set-1 keyboard input for an opt-in BSP polling demo.
//! No IRQ registration, controller reprogramming, heap, DMA or device writes.
//! This is NOT a production keyboard driver (USB/HID, layouts, hotplug absent).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Character(u8),
    Enter,
    Backspace,
}

pub struct Set1Decoder {
    left_shift: bool,
    right_shift: bool,
    extended: bool,
    pause_remaining: u8,
}

impl Set1Decoder {
    pub const fn new() -> Self {
        Self { left_shift: false, right_shift: false, extended: false, pause_remaining: 0 }
    }

    /// Only report key presses. Releases, prefixes, unmapped keys and controller
    /// responses are deliberately ignored. A Pause prefix swallows its six-byte
    /// sequence, preventing accidental synthetic character input.
    pub fn feed(&mut self, scan: u8) -> Option<Key> {
        if self.pause_remaining != 0 {
            self.pause_remaining -= 1;
            return None;
        }
        if scan == 0xe1 {
            self.extended = false;
            self.pause_remaining = 5;
            return None;
        }
        if scan == 0xe0 {
            self.extended = true;
            return None;
        }
        if self.extended {
            self.extended = false;
            return None;
        }
        let release = scan & 0x80 != 0;
        let key = scan & 0x7f;
        if key == 0x2a {
            self.left_shift = !release;
            return None;
        }
        if key == 0x36 {
            self.right_shift = !release;
            return None;
        }
        if release {
            return None;
        }
        match key {
            0x1c => Some(Key::Enter),
            0x0e => Some(Key::Backspace),
            0x39 => Some(Key::Character(b' ')),
            _ => {
                let ascii = match key {
                    0x1e => b'a', 0x30 => b'b', 0x2e => b'c', 0x20 => b'd',
                    0x12 => b'e', 0x21 => b'f', 0x22 => b'g', 0x23 => b'h',
                    0x17 => b'i', 0x24 => b'j', 0x25 => b'k', 0x26 => b'l',
                    0x32 => b'm', 0x31 => b'n', 0x18 => b'o', 0x19 => b'p',
                    0x10 => b'q', 0x13 => b'r', 0x1f => b's', 0x14 => b't',
                    0x16 => b'u', 0x2f => b'v', 0x11 => b'w', 0x2d => b'x',
                    0x15 => b'y', 0x2c => b'z',
                    0x0b => b'0', 0x02 => b'1', 0x03 => b'2', 0x04 => b'3',
                    0x05 => b'4', 0x06 => b'5', 0x07 => b'6', 0x08 => b'7',
                    0x09 => b'8', 0x0a => b'9',
                    _ => return None,
                };
                let shift = self.left_shift || self.right_shift;
                let ascii = if shift && ascii.is_ascii_lowercase() {
                    ascii.to_ascii_uppercase()
                } else {
                    ascii
                };
                Some(Key::Character(ascii))
            }
        }
    }
}

#[cfg(not(test))]
mod hardware {
    use core::arch::asm;

    #[inline]
    unsafe fn read_port(port: u16) -> u8 {
        let value: u8;
        // SAFETY: only QEMU-compatible PS/2 input/status ports are supplied.
        unsafe { asm!("in al, dx", in("dx") port, out("al") value,
            options(nomem, nostack, preserves_flags)); }
        value
    }

    /// Fetch at most one valid keyboard scan code from the 8042 output buffer.
    /// Even error and AUX bytes are consumed to prevent stuck output-buffer
    /// status, but never interpreted as a key.
    pub fn read_scancode() -> Option<u8> {
        // SAFETY: status port read is non-mutating.
        let status = unsafe { read_port(0x64) };
        if status & 0x01 == 0 {
            return None;
        }
        // SAFETY: status indicated a buffered byte, which must be drained.
        let byte = unsafe { read_port(0x60) };
        if status & 0xe0 != 0 {
            return None;
        }
        Some(byte)
    }
}

#[cfg(not(test))]
pub use hardware::read_scancode;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qemu_set1_make_break_enter_and_backspace() {
        let mut d = Set1Decoder::new();
        assert_eq!(d.feed(0x1e), Some(Key::Character(b'a')));
        assert_eq!(d.feed(0x9e), None);
        assert_eq!(d.feed(0x30), Some(Key::Character(b'b')));
        assert_eq!(d.feed(0xb0), None);
        assert_eq!(d.feed(0x0e), Some(Key::Backspace));
        assert_eq!(d.feed(0x8e), None);
        assert_eq!(d.feed(0x1c), Some(Key::Enter));
        assert_eq!(d.feed(0x9c), None);
    }

    #[test]
    fn handles_shift_release_and_unknown_keys_without_phantom_input() {
        let mut d = Set1Decoder::new();
        assert_eq!(d.feed(0x2a), None);
        assert_eq!(d.feed(0x1e), Some(Key::Character(b'A')));
        assert_eq!(d.feed(0x36), None);
        assert_eq!(d.feed(0xaa), None);
        assert_eq!(d.feed(0x30), Some(Key::Character(b'B')));
        assert_eq!(d.feed(0xb6), None);
        assert_eq!(d.feed(0x30), Some(Key::Character(b'b')));
        assert_eq!(d.feed(0x01), None); // Escape
        assert_eq!(d.feed(0x81), None);
    }

    #[test]
    fn extended_and_pause_bytes_are_never_printable_input() {
        let mut d = Set1Decoder::new();
        assert_eq!(d.feed(0xe0), None);
        assert_eq!(d.feed(0x1c), None); // numpad Enter
        assert_eq!(d.feed(0xe0), None);
        assert_eq!(d.feed(0x9c), None);
        assert_eq!(d.feed(0xe1), None);
        for byte in [0x1d, 0x45, 0xe1, 0x9d, 0xc5] {
            assert_eq!(d.feed(byte), None);
        }
        assert_eq!(d.feed(0x20), Some(Key::Character(b'd')));
    }
}
