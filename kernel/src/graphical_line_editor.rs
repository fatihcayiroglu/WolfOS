//! Allocation-free graphical diagnostic input. An overlong line is poisoned
//! until Enter; no truncated command may ever be dispatched or silently reused.

use crate::shell_command::Command;

pub struct LineEditor<const CAP: usize> {
    bytes: [u8; CAP],
    len: usize,
    overflow: bool,
}

impl<const CAP: usize> LineEditor<CAP> {
    pub const fn new() -> Self {
        Self { bytes: [0; CAP], len: 0, overflow: false }
    }

    /// Returns true only if the caller may draw the new character.
    pub fn push(&mut self, byte: u8) -> bool {
        if !(0x20..=0x7e).contains(&byte) || self.overflow {
            return false;
        }
        if self.len >= CAP {
            self.overflow = true;
            return false;
        }
        self.bytes[self.len] = byte;
        self.len += 1;
        true
    }

    /// Returns true only if a previously rendered character was removed.
    /// Overflow is a terminal error for *this line*, cleared only by Enter.
    pub fn backspace(&mut self) -> bool {
        if self.overflow || self.len == 0 {
            return false;
        }
        self.len -= 1;
        self.bytes[self.len] = 0;
        true
    }

    pub fn submit(&mut self) -> Command {
        let command = if self.overflow {
            Command::TooLong
        } else {
            Command::parse(&self.bytes[..self.len])
        };
        self.bytes.fill(0);
        self.len = 0;
        self.overflow = false;
        command
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_boundary_and_poisoned_overflow_never_dispatch_truncated_commands() {
        let mut input = LineEditor::<4>::new();
        for &byte in b"halt" { assert!(input.push(byte)); }
        assert_eq!(input.submit(), Command::Halt);
        for &byte in b"halt" { assert!(input.push(byte)); }
        assert!(!input.push(b'x'));
        assert!(!input.backspace());
        assert!(!input.push(b'e'));
        assert_eq!(input.submit(), Command::TooLong);
        assert_eq!(input.submit(), Command::Empty);
    }

    #[test]
    fn newline_recovers_from_overflow_and_backspace_edits_normal_line() {
        let mut input = LineEditor::<4>::new();
        for &b in b"helx" { assert!(input.push(b)); }
        assert!(input.backspace());
        assert!(input.push(b'p'));
        assert_eq!(input.submit(), Command::Help);
        for &b in b"help" { assert!(input.push(b)); }
        assert!(!input.push(b'a'));
        assert_eq!(input.submit(), Command::TooLong);
        for &b in b"help" { assert!(input.push(b)); }
        assert_eq!(input.submit(), Command::Help);
    }

    #[test]
    fn control_bytes_do_not_enter_parser_and_empty_backspace_is_safe() {
        let mut input = LineEditor::<12>::new();
        assert!(!input.push(0));
        assert!(!input.push(b'\n'));
        assert!(!input.push(0x7f));
        assert!(!input.backspace());
        assert_eq!(input.submit(), Command::Empty);
        for &b in b"HELP" { assert!(input.push(b)); }
        assert_eq!(input.submit(), Command::Unknown);
    }

    #[test]
    fn zero_capacity_is_always_poisoned_on_printable_input() {
        let mut input = LineEditor::<0>::new();
        assert!(!input.push(b'a'));
        assert_eq!(input.submit(), Command::TooLong);
        assert_eq!(input.submit(), Command::Empty);
    }
}
