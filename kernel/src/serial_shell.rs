//! Bounded first interactive WolfOS user interface on QEMU COM1.
//!
//! Intentionally BSP-only and polling: no filesystem, allocator, networking,
//! privileged runtime mutation, desktop or Ring3 process launch is exposed.
//! This is an experimental kernel diagnostic console, not a user shell.
const CAP: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Empty, Help, About, Memory, Clear, Halt, Unknown, TooLong,
}

struct Input {
    bytes: [u8; CAP],
    len: usize,
    overflow: bool,
}

impl Input {
    const fn new() -> Self {
        Self { bytes: [0; CAP], len: 0, overflow: false }
    }

    fn push(&mut self, byte: u8) -> Option<Command> {
        match byte {
            b'\r' | b'\n' => {
                let command = if self.overflow {
                    Command::TooLong
                } else {
                    match &self.bytes[..self.len] {
                        b"" => Command::Empty,
                        b"help" => Command::Help,
                        b"about" => Command::About,
                        b"mem" => Command::Memory,
                        b"clear" => Command::Clear,
                        b"halt" => Command::Halt,
                        _ => Command::Unknown,
                    }
                };
                self.len = 0;
                self.overflow = false;
                Some(command)
            }
            b'\x08' | 0x7f => {
                if !self.overflow && self.len != 0 { self.len -= 1; }
                None
            }
            0x20..=0x7e => {
                if !self.overflow {
                    if self.len == CAP {
                        self.overflow = true;
                    } else {
                        self.bytes[self.len] = byte;
                        self.len += 1;
                    }
                }
                None
            }
            _ => None,
        }
    }
}

#[cfg(not(test))]
fn execute(command: Command) {
    use crate::{pmm, serial};
    match command {
        Command::Empty => {}
        Command::Help =>
            serial::write_line("WOLFOS_SHELL_HELP commands: help about mem clear halt"),
        Command::About =>
            serial::write_line("WOLFOS_SHELL_ABOUT experimental Rust kernel; QEMU COM1, no userspace shell"),
        Command::Memory => {
            let stats = pmm::statistics();
            serial::write_fmt(format_args!(
                "WOLFOS_SHELL_MEM total_frames={} free_frames={} allocated_frames={}\n",
                stats.total_frames, stats.free_frames(), stats.allocated_frames,
            ));
        }
        Command::Clear => {
            serial::write_fmt(format_args!("\x1b[2J\x1b[H"));
            serial::write_line("WOLFOS_SHELL_CLEAR");
        }
        Command::Unknown => serial::write_line("WOLFOS_SHELL_UNKNOWN try help"),
        Command::TooLong => serial::write_line("WOLFOS_SHELL_TOO_LONG maximum 64 ASCII bytes"),
        Command::Halt => {
            serial::write_line("WOLFOS_SHELL_HALT");
            crate::halt_forever();
        }
    }
}

#[cfg(not(test))]
pub fn run() -> ! {
    use crate::serial;
    let mut input = Input::new();
    serial::write_line("WOLFOS_SHELL_READY serial=COM1 input=ASCII");
    serial::write_fmt(format_args!("wolfos> "));
    loop {
        if let Some(byte) = serial::read_byte_nonblocking() {
            match byte {
                b'\r' | b'\n' => {
                    serial::write_line("");
                    if let Some(command) = input.push(byte) {
                        execute(command);
                    }
                    serial::write_fmt(format_args!("wolfos> "));
                }
                b'\x08' | 0x7f => {
                    let len = input.len;
                    input.push(byte);
                    if input.len < len {
                        serial::write_fmt(format_args!("\x08 \x08"));
                    }
                }
                0x20..=0x7e => {
                    input.push(byte);
                    if !input.overflow {
                        serial::write_fmt(format_args!("{}", byte as char));
                    }
                }
                _ => { input.push(byte); }
            }
        } else {
            core::hint::spin_loop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, Input};
    fn enter(input: &mut Input, bytes: &[u8]) -> Command {
        for &byte in bytes { assert_eq!(input.push(byte), None); }
        input.push(b'\r').unwrap()
    }

    #[test]
    fn commands_are_exact_and_case_sensitive() {
        let mut i = Input::new();
        for (name, want) in [
            (b"help".as_slice(), Command::Help),
            (b"about", Command::About),
            (b"mem", Command::Memory),
            (b"clear", Command::Clear),
            (b"halt", Command::Halt),
            (b"HELP", Command::Unknown),
            (b"mem now", Command::Unknown),
            (b"", Command::Empty),
        ] {
            assert_eq!(enter(&mut i, name), want);
        }
    }

    #[test]
    fn backspace_and_unsupported_input_are_safe() {
        let mut i = Input::new();
        assert_eq!(enter(&mut i, b"helpX\x08"), Command::Help);
        assert_eq!(enter(&mut i, b"m\0em"), Command::Memory);
        assert_eq!(i.push(0x7f), None);
        assert_eq!(enter(&mut i, b""), Command::Empty);
    }

    #[test]
    fn overlong_input_never_executes_truncated_command() {
        let mut i = Input::new();
        for _ in 0..65 { assert_eq!(i.push(b'x'), None); }
        assert_eq!(i.push(b'\r'), Some(Command::TooLong));
        assert_eq!(enter(&mut i, b"halt"), Command::Halt);
    }
}
