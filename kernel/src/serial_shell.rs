//! Bounded first interactive WolfOS user interface on QEMU COM1.
//!
//! Intentionally BSP-only and polling: no filesystem, allocator, networking,
//! privileged runtime mutation, desktop or Ring3 process launch is exposed.
//! This is an experimental kernel diagnostic console, not a user shell.
const CAP: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Empty, Help, About, Cpu, Memory, Clear, Halt, Unknown, TooLong,
}

struct Input {
    bytes: [u8; CAP],
    len: usize,
    overflow: bool,
    skip_lf_after_cr: bool,
}

impl Input {
    const fn new() -> Self {
        Self { bytes: [0; CAP], len: 0, overflow: false, skip_lf_after_cr: false }
    }

    fn push(&mut self, byte: u8) -> Option<Command> {
        // A terminal may send CRLF for one Enter key. The LF belongs to
        // that CR, while standalone LF remains a valid command terminator.
        if byte == b'\n' && self.skip_lf_after_cr {
            self.skip_lf_after_cr = false;
            return None;
        }
        self.skip_lf_after_cr = byte == b'\r';
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
                        b"cpu" => Command::Cpu,
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
            serial::write_line("WOLFOS_SHELL_HELP commands: help about cpu mem clear halt"),
        Command::About =>
            serial::write_line("WOLFOS_SHELL_ABOUT experimental Rust kernel; QEMU COM1, no userspace shell"),
        Command::Cpu => {
            // CPUID is read-only, already used during boot, and does not
            // probe mutable PCI/ACPI configuration or install a driver.
            serial::write_line("WOLFOS_SHELL_CPU_BEGIN");
            crate::cpu::log_identity();
            serial::write_line("WOLFOS_SHELL_CPU_END");
        }
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
                    if let Some(command) = input.push(byte) {
                        serial::write_line("");
                        execute(command);
                        serial::write_fmt(format_args!("wolfos> "));
                    }
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
            (b"cpu", Command::Cpu),
            (b"CPU", Command::Unknown),
            (b"cpu 1", Command::Unknown),
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
    fn crlf_is_one_submission_but_standalone_lf_still_works() {
        let mut i = Input::new();
        for &byte in b"help" { assert_eq!(i.push(byte), None); }
        assert_eq!(i.push(b'\r'), Some(Command::Help));
        assert_eq!(i.push(b'\n'), None, "CRLF must not create an empty command");
        for &byte in b"mem" { assert_eq!(i.push(byte), None); }
        assert_eq!(i.push(b'\n'), Some(Command::Memory));
        assert_eq!(i.push(b'\n'), Some(Command::Empty));
        assert_eq!(i.push(b'\r'), Some(Command::Empty));
        assert_eq!(i.push(b'x'), None, "non-LF after CR cancels suppression");
        assert_eq!(i.push(b'\n'), Some(Command::Unknown));
    }

    #[test]
    fn overlong_input_never_executes_truncated_command() {
        let mut i = Input::new();
        for _ in 0..65 { assert_eq!(i.push(b'x'), None); }
        assert_eq!(i.push(b'\r'), Some(Command::TooLong));
        assert_eq!(enter(&mut i, b"halt"), Command::Halt);
    }
}
