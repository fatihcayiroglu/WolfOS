//! Pure, bounded command classification shared by COM1 and optional PS/2 UI.
//! No hardware, heap, privilege changes or command execution in this module.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Empty, Help, About, Cpu, Pci, Memory, Clear, Halt, Unknown, TooLong,
}

impl Command {
    pub fn parse(input: &[u8]) -> Self {
        match input {
            b"" => Self::Empty,
            b"help" => Self::Help,
            b"about" => Self::About,
            b"cpu" => Self::Cpu,
            b"pci" => Self::Pci,
            b"mem" => Self::Memory,
            b"clear" => Self::Clear,
            b"halt" => Self::Halt,
            _ => Self::Unknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_ascii_names_and_no_prefix_matching() {
        for (name, want) in [
            (b"".as_slice(), Command::Empty),
            (b"help", Command::Help),
            (b"about", Command::About),
            (b"cpu", Command::Cpu),
            (b"pci", Command::Pci),
            (b"mem", Command::Memory),
            (b"clear", Command::Clear),
            (b"halt", Command::Halt),
        ] {
            assert_eq!(Command::parse(name), want);
        }
        for name in [b"HELP".as_slice(), b"help ", b"halt now", b"cpu\0", b"\xff"] {
            assert_eq!(Command::parse(name), Command::Unknown);
        }
    }
}
