//! Bounded, allocation-free read-only graphical diagnostic line rendering.
//! The caller supplies already-authorized counts. This module never touches
//! PCI configuration ports, global PMM state or display memory.

use core::fmt::{self, Write};
use crate::shell_command::Command;

pub const CAP: usize = 26;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Line {
    bytes: [u8; CAP],
    len: usize,
}

impl Line {
    const fn new() -> Self {
        Self { bytes: [0; CAP], len: 0 }
    }

    pub fn as_str(&self) -> &str {
        // SAFETY: only Rust ASCII format strings and decimal digits are used,
        // and fmt::Write supplies valid UTF-8 bytes.
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

impl Write for Line {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        if end > CAP {
            return Err(fmt::Error);
        }
        self.bytes[self.len..end].copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// 4-KiB PMM frames, summarized in whole MiB. Overflow or more than 26
/// screen cells fails closed (rather than printing a truncated answer).
pub fn memory(free_frames: usize) -> Option<Line> {
    let mib = free_frames / 256;
    let mut line = Line::new();
    write!(&mut line, "MEM FREE {}M", mib).ok()?;
    Some(line)
}

/// Immutable, early-boot PCI device class counts. Never rescans CF8/CFC.
pub fn pci(displays: usize, networks: usize, storage: usize) -> Option<Line> {
    let mut line = Line::new();
    write!(&mut line, "PCI D{} N{} S{}", displays, networks, storage).ok()?;
    Some(line)
}

/// Bounded read-only CPUID vendor and family/model; no device probing.
pub fn cpu(vendor: &str, family: Option<u32>, model: Option<u32>) -> Option<Line> {
    if !vendor.bytes().all(|byte| byte.is_ascii_graphic()) {
        return None;
    }
    let mut line = Line::new();
    match (family, model) {
        (Some(family), Some(model)) =>
            write!(&mut line, "CPU {} {}/{}", vendor, family, model).ok()?,
        _ => write!(&mut line, "CPU {} NO LEAF1", vendor).ok()?,
    };
    Some(line)
}

pub fn diagnostic(
    command: Command, free_frames: usize,
    displays: usize, networks: usize, storage: usize,
) -> Option<Line> {
    match command {
        Command::Memory => memory(free_frames),
        Command::Pci => pci(displays, networks, storage),
        // No privileged COM1 actions, or arbitrary command execution.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_frames_are_converted_to_whole_mebibytes() {
        assert_eq!(memory(124_739).unwrap().as_str(), "MEM FREE 487M");
        assert_eq!(memory(255).unwrap().as_str(), "MEM FREE 0M");
    }

    #[test]
    fn pci_summary_is_exact_and_not_truncated() {
        assert_eq!(pci(1, 2, 3).unwrap().as_str(), "PCI D1 N2 S3");
        assert_eq!(pci(usize::MAX, usize::MAX, usize::MAX), None);
    }

    #[test]
    fn cpu_summary_is_exact_bounded_and_printable() {
        assert_eq!(cpu("GenuineIntel", Some(6), Some(85)).unwrap().as_str(),
                   "CPU GenuineIntel 6/85");
        assert_eq!(cpu("AuthenticAMD", Some(271), Some(255)).unwrap().as_str(),
                   "CPU AuthenticAMD 271/255");
        assert_eq!(cpu("unknown", None, None).unwrap().as_str(),
                   "CPU unknown NO LEAF1");
        assert_eq!(cpu("vendor\n", Some(6), Some(85)), None);
        assert_eq!(cpu("extra-long-vendor-name", Some(271), Some(255)), None);
    }

    #[test]
    fn classifier_rejects_privileged_actions() {
        assert_eq!(diagnostic(Command::Halt, 2, 1, 1, 1), None);
        assert_eq!(diagnostic(Command::Clear, 2, 1, 1, 1), None);
        assert_eq!(diagnostic(Command::Memory, 512, 1, 1, 1).unwrap().as_str(), "MEM FREE 2M");
    }
}
