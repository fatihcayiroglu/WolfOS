//! Pure xAPIC ID and version register decoding (no_std and host-testable).
//! For MMIO mode only; x2APIC uses a different register MSR interface.

pub const XAPIC_ID_OFFSET: usize = 0x20;
pub const XAPIC_VERSION_OFFSET: usize = 0x30;
pub const XAPIC_REGISTER_BYTES: usize = 4;
pub const XAPIC_PAGE_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XApicVersion {
    pub version: u8,
    pub max_lvt: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XApicError {
    BadVersion,
    InvalidId,
}

pub fn decode_id(raw: u32) -> u32 {
    // In xAPIC MMIO mode the APIC ID occupies bits 24..31.
    raw >> 24
}

pub fn decode_version(raw: u32) -> Result<XApicVersion, XApicError> {
    let version = (raw & 0xff) as u8;
    let max_lvt = ((raw >> 16) & 0xff) as u8;
    // Architectural xAPIC versions are >= 0x10. At least 3 LVT entries
    // (LINT0, LINT1, Error) must exist; we do not configure any of them.
    if version < 0x10 || max_lvt < 3 {
        return Err(XApicError::BadVersion);
    }
    Ok(XApicVersion { version, max_lvt })
}

pub fn verify_identity(raw_id: u32, expected: u32) -> Result<u32, XApicError> {
    let found = decode_id(raw_id);
    if found != expected || found > 255 {
        Err(XApicError::InvalidId)
    } else {
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_xapic_mmio_registers() {
        assert_eq!(decode_id(0x0300_0000), 3);
        assert_eq!(verify_identity(0x0300_0000, 3), Ok(3));
        assert_eq!(decode_version(0x0005_0014), Ok(XApicVersion { version: 0x14, max_lvt: 5 }));
    }

    #[test]
    fn reject_invalid_version_and_ids() {
        assert_eq!(decode_version(0x0000_0000), Err(XApicError::BadVersion));
        assert_eq!(decode_version(0x0001_0010), Err(XApicError::BadVersion));
        assert_eq!(verify_identity(0x0200_0000, 1), Err(XApicError::InvalidId));
        assert_eq!(verify_identity(0x0000_0000, 257), Err(XApicError::InvalidId));
    }

    #[test]
    fn registers_fit_entirely_inside_a_single_mmio_page() {
        assert!(XAPIC_ID_OFFSET + XAPIC_REGISTER_BYTES <= XAPIC_PAGE_BYTES);
        assert!(XAPIC_VERSION_OFFSET + XAPIC_REGISTER_BYTES <= XAPIC_PAGE_BYTES);
    }
}
