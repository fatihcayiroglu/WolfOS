//! ACPI Root System Description Pointer (RSDP) validation.
//! Pure no_std parser, also compiled as a host Rust unit-test binary.
//! RSDT/XSDT and MADT enumeration are deliberately out of scope for P1.7.

pub const MIN_RSDP_SIZE: usize = 20;
pub const ACPI_V2_RSDP_SIZE: usize = 36;
pub const MAX_RSDP_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RsdpError {
    ShortBuffer,
    WrongSignature,
    BadChecksum,
    InvalidLength,
    BadExtendedChecksum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RsdpInfo {
    pub revision: u8,
    pub oem_id: [u8; 6],
    pub rsdt_physical: u32,
    pub xsdt_physical: Option<u64>,
    pub length: usize,
}

pub fn sum_is_zero(bytes: &[u8]) -> bool {
    bytes.iter().fold(0_u8, |sum, &byte| sum.wrapping_add(byte)) == 0
}

pub fn parse_rsdp(bytes: &[u8]) -> Result<RsdpInfo, RsdpError> {
    if bytes.len() < MIN_RSDP_SIZE { return Err(RsdpError::ShortBuffer); }
    if &bytes[..8] != b"RSD PTR " { return Err(RsdpError::WrongSignature); }
    if !sum_is_zero(&bytes[..MIN_RSDP_SIZE]) {
        return Err(RsdpError::BadChecksum);
    }
    let oem_id: [u8; 6] = bytes[9..15].try_into()
        .map_err(|_| RsdpError::ShortBuffer)?;
    let revision = bytes[15];
    let rsdt_physical = u32::from_le_bytes(bytes[16..20].try_into().unwrap());

    if revision < 2 {
        return Ok(RsdpInfo {
            revision, oem_id, rsdt_physical, xsdt_physical: None,
            length: MIN_RSDP_SIZE,
        });
    }
    if bytes.len() < ACPI_V2_RSDP_SIZE { return Err(RsdpError::ShortBuffer); }
    let length = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
    if !(ACPI_V2_RSDP_SIZE..=MAX_RSDP_SIZE).contains(&length) {
        return Err(RsdpError::InvalidLength);
    }
    if bytes.len() < length { return Err(RsdpError::ShortBuffer); }
    if !sum_is_zero(&bytes[..length]) { return Err(RsdpError::BadExtendedChecksum); }
    let xsdt_physical = u64::from_le_bytes(bytes[24..32].try_into().unwrap());

    Ok(RsdpInfo {
        revision, oem_id, rsdt_physical,
        xsdt_physical: Some(xsdt_physical), length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_checksum(bytes: &mut [u8], at: usize) {
        bytes[at] = 0;
        let sum = bytes.iter().fold(0_u8, |s, &b| s.wrapping_add(b));
        bytes[at] = 0_u8.wrapping_sub(sum);
    }

    fn example_v1() -> [u8; 20] {
        let mut b = [0_u8; 20];
        b[..8].copy_from_slice(b"RSD PTR ");
        b[9..15].copy_from_slice(b"WOLFOS");
        b[16..20].copy_from_slice(&0x1234_5000u32.to_le_bytes());
        set_checksum(&mut b, 8);
        b
    }

    #[test]
    fn validates_acpi_v1_and_checksums() {
        let mut b = example_v1();
        let parsed = parse_rsdp(&b).unwrap();
        assert_eq!(parsed.revision, 0);
        assert_eq!(parsed.oem_id, *b"WOLFOS");
        assert_eq!(parsed.rsdt_physical, 0x1234_5000);
        assert_eq!(parsed.xsdt_physical, None);
        b[10] ^= 1;
        assert_eq!(parse_rsdp(&b), Err(RsdpError::BadChecksum));
        b[0] ^= 1;
        assert_eq!(parse_rsdp(&b), Err(RsdpError::WrongSignature));
    }

    #[test]
    fn validates_acpi_v2_extended_checksum() {
        let mut b = [0_u8; 36];
        b[..20].copy_from_slice(&example_v1());
        b[15] = 2;
        set_checksum(&mut b[..20], 8);
        b[20..24].copy_from_slice(&(36_u32).to_le_bytes());
        b[24..32].copy_from_slice(&0x1_2345_6000_u64.to_le_bytes());
        set_checksum(&mut b, 32);
        let parsed = parse_rsdp(&b).unwrap();
        assert_eq!(parsed.length, 36);
        assert_eq!(parsed.xsdt_physical, Some(0x1_2345_6000_u64));
        b[26] ^= 0x80;
        assert_eq!(parse_rsdp(&b), Err(RsdpError::BadExtendedChecksum));
    }

    #[test]
    fn rejects_bad_lengths_and_short_buffers() {
        assert_eq!(parse_rsdp(&[]), Err(RsdpError::ShortBuffer));
        let mut b = [0_u8; 36];
        b[..20].copy_from_slice(&example_v1());
        b[15] = 2;
        set_checksum(&mut b[..20], 8);
        b[20..24].copy_from_slice(&(33_u32).to_le_bytes());
        assert_eq!(parse_rsdp(&b), Err(RsdpError::InvalidLength));
        b[20..24].copy_from_slice(&(5000_u32).to_le_bytes());
        assert_eq!(parse_rsdp(&b), Err(RsdpError::InvalidLength));
    }
}
