//! Pure ACPI SDT/RSDT/XSDT/MADT parsing; no_std and host-testable.
//! Firmware-provided lengths, alignment and checksums are never trusted.

pub const SDT_HEADER_LEN: usize = 36;
pub const MADT_FIXED_LEN: usize = SDT_HEADER_LEN + 8;
pub const MAX_SDT_LENGTH: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableError {
    TooShort,
    InvalidLength,
    BadChecksum,
    WrongSignature,
    InvalidRootEntries,
    InvalidMadtEntry,
}

pub struct Sdt<'a> {
    pub signature: [u8; 4],
    pub bytes: &'a [u8],
}

pub fn sdt_length(header: &[u8]) -> Result<usize, TableError> {
    if header.len() < SDT_HEADER_LEN { return Err(TableError::TooShort); }
    let length = u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize;
    if !(SDT_HEADER_LEN..=MAX_SDT_LENGTH).contains(&length) {
        return Err(TableError::InvalidLength);
    }
    Ok(length)
}

pub fn parse_sdt(bytes: &[u8]) -> Result<Sdt<'_>, TableError> {
    let length = sdt_length(bytes)?;
    if bytes.len() < length { return Err(TableError::TooShort); }
    let bytes = &bytes[..length];
    if !crate_checksum(bytes) { return Err(TableError::BadChecksum); }
    Ok(Sdt { signature: bytes[0..4].try_into().unwrap(), bytes })
}

fn crate_checksum(bytes: &[u8]) -> bool {
    bytes.iter().fold(0_u8, |a, &b| a.wrapping_add(b)) == 0
}

pub struct RootTable<'a> {
    bytes: &'a [u8],
    stride: usize,
}
impl<'a> RootTable<'a> {
    pub fn parse(table: &'a Sdt<'a>) -> Result<Self, TableError> {
        let stride = match &table.signature {
            b"XSDT" => 8,
            b"RSDT" => 4,
            _ => return Err(TableError::WrongSignature),
        };
        if (table.bytes.len() - SDT_HEADER_LEN) % stride != 0 {
            return Err(TableError::InvalidRootEntries);
        }
        Ok(Self { bytes: &table.bytes[SDT_HEADER_LEN..], stride })
    }
    pub fn len(&self) -> usize { self.bytes.len() / self.stride }
    pub fn physical_at(&self, index: usize) -> Option<u64> {
        let start = index.checked_mul(self.stride)?;
        let entry = self.bytes.get(start..start+self.stride)?;
        Some(if self.stride == 8 {
            u64::from_le_bytes(entry.try_into().ok()?)
        } else {
            u32::from_le_bytes(entry.try_into().ok()?) as u64
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MadtSummary {
    pub local_apic_phys: u32,
    pub flags: u32,
    pub enabled_lapic: usize,
    pub enabled_x2apic: usize,
    pub online_capable: usize,
    pub io_apics: usize,
    pub entries: usize,
}

pub fn parse_madt(table: &Sdt<'_>) -> Result<MadtSummary, TableError> {
    if table.signature != *b"APIC" { return Err(TableError::WrongSignature); }
    let bytes = table.bytes;
    if bytes.len() < MADT_FIXED_LEN { return Err(TableError::TooShort); }
    let mut summary = MadtSummary {
        local_apic_phys: u32::from_le_bytes(bytes[36..40].try_into().unwrap()),
        flags: u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
        enabled_lapic: 0, enabled_x2apic: 0, online_capable: 0,
        io_apics: 0, entries: 0,
    };
    let mut cursor = MADT_FIXED_LEN;
    while cursor < bytes.len() {
        if bytes.len() - cursor < 2 { return Err(TableError::InvalidMadtEntry); }
        let kind = bytes[cursor];
        let length = bytes[cursor+1] as usize;
        if length < 2 || length > bytes.len() - cursor {
            return Err(TableError::InvalidMadtEntry);
        }
        let entry = &bytes[cursor..cursor+length];
        match kind {
            0 => {
                if length < 8 { return Err(TableError::InvalidMadtEntry); }
                let flags = u32::from_le_bytes(entry[4..8].try_into().unwrap());
                if flags & 1 != 0 { summary.enabled_lapic += 1; }
                else if flags & 2 != 0 { summary.online_capable += 1; }
            }
            1 => {
                if length < 12 { return Err(TableError::InvalidMadtEntry); }
                summary.io_apics += 1;
            }
            9 => {
                if length < 16 { return Err(TableError::InvalidMadtEntry); }
                let flags = u32::from_le_bytes(entry[8..12].try_into().unwrap());
                if flags & 1 != 0 { summary.enabled_x2apic += 1; }
                else if flags & 2 != 0 { summary.online_capable += 1; }
            }
            _ => {} // Unknown ACPI subtable types are forward-compatible.
        }
        summary.entries += 1;
        cursor += length;
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn checksum(table: &mut [u8]) {
        table[9] = 0;
        let sum = table.iter().fold(0_u8, |a, &b| a.wrapping_add(b));
        table[9] = 0_u8.wrapping_sub(sum);
    }
    fn sdt(signature: &[u8; 4], length: usize) -> [u8; 128] {
        let mut bytes = [0_u8; 128];
        bytes[0..4].copy_from_slice(signature);
        bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        checksum(&mut bytes[..length]);
        bytes
    }
    #[test]
    fn rsdt_and_xsdt_root_entries() {
        let mut x = sdt(b"XSDT", 52);
        x[36..44].copy_from_slice(&0x1_0000_9000u64.to_le_bytes());
        x[44..52].copy_from_slice(&0x00f0_0000u64.to_le_bytes());
        checksum(&mut x[..52]);
        let table = parse_sdt(&x).unwrap();
        let root = RootTable::parse(&table).unwrap();
        assert_eq!(root.len(), 2);
        assert_eq!(root.physical_at(0), Some(0x1_0000_9000));
        assert_eq!(root.physical_at(1), Some(0xf0_0000));
        assert_eq!(root.physical_at(2), None);
        let mut r = sdt(b"RSDT", 40);
        r[36..40].copy_from_slice(&0xabcd_4000u32.to_le_bytes());
        checksum(&mut r[..40]);
        let t = parse_sdt(&r).unwrap();
        assert_eq!(RootTable::parse(&t).unwrap().physical_at(0), Some(0xabcd_4000));
    }
    #[test]
    fn madt_counts_enabled_cpu_and_io_apic() {
        let mut m = sdt(b"APIC", 44+8+12+16);
        m[36..40].copy_from_slice(&0xfee0_0000u32.to_le_bytes());
        m[44..52].copy_from_slice(&[0,8,0,1,1,0,0,0]);
        m[52..64].copy_from_slice(&[1,12,2,0,0,0,0xc0,0xfe,0,0,0,0]);
        m[64..80].copy_from_slice(&[9,16,0,0,1,0,0,0,1,0,0,0,2,0,0,0]);
        checksum(&mut m[..80]);
        let table = parse_sdt(&m).unwrap();
        let info = parse_madt(&table).unwrap();
        assert_eq!(info.enabled_lapic, 1);
        assert_eq!(info.enabled_x2apic, 1);
        assert_eq!(info.io_apics, 1);
        assert_eq!(info.entries, 3);
    }
    #[test]
    fn rejects_corruption_and_zero_length_records() {
        let mut x = sdt(b"XSDT", 44);
        x[36] = 7;
        assert_eq!(parse_sdt(&x).err(), Some(TableError::BadChecksum));
        let invalid_root = sdt(b"XSDT", 41);
        let table = parse_sdt(&invalid_root).unwrap();
        assert!(matches!(RootTable::parse(&table), Err(TableError::InvalidRootEntries)));
        let mut m = sdt(b"APIC", 46);
        m[44..46].copy_from_slice(&[0, 0]);
        checksum(&mut m[..46]);
        let table = parse_sdt(&m).unwrap();
        assert_eq!(parse_madt(&table), Err(TableError::InvalidMadtEntry));
        assert_eq!(sdt_length(&[0; 8]), Err(TableError::TooShort));
    }
}
