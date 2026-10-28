//! Read-only PCI BAR type and assignment proof for VirtIO GPU capabilities.
//! This does not discover BAR aperture sizes, map MMIO or perform any device
//! configuration writes. The parsed bases are never returned to kernel users.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarKind { Io, Memory32, Memory64 }
impl BarKind {
    pub const fn label(self) -> &'static str {
        match self { Self::Io => "io", Self::Memory32 => "mem32", Self::Memory64 => "mem64" }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarError {
    MissingBar, UpperHalf64, UnsupportedType, UnassignedAddress,
    OutOfRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BarSlot { Empty, UpperHalf64, Invalid(BarError), Ready(BarKind) }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BarProof {
    pub common: BarKind,
    pub notify: BarKind,
    pub isr: BarKind,
    pub device: BarKind,
}

fn le32(cfg: &[u8; 256], pos: usize) -> u32 {
    u32::from_le_bytes([cfg[pos], cfg[pos+1], cfg[pos+2], cfg[pos+3]])
}

/// Verify that each of the four already-validated VirtIO capability BAR
/// numbers names an *assigned* I/O or memory BAR, not the high half of a
/// 64-bit pair.  PCI resource sizes are unknowable without BAR probing
/// writes, so the caller MUST NOT treat this proof as mapping authorization.
pub fn inspect(cfg: &[u8; 256], referenced: [u8; 4]) -> Result<BarProof, BarError> {
    let mut slots = [BarSlot::Empty; 6];
    let mut i = 0usize;
    while i < 6 {
        let low = le32(cfg, 0x10 + 4*i);
        if low == 0 {
            i += 1;
            continue;
        }
        if low & 1 == 1 {
            let base = low & !3;
            slots[i] = if base == 0 {
                BarSlot::Invalid(BarError::UnassignedAddress)
            } else {
                BarSlot::Ready(BarKind::Io)
            };
            i += 1;
            continue;
        }
        let kind = (low >> 1) & 3;
        match kind {
            0 => {
                slots[i] = if low & !15 == 0 {
                    BarSlot::Invalid(BarError::UnassignedAddress)
                } else {
                    BarSlot::Ready(BarKind::Memory32)
                };
                i += 1;
            }
            2 => {
                if i == 5 {
                    slots[i] = BarSlot::Invalid(BarError::OutOfRange);
                    i += 1;
                    continue;
                }
                let high = le32(cfg, 0x10 + 4*(i+1));
                let base = (u64::from(high) << 32) | u64::from(low & !15);
                slots[i] = if base == 0 {
                    BarSlot::Invalid(BarError::UnassignedAddress)
                } else {
                    BarSlot::Ready(BarKind::Memory64)
                };
                slots[i+1] = BarSlot::UpperHalf64;
                i += 2;
            }
            _ => {
                slots[i] = BarSlot::Invalid(BarError::UnsupportedType);
                i += 1;
            }
        }
    }

    let mut selected = [BarKind::Memory32; 4];
    for (ix, bar) in referenced.iter().enumerate() {
        let entry = slots.get(usize::from(*bar)).ok_or(BarError::OutOfRange)?;
        selected[ix] = match *entry {
            BarSlot::Ready(kind) => kind,
            BarSlot::UpperHalf64 => return Err(BarError::UpperHalf64),
            BarSlot::Empty => return Err(BarError::MissingBar),
            BarSlot::Invalid(e) => return Err(e),
        };
    }
    Ok(BarProof {
        common:selected[0], notify:selected[1], isr:selected[2], device:selected[3],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn cfg()->[u8;256] {
        let mut c=[0u8;256];
        let values=[0x8000_1000u32,0x0000_c001,0x9000_0004,1,
                    0xf000_0000,0x0000_d001];
        for (i,value) in values.iter().enumerate() {
            c[0x10+4*i..0x14+4*i].copy_from_slice(&value.to_le_bytes());
        }
        c
    }
    #[test]
    fn recognizes_mixed_io_memory32_and_memory64() {
        let p=inspect(&cfg(),[0,1,2,4]).unwrap();
        assert_eq!((p.common,p.notify,p.isr,p.device),
                   (BarKind::Memory32,BarKind::Io,BarKind::Memory64,BarKind::Memory32));
        assert_eq!(p.isr.label(),"mem64");
    }
    #[test]
    fn repeated_references_are_legal() {
        assert_eq!(inspect(&cfg(),[4,4,4,4]).unwrap().notify,BarKind::Memory32);
    }
    #[test]
    fn rejects_referencing_the_upper_half_of_mem64() {
        assert_eq!(inspect(&cfg(),[3,4,4,4]),Err(BarError::UpperHalf64));
    }
    #[test]
    fn rejects_missing_referenced_bar() {
        let mut c=cfg();c[0x10..0x14].fill(0);
        assert_eq!(inspect(&c,[0,1,2,4]),Err(BarError::MissingBar));
    }
    #[test]
    fn rejects_reserved_memory_bar_kind() {
        let mut c=cfg();c[0x10..0x14].copy_from_slice(&0x8000_1002u32.to_le_bytes());
        assert_eq!(inspect(&c,[0,1,2,4]),Err(BarError::UnsupportedType));
    }
    #[test]
    fn rejects_unassigned_io_bar_even_if_io_bit_set() {
        let mut c=cfg();c[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(inspect(&c,[1,0,2,4]),Err(BarError::UnassignedAddress));
    }
    #[test]
    fn rejects_unassigned_memory64_base() {
        let mut c=cfg();c[0x18..0x1c].copy_from_slice(&4u32.to_le_bytes());
        c[0x1c..0x20].fill(0);
        assert_eq!(inspect(&c,[2,0,1,4]),Err(BarError::UnassignedAddress));
    }
    #[test]
    fn high_part_nonzero_can_assign_memory64_base() {
        let mut c=cfg();c[0x18..0x1c].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(inspect(&c,[2,0,1,4]).unwrap().common,BarKind::Memory64);
    }
    #[test]
    fn rejects_64bit_bar_in_final_slot() {
        let mut c=cfg();c[0x24..0x28].copy_from_slice(&0x0000_d004u32.to_le_bytes());
        assert_eq!(inspect(&c,[5,0,2,4]),Err(BarError::OutOfRange));
    }
    #[test]
    fn ignores_unused_invalid_bar_without_claiming_it_valid() {
        let mut c=cfg();c[0x10..0x14].copy_from_slice(&0x8000_1006u32.to_le_bytes());
        assert!(inspect(&c,[1,2,4,5]).is_ok());
    }
    #[test]
    fn rejects_out_of_range_referenced_bar() {
        assert_eq!(inspect(&cfg(),[6,1,2,4]),Err(BarError::OutOfRange));
    }
}
