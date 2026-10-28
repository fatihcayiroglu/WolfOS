//! BAR aperture sizing arithmetic and region containment for QEMU-only tests.
//! Pure functions here never touch PCI config, map MMIO, allocate DMA or
//! authorize a real device driver; caller must restore all probe writes.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BarKind { Io, Memory32, Memory64 }
impl BarKind {
    pub const fn label(self) -> &'static str {
        match self { Self::Io=>"io", Self::Memory32=>"mem32", Self::Memory64=>"mem64" }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeError { BadType, BadSize, BadAlignment, OutsideAperture, Overflow }

pub fn aperture_size(
    kind: BarKind, low_readback: u32, high_readback: u32,
) -> Result<u64, ProbeError> {
    let bytes=match kind {
        BarKind::Io => {
            if low_readback & 1 != 1 { return Err(ProbeError::BadType); }
            u64::from((!(low_readback & !3)).wrapping_add(1))
        }
        BarKind::Memory32 => {
            if low_readback & 7 != 0 { return Err(ProbeError::BadType); }
            u64::from((!(low_readback & !15)).wrapping_add(1))
        }
        BarKind::Memory64 => {
            if low_readback & 7 != 4 { return Err(ProbeError::BadType); }
            let masked=(u64::from(high_readback) << 32)
                | u64::from(low_readback & !15);
            (!masked).wrapping_add(1)
        }
    };
    if bytes==0 || !bytes.is_power_of_two() {
        return Err(ProbeError::BadSize);
    }
    Ok(bytes)
}

/// A measured BAR size is usable only when the firmware-assigned base is
/// naturally aligned and the selected vendor capability lies entirely in it.
pub fn validate_window(
    base: u64, bytes: u64, offset: u32, len: u32,
) -> Result<(), ProbeError> {
    if base==0 || bytes==0 || !bytes.is_power_of_two() {
        return Err(ProbeError::BadSize);
    }
    if base % bytes != 0 { return Err(ProbeError::BadAlignment); }
    let end=base.checked_add(bytes).ok_or(ProbeError::Overflow)?;
    let start=base.checked_add(u64::from(offset)).ok_or(ProbeError::Overflow)?;
    let cap_end=start.checked_add(u64::from(len)).ok_or(ProbeError::Overflow)?;
    if len==0 || cap_end>end { return Err(ProbeError::OutsideAperture); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decode_io_mask() {
        assert_eq!(aperture_size(BarKind::Io,0xffff_ff01,0),Ok(256));
    }
    #[test]
    fn decode_memory32_mask() {
        assert_eq!(aperture_size(BarKind::Memory32,0xffff_0000,0),Ok(65536));
    }
    #[test]
    fn decode_memory64_above_4g() {
        assert_eq!(aperture_size(BarKind::Memory64,0xfff0_0004,0xffff_ffff),Ok(0x100000));
    }
    #[test]
    fn refuse_wrong_kind_masks() {
        assert_eq!(aperture_size(BarKind::Io,0xffff_fff0,0),Err(ProbeError::BadType));
        assert_eq!(aperture_size(BarKind::Memory32,0xffff_fff5,0),Err(ProbeError::BadType));
        assert_eq!(aperture_size(BarKind::Memory64,0xffff_fff0,0xffff_ffff),Err(ProbeError::BadType));
    }
    #[test]
    fn refuse_zero_or_nonpower_of_two_size() {
        assert_eq!(aperture_size(BarKind::Memory32,0,0),Err(ProbeError::BadSize));
        assert_eq!(aperture_size(BarKind::Memory32,0xffff_ff20,0),Err(ProbeError::BadSize));
    }
    #[test]
    fn accept_exact_capability_bound() {
        assert_eq!(validate_window(0x8000_0000,0x1000,0xf00,0x100),Ok(()));
    }
    #[test]
    fn refuse_capability_beyond_aperture() {
        assert_eq!(validate_window(0x8000_0000,0x1000,0xf00,0x101),Err(ProbeError::OutsideAperture));
    }
    #[test]
    fn refuse_unaligned_firmware_base() {
        assert_eq!(validate_window(0x8000_0100,0x1000,0,56),Err(ProbeError::BadAlignment));
    }
    #[test]
    fn refuse_zero_length_or_size() {
        assert_eq!(validate_window(0x8000_0000,0x1000,0,0),Err(ProbeError::OutsideAperture));
        assert_eq!(validate_window(0x8000_0000,0,0,56),Err(ProbeError::BadSize));
    }
    #[test]
    fn refuse_span_or_base_overflow() {
        assert_eq!(validate_window(u64::MAX-0xffe,0x1000,0,56),Err(ProbeError::BadAlignment));
        assert_eq!(validate_window(u64::MAX-0x1fff,0x1000,0x2000,56),Err(ProbeError::Overflow));
    }
    #[test]
    fn reject_unassigned_bar() {
        assert_eq!(validate_window(0,0x1000,0,56),Err(ProbeError::BadSize));
    }
}
