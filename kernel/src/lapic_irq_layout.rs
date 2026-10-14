//! Pure xAPIC interrupt acknowledgement register layout.
//! No MMIO, no EOI writes, no IRQ enablement.
pub const EOI_OFFSET: usize = 0xB0;
pub const SPURIOUS_VECTOR_OFFSET: usize = 0xF0;
pub const EOI_VALUE: u32 = 0;
pub const SOFTWARE_ENABLE: u32 = 1 << 8;
pub const SPURIOUS_VECTOR_MASK: u32 = 0xff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApicIrqError {
    InvalidSpuriousVector,
    VectorCollision,
}

/// xAPIC EOI is a write-only acknowledgement of value zero.
/// Only call from a real interrupt handler after correctly identifying the
/// interrupt source. Spurious interrupts must not be EOI-acknowledged.
pub const fn eoi_write() -> (usize, u32) {
    (EOI_OFFSET, EOI_VALUE)
}

/// Build a software-enabled SVR, preserving other architecturally managed
/// bits from a previously read register. Does not write the register.
pub fn enabled_svr(current: u32, spurious_vector: u8, timer_vector: u8)
    -> Result<u32, ApicIrqError>
{
    if spurious_vector < 0x20 {
        return Err(ApicIrqError::InvalidSpuriousVector);
    }
    if spurious_vector == timer_vector {
        return Err(ApicIrqError::VectorCollision);
    }
    Ok((current & !SPURIOUS_VECTOR_MASK)
        | u32::from(spurious_vector) | SOFTWARE_ENABLE)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn eoi_layout_is_valid() {
        assert_eq!(eoi_write(), (0xB0, 0));
        assert_eq!(EOI_OFFSET % 16, 0);
        assert!(EOI_OFFSET + 4 <= 4096);
    }
    #[test]
    fn software_enable_preserves_unrelated_bits() {
        assert_eq!(enabled_svr(0x1000, 0xff, 0xe0), Ok(0x11ff));
        assert_eq!(enabled_svr(0, 0xff, 0xff), Err(ApicIrqError::VectorCollision));
        assert_eq!(enabled_svr(0, 0x1f, 0xe0), Err(ApicIrqError::InvalidSpuriousVector));
    }
}
