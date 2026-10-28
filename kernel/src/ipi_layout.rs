//! Pure xAPIC fixed-delivery physical-target IPI register encoding.
//! No MMIO operations and no IRQ enablement happen in this module.

pub const ICR_LOW_OFFSET: usize = 0x300;
pub const ICR_HIGH_OFFSET: usize = 0x310;
pub const APIC_ID_OFFSET: usize = 0x20;
pub const DELIVERY_PENDING: u32 = 1 << 12;
const VECTOR_MIN: u8 = 0x20;
const VECTOR_MAX: u8 = 0xfe;
const TARGET_MAX: u32 = 0xff;
const ICR_DEST_SHIFT: u32 = 24;
pub const AP_IPI_VECTOR: u8 = 0xe1;
pub const SPURIOUS_VECTOR: u8 = 0xff;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpiError {
    InvalidVector,
    InvalidTarget,
    TargetIsSelf,
    DeliveryStillPending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedIpi {
    pub high: u32,
    pub low: u32,
}

/// Physical destination ID, fixed-delivery, edge-triggered, assert,
/// no destination shorthand. x2APIC destinations are NOT supported.
pub fn directed_fixed_ipi(
    sender_id: u32, target_id: u32, vector: u8, icr_low_snapshot: u32,
) -> Result<FixedIpi, IpiError> {
    if !(VECTOR_MIN..=VECTOR_MAX).contains(&vector) || vector == SPURIOUS_VECTOR {
        return Err(IpiError::InvalidVector);
    }
    if sender_id > TARGET_MAX || target_id > TARGET_MAX {
        return Err(IpiError::InvalidTarget);
    }
    if target_id == sender_id {
        return Err(IpiError::TargetIsSelf);
    }
    if icr_low_snapshot & DELIVERY_PENDING != 0 {
        return Err(IpiError::DeliveryStillPending);
    }
    Ok(FixedIpi {
        high: target_id << ICR_DEST_SHIFT,
        low: u32::from(vector),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_offsets_are_xapic_aligned_and_in_single_page() {
        for off in [ICR_LOW_OFFSET, ICR_HIGH_OFFSET, APIC_ID_OFFSET] {
            assert_eq!(off % 16, 0);
            assert!(off + 4 <= 4096);
        }
    }

    #[test]
    fn physical_fixed_ipi_has_no_shorthand_or_level_or_delivery_mode_bits() {
        let p = directed_fixed_ipi(0, 3, AP_IPI_VECTOR, 0).unwrap();
        assert_eq!(p.high, 3 << 24);
        assert_eq!(p.low, 0xe1);
        assert_eq!(p.low & !0xff, 0);
        let p = directed_fixed_ipi(255, 0, 0x20, 0).unwrap();
        assert_eq!(p.high, 0);
        assert_eq!(p.low, 0x20);
    }

    #[test]
    fn invalid_vector_target_and_pending_are_rejected() {
        assert_eq!(directed_fixed_ipi(0, 1, 0x1f, 0), Err(IpiError::InvalidVector));
        assert_eq!(directed_fixed_ipi(0, 1, 0xff, 0), Err(IpiError::InvalidVector));
        assert_eq!(directed_fixed_ipi(0, 256, 0xe1, 0), Err(IpiError::InvalidTarget));
        assert_eq!(directed_fixed_ipi(257, 1, 0xe1, 0), Err(IpiError::InvalidTarget));
        assert_eq!(directed_fixed_ipi(3, 3, 0xe1, 0), Err(IpiError::TargetIsSelf));
        assert_eq!(directed_fixed_ipi(0, 3, 0xe1, DELIVERY_PENDING),
                   Err(IpiError::DeliveryStillPending));
    }
}
