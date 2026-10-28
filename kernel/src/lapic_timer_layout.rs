//! xAPIC local timer register layout and encode/decode validation.
//! Pure no_std data model: absolutely no APIC MMIO writes or IRQ enabling.
//! Used to constrain future BSP-only timer programming code.

pub const LVT_TIMER_OFFSET: usize = 0x320;
pub const INITIAL_COUNT_OFFSET: usize = 0x380;
pub const CURRENT_COUNT_OFFSET: usize = 0x390;
pub const DIVIDE_CONFIG_OFFSET: usize = 0x3e0;
pub const APIC_REGISTER_BYTES: usize = 4;
pub const APIC_PAGE_BYTES: usize = 4096;

pub const LVT_VECTOR_MASK: u32 = 0xff;
pub const LVT_DELIVERY_STATUS: u32 = 1 << 12;
pub const LVT_MASKED: u32 = 1 << 16;
pub const LVT_MODE_MASK: u32 = 0b11 << 17;
pub const LVT_RESERVED_MASK: u32 = !(
    LVT_VECTOR_MASK | LVT_DELIVERY_STATUS | LVT_MASKED | LVT_MODE_MASK
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerMode {
    OneShot,
    Periodic,
    TscDeadline,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerLvt {
    pub vector: u8,
    pub masked: bool,
    pub delivery_pending: bool,
    pub mode: TimerMode,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerError {
    InvalidVector,
    ReservedBits,
    InvalidMode,
    ZeroInitialCount,
    InvalidDivisor,
}

/// The vector must be in the 0x20..0xfe external interrupt range. 0xff is
/// conventionally the APIC spurious vector and is intentionally excluded.
pub fn make_lvt(vector: u8, masked: bool, mode: TimerMode) -> Result<u32, TimerError> {
    if !(0x20..=0xfe).contains(&vector) {
        return Err(TimerError::InvalidVector);
    }
    let bits = match mode {
        TimerMode::OneShot => 0,
        TimerMode::Periodic => 1 << 17,
        TimerMode::TscDeadline => 2 << 17,
    };
    Ok(vector as u32 | bits | if masked { LVT_MASKED } else { 0 })
}

/// Decode hardware status, including the read-only delivery-status bit.
pub fn parse_lvt(raw: u32) -> Result<TimerLvt, TimerError> {
    if raw & LVT_RESERVED_MASK != 0 {
        return Err(TimerError::ReservedBits);
    }
    let vector = (raw & LVT_VECTOR_MASK) as u8;
    if !(0x20..=0xfe).contains(&vector) {
        return Err(TimerError::InvalidVector);
    }
    let mode = match (raw & LVT_MODE_MASK) >> 17 {
        0 => TimerMode::OneShot,
        1 => TimerMode::Periodic,
        2 => TimerMode::TscDeadline,
        _ => return Err(TimerError::InvalidMode),
    };
    Ok(TimerLvt {
        vector,
        masked: raw & LVT_MASKED != 0,
        delivery_pending: raw & LVT_DELIVERY_STATUS != 0,
        mode,
    })
}

/// xAPIC divisor encoding is permuted: bits (3,1,0) encode 1..128.
/// In particular /1 is 0b1011 and /2 is 0b0000.
pub fn encode_divisor(divisor: u32) -> Result<u32, TimerError> {
    let code = match divisor {
        1 => 0b1011,
        2 => 0b0000,
        4 => 0b0001,
        8 => 0b0010,
        16 => 0b0011,
        32 => 0b1000,
        64 => 0b1001,
        128 => 0b1010,
        _ => return Err(TimerError::InvalidDivisor),
    };
    Ok(code)
}

pub fn decode_divisor(raw: u32) -> Result<u32, TimerError> {
    if raw & !0b1011 != 0 {
        return Err(TimerError::ReservedBits);
    }
    match raw {
        0b1011 => Ok(1),
        0b0000 => Ok(2),
        0b0001 => Ok(4),
        0b0010 => Ok(8),
        0b0011 => Ok(16),
        0b1000 => Ok(32),
        0b1001 => Ok(64),
        0b1010 => Ok(128),
        _ => Err(TimerError::InvalidDivisor),
    }
}

pub fn validate_initial_count(count: u32) -> Result<u32, TimerError> {
    if count == 0 { Err(TimerError::ZeroInitialCount) } else { Ok(count) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registers_are_32_bit_aligned_and_within_single_apic_page() {
        for offset in [LVT_TIMER_OFFSET, INITIAL_COUNT_OFFSET,
                       CURRENT_COUNT_OFFSET, DIVIDE_CONFIG_OFFSET] {
            assert_eq!(offset % 16, 0);
            assert!(offset + APIC_REGISTER_BYTES <= APIC_PAGE_BYTES);
        }
    }
    #[test]
    fn timer_lvt_modes_mask_and_delivery_status() {
        for mode in [TimerMode::OneShot, TimerMode::Periodic, TimerMode::TscDeadline] {
            for masked in [true, false] {
                let bits = make_lvt(0xe0, masked, mode).unwrap();
                let decoded = parse_lvt(bits).unwrap();
                assert_eq!(decoded.mode, mode);
                assert_eq!(decoded.masked, masked);
                assert_eq!(decoded.vector, 0xe0);
                assert!(!decoded.delivery_pending);
                assert!(parse_lvt(bits | LVT_DELIVERY_STATUS).unwrap().delivery_pending);
            }
        }
    }
    #[test]
    fn reject_reserved_modes_vectors_and_bits() {
        for vector in [0, 1, 31, 255] {
            assert_eq!(make_lvt(vector, true, TimerMode::OneShot),
                Err(TimerError::InvalidVector));
        }
        assert_eq!(parse_lvt(0x20 | (3 << 17)), Err(TimerError::InvalidMode));
        assert_eq!(parse_lvt(0x20 | (1 << 31)), Err(TimerError::ReservedBits));
        assert_eq!(validate_initial_count(0), Err(TimerError::ZeroInitialCount));
        assert_eq!(validate_initial_count(1), Ok(1));
    }
    #[test]
    fn divisor_roundtrip_all_supported_factors() {
        for divisor in [1, 2, 4, 8, 16, 32, 64, 128] {
            let encoded = encode_divisor(divisor).unwrap();
            assert_eq!(decode_divisor(encoded), Ok(divisor));
        }
        for bad in [0, 3, 5, 256] {
            assert_eq!(encode_divisor(bad), Err(TimerError::InvalidDivisor));
        }
        assert_eq!(decode_divisor(0b0100), Err(TimerError::ReservedBits));
        assert_eq!(decode_divisor(0b1100), Err(TimerError::ReservedBits));
    }
}
