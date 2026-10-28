//! Pure integer arithmetic for future BSP xAPIC timer calibration.
//! No hardware access, no IRQ activation, no assumption of a fixed APIC clock.
//! Input "elapsed_apic_ticks" is the measured decrement at a chosen divider.
//! Calibrate against an independently verified reference clock.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CalibrationError {
    ZeroReferenceFrequency,
    ZeroReferenceTicks,
    ZeroApicTicks,
    ZeroTargetFrequency,
    TargetTooFast,
    CountOverflow,
    ArithmeticOverflow,
}

/// Estimate the effective local APIC timer tick frequency for the selected
/// divider. Floor division is conservative; caller must supply an actual
/// measured interval and account for drift and reference-clock accuracy.
pub fn effective_ticks_per_second(
    elapsed_apic_ticks: u32,
    elapsed_reference_ticks: u64,
    reference_hz: u64,
) -> Result<u64, CalibrationError> {
    if reference_hz == 0 {
        return Err(CalibrationError::ZeroReferenceFrequency);
    }
    if elapsed_reference_ticks == 0 {
        return Err(CalibrationError::ZeroReferenceTicks);
    }
    if elapsed_apic_ticks == 0 {
        return Err(CalibrationError::ZeroApicTicks);
    }
    let numerator = u128::from(elapsed_apic_ticks)
        .checked_mul(u128::from(reference_hz))
        .ok_or(CalibrationError::ArithmeticOverflow)?;
    let result = numerator / u128::from(elapsed_reference_ticks);
    if result == 0 {
        return Err(CalibrationError::TargetTooFast);
    }
    u64::try_from(result).map_err(|_| CalibrationError::ArithmeticOverflow)
}

/// Choose a nonzero 32-bit initial count for a desired periodic IRQ rate.
/// Rounded to the nearest tick, with an explicit failure instead of clamping.
pub fn periodic_initial_count(
    effective_hz: u64,
    target_interrupt_hz: u32,
) -> Result<u32, CalibrationError> {
    if effective_hz == 0 {
        return Err(CalibrationError::ZeroApicTicks);
    }
    if target_interrupt_hz == 0 {
        return Err(CalibrationError::ZeroTargetFrequency);
    }
    let divisor = u64::from(target_interrupt_hz);
    let rounded = effective_hz / divisor
        + u64::from(effective_hz % divisor >= (divisor / 2 + divisor % 2));
    if rounded == 0 {
        return Err(CalibrationError::TargetTooFast);
    }
    u32::try_from(rounded).map_err(|_| CalibrationError::CountOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calibrated_100_mhz_effective_clock() {
        assert_eq!(effective_ticks_per_second(10_000_000, 10_000_000, 100_000_000), Ok(100_000_000));
        assert_eq!(periodic_initial_count(100_000_000, 100), Ok(1_000_000));
        assert_eq!(periodic_initial_count(100_000_000, 1000), Ok(100_000));
    }

    #[test]
    fn calibration_rejects_missing_reference_or_no_decrement() {
        assert_eq!(effective_ticks_per_second(1, 1, 0), Err(CalibrationError::ZeroReferenceFrequency));
        assert_eq!(effective_ticks_per_second(1, 0, 1), Err(CalibrationError::ZeroReferenceTicks));
        assert_eq!(effective_ticks_per_second(0, 1, 1), Err(CalibrationError::ZeroApicTicks));
        assert_eq!(effective_ticks_per_second(1, 2, 1), Err(CalibrationError::TargetTooFast));
    }

    #[test]
    fn boundary_and_rounding_checks() {
        assert_eq!(periodic_initial_count(10, 4), Ok(3));
        assert_eq!(periodic_initial_count(9, 4), Ok(2));
        assert_eq!(periodic_initial_count(1, 2), Ok(1));
        assert_eq!(periodic_initial_count(1, 3), Err(CalibrationError::TargetTooFast));
        assert_eq!(periodic_initial_count(0, 1), Err(CalibrationError::ZeroApicTicks));
        assert_eq!(periodic_initial_count(1, 0), Err(CalibrationError::ZeroTargetFrequency));
        assert_eq!(periodic_initial_count(u64::from(u32::MAX) + 1, 1), Err(CalibrationError::CountOverflow));
        assert_eq!(periodic_initial_count(u64::from(u32::MAX), 1), Ok(u32::MAX));
    }
}
