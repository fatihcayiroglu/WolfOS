//! Pure staged xAPIC timer register-write plan; never touches hardware.
//! A future BSP-only MMIO driver must own mapping, synchronization, IDT,
//! interrupt routing, EOI, calibration and rollback before applying this plan.

#[path = "lapic_timer_layout.rs"]
mod layout;

use layout::{TimerError, TimerMode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterWrite {
    pub offset: usize,
    pub value: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimerPlan {
    /// Write these in order while interrupts and the local timer are isolated.
    pub preparation: [RegisterWrite; 3],
    /// This final unmask is an explicit separate commit step. Merely
    /// constructing a TimerPlan never enables timer interrupts.
    pub activation: RegisterWrite,
    /// Safe default to re-mask LVT, not a substitute for full teardown.
    pub mask: RegisterWrite,
}

pub fn periodic_timer_plan(
    vector: u8,
    divisor: u32,
    initial_count: u32,
) -> Result<TimerPlan, TimerError> {
    let masked = layout::make_lvt(vector, true, TimerMode::Periodic)?;
    let active = layout::make_lvt(vector, false, TimerMode::Periodic)?;
    let divide = layout::encode_divisor(divisor)?;
    let count = layout::validate_initial_count(initial_count)?;
    Ok(TimerPlan {
        preparation: [
            RegisterWrite { offset: layout::LVT_TIMER_OFFSET, value: masked },
            RegisterWrite { offset: layout::DIVIDE_CONFIG_OFFSET, value: divide },
            RegisterWrite { offset: layout::INITIAL_COUNT_OFFSET, value: count },
        ],
        activation: RegisterWrite { offset: layout::LVT_TIMER_OFFSET, value: active },
        mask: RegisterWrite { offset: layout::LVT_TIMER_OFFSET, value: masked },
    })
}

/// Arm exactly one local timer IRQ without accidentally consuming the
/// count while the LVT is still masked. Unlike the periodic plan, a one-shot
/// commit must be the FINAL initial-count write, AFTER the LVT is unmasked.
/// The caller must hold IF=0, finish task/IDT/FX setup, then execute start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OneShotTimerPlan {
    pub preparation: [RegisterWrite; 3],
    pub arm: RegisterWrite,
    pub start: RegisterWrite,
    pub mask: RegisterWrite,
}

pub fn one_shot_timer_plan(
    vector: u8,
    divisor: u32,
    initial_count: u32,
) -> Result<OneShotTimerPlan, TimerError> {
    let masked = layout::make_lvt(vector, true, TimerMode::OneShot)?;
    let armed = layout::make_lvt(vector, false, TimerMode::OneShot)?;
    let divide = layout::encode_divisor(divisor)?;
    let count = layout::validate_initial_count(initial_count)?;
    Ok(OneShotTimerPlan {
        preparation: [
            RegisterWrite { offset: layout::LVT_TIMER_OFFSET, value: masked },
            RegisterWrite { offset: layout::INITIAL_COUNT_OFFSET, value: 0 },
            RegisterWrite { offset: layout::DIVIDE_CONFIG_OFFSET, value: divide },
        ],
        arm: RegisterWrite { offset: layout::LVT_TIMER_OFFSET, value: armed },
        start: RegisterWrite { offset: layout::INITIAL_COUNT_OFFSET, value: count },
        mask: RegisterWrite { offset: layout::LVT_TIMER_OFFSET, value: masked },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shot_count_is_last_commit_after_unmask() {
        let plan = one_shot_timer_plan(0xe4, 16, 262_144).unwrap();
        assert_eq!(plan.preparation[0].offset, layout::LVT_TIMER_OFFSET);
        assert_ne!(plan.preparation[0].value & layout::LVT_MASKED, 0);
        assert_eq!(plan.preparation[1],
            RegisterWrite { offset: layout::INITIAL_COUNT_OFFSET, value: 0 });
        assert_eq!(plan.preparation[2],
            RegisterWrite { offset: layout::DIVIDE_CONFIG_OFFSET, value: 0b0011 });
        assert_eq!(plan.arm.offset, layout::LVT_TIMER_OFFSET);
        assert_eq!(plan.arm.value & layout::LVT_MASKED, 0);
        assert_eq!(layout::parse_lvt(plan.arm.value).unwrap().mode,
            TimerMode::OneShot);
        assert_eq!(plan.start,
            RegisterWrite { offset: layout::INITIAL_COUNT_OFFSET, value: 262_144 });
        assert_eq!(plan.mask, plan.preparation[0]);
    }

    #[test]
    fn one_shot_rejects_invalid_inputs_before_hardware_writes() {
        assert_eq!(one_shot_timer_plan(0x1f, 16, 1), Err(TimerError::InvalidVector));
        assert_eq!(one_shot_timer_plan(0xff, 16, 1), Err(TimerError::InvalidVector));
        assert_eq!(one_shot_timer_plan(0xe4, 3, 1), Err(TimerError::InvalidDivisor));
        assert_eq!(one_shot_timer_plan(0xe4, 16, 0), Err(TimerError::ZeroInitialCount));
    }

    #[test]
    fn staged_plan_starts_and_ends_masked() {
        let plan = periodic_timer_plan(0xe0, 16, 1_000_000).unwrap();
        assert_eq!(plan.preparation[0].offset, layout::LVT_TIMER_OFFSET);
        assert_ne!(plan.preparation[0].value & layout::LVT_MASKED, 0);
        assert_eq!(plan.preparation[1],
            RegisterWrite { offset: layout::DIVIDE_CONFIG_OFFSET, value: 0b0011 });
        assert_eq!(plan.preparation[2],
            RegisterWrite { offset: layout::INITIAL_COUNT_OFFSET, value: 1_000_000 });
        assert_eq!(plan.activation.offset, layout::LVT_TIMER_OFFSET);
        assert_eq!(plan.activation.value & layout::LVT_MASKED, 0);
        assert_eq!(plan.mask, plan.preparation[0]);
        assert_eq!(layout::parse_lvt(plan.activation.value).unwrap().mode, TimerMode::Periodic);
    }

    #[test]
    fn never_emits_unmasked_preparation() {
        for vector in [0x20, 0x30, 0xe0, 0xfe] {
            for divisor in [1, 2, 4, 8, 16, 32, 64, 128] {
                let plan = periodic_timer_plan(vector, divisor, 1).unwrap();
                assert_eq!(plan.preparation[0].value & layout::LVT_MASKED, layout::LVT_MASKED);
                assert_eq!(layout::decode_divisor(plan.preparation[1].value), Ok(divisor));
            }
        }
    }

    #[test]
    fn refuses_invalid_parameters_without_partial_plan() {
        assert_eq!(periodic_timer_plan(0x1f, 16, 1), Err(TimerError::InvalidVector));
        assert_eq!(periodic_timer_plan(0xff, 16, 1), Err(TimerError::InvalidVector));
        assert_eq!(periodic_timer_plan(0xe0, 3, 1), Err(TimerError::InvalidDivisor));
        assert_eq!(periodic_timer_plan(0xe0, 16, 0), Err(TimerError::ZeroInitialCount));
    }
}
