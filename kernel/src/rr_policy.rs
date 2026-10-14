//! Bounded, allocation-free round-robin runnable selection for kernel tasks.
//! Pure logic: never changes live task stacks or CPU interrupt state.
//!
//! The caller owns the runnable bitmap and must validate saved task frames
//! before committing to an IRQ-triggered context handoff.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectError {
    InvalidTaskCount,
    InvalidCurrent,
    OutOfRangeRunnableBits,
    NoRunnableTask,
}

/// Search starting AFTER the current task. Wrap once, including current
/// as the final candidate if it is the only runnable task. No allocation,
/// locks, atomics, recursion, or unbounded loops in this IRQ-safe selector.
pub fn next_runnable(
    current: usize,
    count: usize,
    runnable: u64,
) -> Result<usize, SelectError> {
    if count == 0 || count > 64 {
        return Err(SelectError::InvalidTaskCount);
    }
    if current >= count {
        return Err(SelectError::InvalidCurrent);
    }
    if count < 64 && runnable >> count != 0 {
        return Err(SelectError::OutOfRangeRunnableBits);
    }
    if runnable == 0 {
        return Err(SelectError::NoRunnableTask);
    }
    for offset in 1..=count {
        let candidate = (current + offset) % count;
        if runnable & (1u64 << candidate) != 0 {
            return Ok(candidate);
        }
    }
    Err(SelectError::NoRunnableTask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_runnable_tasks_get_strict_cyclic_fairness() {
        let mask = 0b111;
        let mut current = 0;
        let mut visits = [0usize; 3];
        for _ in 0..300 {
            current = next_runnable(current, 3, mask).unwrap();
            visits[current] += 1;
        }
        assert_eq!(visits, [100, 100, 100]);
        assert_eq!(next_runnable(0, 3, mask), Ok(1));
        assert_eq!(next_runnable(1, 3, mask), Ok(2));
        assert_eq!(next_runnable(2, 3, mask), Ok(0));
    }

    #[test]
    fn skips_non_runnable_tasks_and_preserves_only_ready_task() {
        assert_eq!(next_runnable(0, 3, 0b101), Ok(2));
        assert_eq!(next_runnable(2, 3, 0b101), Ok(0));
        assert_eq!(next_runnable(1, 3, 0b100), Ok(2));
        assert_eq!(next_runnable(2, 3, 0b100), Ok(2));
    }

    #[test]
    fn all_invalid_shapes_are_rejected_without_partial_selection() {
        assert_eq!(next_runnable(0, 0, 0), Err(SelectError::InvalidTaskCount));
        assert_eq!(next_runnable(0, 65, 1), Err(SelectError::InvalidTaskCount));
        assert_eq!(next_runnable(3, 3, 0b111), Err(SelectError::InvalidCurrent));
        assert_eq!(next_runnable(0, 3, 0b1000), Err(SelectError::OutOfRangeRunnableBits));
        assert_eq!(next_runnable(0, 3, 0), Err(SelectError::NoRunnableTask));
    }

    #[test]
    fn full_64_task_mask_has_no_invalid_shift() {
        assert_eq!(next_runnable(63, 64, 1), Ok(0));
        assert_eq!(next_runnable(0, 64, 1 << 63), Ok(63));
    }
}
