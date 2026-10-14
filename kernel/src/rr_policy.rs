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

/// Invalid lifecycle operations are fail-closed. Callers that mutate a
/// runnable mask from an IRQ must use atomic CAS/fetch_update and rerun these
/// pure checks against the then-current mask; a stale read is not a lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnableError {
    InvalidTaskCount,
    InvalidTask,
    InvalidMask,
    AlreadyBlocked,
    AlreadyReady,
    WouldBlockLastRunnable,
}

fn valid_bit(mask: u64, task: usize, count: usize)
    -> Result<u64, RunnableError>
{
    if count == 0 || count > 64 {
        return Err(RunnableError::InvalidTaskCount);
    }
    if task >= count {
        return Err(RunnableError::InvalidTask);
    }
    if count < 64 && mask >> count != 0 {
        return Err(RunnableError::InvalidMask);
    }
    Ok(1u64 << task)
}

/// Remove one task from the runnable set. The current task may be blocked
/// only while there remains another runnable task for its next IRQ handoff.
pub fn block_runnable(mask: u64, task: usize, count: usize)
    -> Result<u64, RunnableError>
{
    let bit = valid_bit(mask, task, count)?;
    if mask & bit == 0 {
        return Err(RunnableError::AlreadyBlocked);
    }
    let remaining = mask & !bit;
    if remaining == 0 {
        return Err(RunnableError::WouldBlockLastRunnable);
    }
    Ok(remaining)
}

/// Wake exactly one currently blocked task; cannot silently insert an invalid
/// task index, or accidentally wake an already runnable task.
pub fn wake_runnable(mask: u64, task: usize, count: usize)
    -> Result<u64, RunnableError>
{
    let bit = valid_bit(mask, task, count)?;
    if mask & bit != 0 {
        return Err(RunnableError::AlreadyReady);
    }
    Ok(mask | bit)
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
    #[test]
    fn blocked_task_is_skipped_then_returns_to_fair_rotation_after_wake() {
        let original = 0b111_u64;
        let blocked = block_runnable(original, 1, 3).unwrap();
        assert_eq!(blocked, 0b101);
        assert_eq!(next_runnable(0, 3, blocked), Ok(2));
        assert_eq!(next_runnable(2, 3, blocked), Ok(0));
        assert_eq!(next_runnable(1, 3, blocked), Ok(2));
        let restored = wake_runnable(blocked, 1, 3).unwrap();
        assert_eq!(restored, original);
        let mut current = 0;
        let mut visits = [0; 3];
        for _ in 0..36 {
            current = next_runnable(current, 3, restored).unwrap();
            visits[current] += 1;
        }
        assert_eq!(visits, [12, 12, 12]);
    }

    #[test]
    fn lifecycle_refuses_double_block_double_wake_and_last_ready_removal() {
        assert_eq!(block_runnable(0b111, 1, 3), Ok(0b101));
        assert_eq!(block_runnable(0b101, 1, 3), Err(RunnableError::AlreadyBlocked));
        assert_eq!(wake_runnable(0b111, 1, 3), Err(RunnableError::AlreadyReady));
        assert_eq!(block_runnable(0b010, 1, 3), Err(RunnableError::WouldBlockLastRunnable));
        assert_eq!(wake_runnable(0b000, 2, 3), Ok(0b100));
    }

    #[test]
    fn lifecycle_refuses_invalid_indices_and_out_of_range_bits() {
        assert_eq!(block_runnable(1, 0, 0), Err(RunnableError::InvalidTaskCount));
        assert_eq!(wake_runnable(1, 0, 65), Err(RunnableError::InvalidTaskCount));
        assert_eq!(block_runnable(0b111, 3, 3), Err(RunnableError::InvalidTask));
        assert_eq!(wake_runnable(0b1000, 1, 3), Err(RunnableError::InvalidMask));
        assert_eq!(block_runnable(0b1000, 1, 3), Err(RunnableError::InvalidMask));
        assert_eq!(wake_runnable(0b101, 0, 3), Err(RunnableError::AlreadyReady));
        assert_eq!(wake_runnable(0, 63, 64), Ok(1u64 << 63));
    }

}
