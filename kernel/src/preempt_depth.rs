//! BSP-only IRQ-aware preemption-disable depth for kernel critical sections.
//!
//! Unlike CLI, disabling *preemption* leaves hardware timer IRQs deliverable.
//! The IRQ can still EOI and publish ticks, but cannot hand control to a
//! different kernel stack until every nested critical section is exited.
//!
//! This primitive alone is NOT a production scheduler lock. It is currently
//! only wired to the BSP-only xAPIC QEMU preemption smoke; there is no AP task
//! preemption, arbitrary task ownership or cross-CPU scheduling yet.

use core::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DepthError {
    Overflow,
    UnbalancedEnable,
}

pub struct PreemptDepth {
    depth: AtomicUsize,
}

impl PreemptDepth {
    pub const fn new() -> Self {
        Self { depth: AtomicUsize::new(0) }
    }

    /// Enter an IRQ-preempt-disabled critical section. Hardware IRQs remain
    /// enabled. Overflow is refused without mutating the depth.
    pub fn disable(&self) -> Result<usize, DepthError> {
        self.depth.fetch_update(Ordering::AcqRel, Ordering::Acquire, |depth| {
            depth.checked_add(1)
        })
        .map(|old| old + 1)
        .map_err(|_| DepthError::Overflow)
    }

    /// Exit exactly one critical section. An unbalanced enable is rejected,
    /// not allowed to silently underflow and re-enable task switching.
    pub fn enable(&self) -> Result<usize, DepthError> {
        self.depth.fetch_update(Ordering::AcqRel, Ordering::Acquire, |depth| {
            depth.checked_sub(1)
        })
        .map(|old| old - 1)
        .map_err(|_| DepthError::UnbalancedEnable)
    }

    /// Used by the IRQ dispatcher BEFORE it selects another task stack.
    pub fn can_preempt(&self) -> bool {
        self.depth.load(Ordering::Acquire) == 0
    }

    pub fn depth(&self) -> usize {
        self.depth.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_sections_block_until_outermost_exit() {
        let p = PreemptDepth::new();
        assert!(p.can_preempt());
        assert_eq!(p.disable(), Ok(1));
        assert!(!p.can_preempt());
        assert_eq!(p.disable(), Ok(2));
        assert_eq!(p.depth(), 2);
        assert!(!p.can_preempt());
        assert_eq!(p.enable(), Ok(1));
        assert!(!p.can_preempt());
        assert_eq!(p.enable(), Ok(0));
        assert!(p.can_preempt());
    }

    #[test]
    fn underflow_does_not_enable_an_unbalanced_critical_section() {
        let p = PreemptDepth::new();
        assert_eq!(p.enable(), Err(DepthError::UnbalancedEnable));
        assert_eq!(p.depth(), 0);
        assert!(p.can_preempt());
        assert_eq!(p.disable(), Ok(1));
        assert_eq!(p.enable(), Ok(0));
        assert_eq!(p.enable(), Err(DepthError::UnbalancedEnable));
    }

    #[test]
    fn overflow_is_refused_without_wrapping_to_zero() {
        let p = PreemptDepth::new();
        p.depth.store(usize::MAX, Ordering::Relaxed);
        assert_eq!(p.disable(), Err(DepthError::Overflow));
        assert_eq!(p.depth(), usize::MAX);
        assert!(!p.can_preempt());
        assert_eq!(p.enable(), Ok(usize::MAX - 1));
    }
}
