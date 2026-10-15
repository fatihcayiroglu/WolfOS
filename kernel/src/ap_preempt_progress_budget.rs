//! Bounded, allocation-free progress watchdog for AP-local xAPIC smoke.
//! A genuine new IRQ permits another no-progress spin window, but a hard
//! total-spin and total-tick cap prevents an IRQ storm from hiding a hang.
//! This ONLY controls how long the test waits; it cannot certify preemption.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrqProgressBudget {
    last_tick: u64,
    idle_polls: u64,
    all_polls: u64,
}

impl IrqProgressBudget {
    pub const fn new(initial_tick: u64) -> Self {
        Self { last_tick: initial_tick, idle_polls: 0, all_polls: 0 }
    }

    /// Return false on exhausted bounds, counter regression or IRQ storm.
    /// Replenish only the *idle* budget on strictly new, observed timer IRQs.
    /// Never replenish the overall spin limit.
    pub fn poll(
        &mut self, timer_ticks: u64, max_idle_polls: u64,
        max_total_polls: u64, max_timer_ticks: u64,
    ) -> bool {
        if max_idle_polls == 0 || max_total_polls == 0
            || timer_ticks < self.last_tick || timer_ticks >= max_timer_ticks
            || self.all_polls >= max_total_polls
        {
            return false;
        }
        self.all_polls += 1;
        if timer_ticks > self.last_tick {
            self.last_tick = timer_ticks;
            self.idle_polls = 0;
        } else {
            self.idle_polls += 1;
        }
        self.idle_polls < max_idle_polls
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_timer_progress_exhausts_idle_bound() {
        let mut b = IrqProgressBudget::new(4);
        assert!(b.poll(4, 4, 100, 64));
        assert!(b.poll(4, 4, 100, 64));
        assert!(b.poll(4, 4, 100, 64));
        assert!(!b.poll(4, 4, 100, 64));
    }

    #[test]
    fn observed_irqs_renew_idle_not_total_limit() {
        let mut b = IrqProgressBudget::new(4);
        // This can outlast an original 10-poll global work budget, only
        // because real timer ticks continue arriving between short bursts.
        for tick in 5..15 {
            assert!(b.poll(tick, 4, 40, 64));
            assert!(b.poll(tick, 4, 40, 64));
            assert!(b.poll(tick, 4, 40, 64));
        }
        assert_eq!(b.last_tick, 14);
        assert_eq!(b.all_polls, 30);
        assert_eq!(b.idle_polls, 2);
        for tick in 15..19 {
            if !b.poll(tick, 4, 40, 64) { break; }
            let _ = b.poll(tick, 4, 40, 64);
            let _ = b.poll(tick, 4, 40, 64);
        }
        assert_eq!(b.all_polls, 40);
        assert!(!b.poll(20, 4, 40, 64), "IRQ progress never bypasses global cap");
    }

    #[test]
    fn regressions_and_interrupt_storm_fail_closed() {
        let mut b = IrqProgressBudget::new(3);
        assert!(!b.poll(2, 10, 100, 64));
        assert_eq!(b, IrqProgressBudget::new(3));
        assert!(!b.poll(64, 10, 100, 64));
        assert_eq!(b, IrqProgressBudget::new(3));
        assert!(!b.poll(3, 0, 100, 64));
        assert!(!b.poll(3, 10, 0, 64));
    }

    #[test]
    fn total_bound_still_applies_if_every_poll_sees_new_tick() {
        let mut b = IrqProgressBudget::new(0);
        assert!(b.poll(1, 2, 3, 64));
        assert!(b.poll(2, 2, 3, 64));
        assert!(b.poll(3, 2, 3, 64));
        assert!(!b.poll(4, 2, 3, 64));
    }
}
