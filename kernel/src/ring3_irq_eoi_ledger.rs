//! BSP-only, allocation-free accounting for validated real Ring3 xAPIC IRQs.
//! This ledger never reads APIC ISR, writes MMIO, accepts IRQ provenance, or
//! claims that a callback is a hardware interrupt. The trusted handler must
//! validate the vector, CPL3 frame, CR3/TSS.RSP0/FX and stack *before* begin.
//! Each callback must then perform one physical EOI, acknowledge it here,
//! and finish either a same-PID IRET or a true cross-PID context handoff.
//! The order and counters prevent duplicate, missing and fabricated EOI
//! proof at QEMU shutdown; a failed operation cannot mutate any field.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { InvalidPid, WrongPhase, Overflow, Undrained }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase { Idle, Entered, Acknowledged }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Totals {
    pub received: u64,
    pub eoi: u64,
    pub resumed_same: u64,
    pub switched: u64,
}

/// The four separated arrays are physically independent counters: a forged
/// "same PID" continuation cannot be counted as a hardware task switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ring3IrqEoiLedger<const N: usize> {
    received: [u64; N],
    eoi: [u64; N],
    resumed_same: [u64; N],
    switched: [u64; N],
    phase: [Phase; N],
}

impl<const N: usize> Ring3IrqEoiLedger<N> {
    pub const fn new() -> Self {
        Self {
            received: [0; N], eoi: [0; N],
            resumed_same: [0; N], switched: [0; N],
            phase: [Phase::Idle; N],
        }
    }

    /// Only for an independently authenticated genuine xAPIC timer IRQ.
    pub fn begin(&mut self, index: usize) -> Result<(), Error> {
        if index >= N { return Err(Error::InvalidPid) }
        if self.phase[index] != Phase::Idle { return Err(Error::WrongPhase) }
        let next = self.received[index].checked_add(1).ok_or(Error::Overflow)?;
        self.received[index] = next;
        self.phase[index] = Phase::Entered;
        Ok(())
    }

    /// Only AFTER the trusted handler has physically written exactly one
    /// EOI to the validated supervisor-only xAPIC UC alias.
    pub fn acknowledge(&mut self, index: usize) -> Result<(), Error> {
        if index >= N { return Err(Error::InvalidPid) }
        if self.phase[index] != Phase::Entered { return Err(Error::WrongPhase) }
        let next = self.eoi[index].checked_add(1).ok_or(Error::Overflow)?;
        if next != self.received[index] { return Err(Error::WrongPhase) }
        self.eoi[index] = next;
        self.phase[index] = Phase::Acknowledged;
        Ok(())
    }

    /// Exactly one success outcome follows the EOI; never count a syscall
    /// or a parked/EXITED user as a hardware IRQ handoff.
    pub fn finish(&mut self, index: usize, cross_pid: bool) -> Result<(), Error> {
        if index >= N { return Err(Error::InvalidPid) }
        if self.phase[index] != Phase::Acknowledged { return Err(Error::WrongPhase) }
        if cross_pid {
            let next = self.switched[index].checked_add(1).ok_or(Error::Overflow)?;
            self.switched[index] = next;
        } else {
            let next = self.resumed_same[index].checked_add(1).ok_or(Error::Overflow)?;
            self.resumed_same[index] = next;
        }
        self.phase[index] = Phase::Idle;
        Ok(())
    }

    /// Fail if any valid IRQ lacks its single EOI or its exact return kind.
    /// Count totals using checked arithmetic; never permit wrapped success.
    pub fn verify_drained(&self) -> Result<Totals, Error> {
        let mut t = Totals { received: 0, eoi: 0, resumed_same: 0, switched: 0 };
        for i in 0..N {
            if self.phase[i] != Phase::Idle
                || self.received[i] != self.eoi[i] {
                return Err(Error::Undrained)
            }
            let outcome = self.resumed_same[i].checked_add(self.switched[i])
                .ok_or(Error::Overflow)?;
            if outcome != self.received[i] { return Err(Error::Undrained) }
            t.received = t.received.checked_add(self.received[i]).ok_or(Error::Overflow)?;
            t.eoi = t.eoi.checked_add(self.eoi[i]).ok_or(Error::Overflow)?;
            t.resumed_same = t.resumed_same.checked_add(self.resumed_same[i])
                .ok_or(Error::Overflow)?;
            t.switched = t.switched.checked_add(self.switched[i]).ok_or(Error::Overflow)?;
        }
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn four_real_irq_sources_each_get_one_eoi_and_one_outcome() {
        let mut q = Ring3IrqEoiLedger::<4>::new();
        for turn in 0..80 {
            let src = turn % 4;
            q.begin(src).unwrap();
            q.acknowledge(src).unwrap();
            q.finish(src, turn % 2 == 0).unwrap();
        }
        assert_eq!(q.verify_drained(), Ok(Totals {
            received: 80, eoi: 80, resumed_same: 40, switched: 40,
        }));
    }

    #[test]
    fn missing_eoi_double_eoi_or_duplicate_irq_is_rejected_unchanged() {
        let mut q = Ring3IrqEoiLedger::<4>::new();
        assert_eq!(q.acknowledge(0), Err(Error::WrongPhase));
        q.begin(0).unwrap();
        assert_eq!(q.verify_drained(), Err(Error::Undrained));
        let before = q;
        assert_eq!(q.begin(0), Err(Error::WrongPhase));
        assert_eq!(q.finish(0, true), Err(Error::WrongPhase));
        assert_eq!(q, before);
        q.acknowledge(0).unwrap();
        let before = q;
        assert_eq!(q.acknowledge(0), Err(Error::WrongPhase));
        assert_eq!(q.begin(0), Err(Error::WrongPhase));
        assert_eq!(q, before);
        assert_eq!(q.verify_drained(), Err(Error::Undrained));
        q.finish(0, false).unwrap();
        let before = q;
        assert_eq!(q.finish(0, false), Err(Error::WrongPhase));
        assert_eq!(q, before);
        assert_eq!(q.verify_drained().unwrap().received, 1);
    }

    #[test]
    fn invalid_index_and_counter_overflows_do_not_mutate_state() {
        let mut q = Ring3IrqEoiLedger::<4>::new();
        let before = q;
        assert_eq!(q.begin(4), Err(Error::InvalidPid));
        assert_eq!(q.acknowledge(100), Err(Error::InvalidPid));
        assert_eq!(q.finish(4, true), Err(Error::InvalidPid));
        assert_eq!(q, before);

        q.received[0] = u64::MAX;
        let before = q;
        assert_eq!(q.begin(0), Err(Error::Overflow));
        assert_eq!(q, before);

        q.received[0] = 1;
        q.eoi[0] = u64::MAX;
        q.phase[0] = Phase::Entered;
        let before = q;
        assert_eq!(q.acknowledge(0), Err(Error::Overflow));
        assert_eq!(q, before);

        q.phase[0] = Phase::Acknowledged;
        q.switched[0] = u64::MAX;
        let before = q;
        assert_eq!(q.finish(0, true), Err(Error::Overflow));
        assert_eq!(q, before);
    }

    #[test]
    fn corrupt_balances_and_aggregate_overflow_fail_closed() {
        let mut q = Ring3IrqEoiLedger::<4>::new();
        q.received[0] = 2;
        q.eoi[0] = 2;
        q.resumed_same[0] = 1;
        assert_eq!(q.verify_drained(), Err(Error::Undrained));
        q.switched[0] = 1;
        assert_eq!(q.verify_drained().unwrap().received, 2);
        q.received[1] = u64::MAX;
        q.eoi[1] = u64::MAX;
        q.switched[1] = u64::MAX;
        assert_eq!(q.verify_drained(), Err(Error::Overflow));
    }

    #[test]
    fn zero_capacity_ledger_is_inert_and_drained() {
        let mut q = Ring3IrqEoiLedger::<0>::new();
        assert_eq!(q.begin(0), Err(Error::InvalidPid));
        assert_eq!(q.verify_drained(), Ok(Totals {
            received: 0, eoi: 0, resumed_same: 0, switched: 0,
        }));
    }
}
