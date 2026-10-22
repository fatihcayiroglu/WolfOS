"""Fail-closed offline adversarial tests for authentic Ring3 IRQ wake evidence."""
import unittest

from user_event_irq_wake_smoke import (
    BOOT, START, WAIT, SWITCH, EOI, HANDOFF, EXIT1, RESUME,
    EXIT2, TIMER_CLEANUP, CLEANUP, evaluate,
)

HARDWARE = (
    "WOLFOS_RING3_IRQ_WAKE_HARDWARE_OK events=1 timer_switches=1 "
    "signal_syscalls=0 voluntary_yields=0 traps=3 physical_irqs=7 "
    "physical_eois=7 private_cr3=2 fx=2"
)
GOOD = [
    BOOT, START, WAIT, SWITCH, EOI, HANDOFF,
    EXIT1, RESUME, SWITCH, EXIT2, HARDWARE, TIMER_CLEANUP, CLEANUP,
]


class RealIrqWakeProofTests(unittest.TestCase):
    def accepts(self, rows, code=33):
        return evaluate("\n".join(rows) + "\n", code)

    def test_genuine_full_order_is_accepted(self):
        self.assertTrue(self.accepts(GOOD))

    def test_wrong_exit_missing_or_truncated_is_rejected(self):
        self.assertFalse(self.accepts(GOOD, 0))
        for i in range(len(GOOD)):
            self.assertFalse(self.accepts(GOOD[:i] + GOOD[i+1:]), i)

    def test_replay_duplicate_wrong_order_and_added_fake_stems(self):
        for line in (WAIT, EOI, HANDOFF, RESUME, HARDWARE, CLEANUP, SWITCH):
            self.assertFalse(self.accepts(GOOD + [line]))
        for a, b in ((3, 4), (4, 5), (5, 6), (8, 9), (10, 11)):
            v = list(GOOD)
            v[a], v[b] = v[b], v[a]
            self.assertFalse(self.accepts(v))
        self.assertFalse(self.accepts(GOOD + ["evil " + EOI]))
        self.assertFalse(self.accepts(GOOD + [EOI + " forged"]))
        self.assertFalse(self.accepts(GOOD + ["WOLFOS_RING3_IRQ_WAKE_UNKNOWN=1"]))

    def test_hardware_ledger_requires_matching_nonzero_real_eois(self):
        for a, b in ((0, 0), (7, 6), (6, 7), (1, 0), (99, 1)):
            bad = HARDWARE.replace("physical_irqs=7", f"physical_irqs={a}")
            bad = bad.replace("physical_eois=7", f"physical_eois={b}")
            self.assertFalse(self.accepts([bad if x == HARDWARE else x for x in GOOD]))
        self.assertFalse(self.accepts([
            x.replace("signal_syscalls=0", "signal_syscalls=1") for x in GOOD
        ]))

    def test_cannot_substitute_syscall_notification_or_synthetic_policy(self):
        for forbidden in (
            "WOLFOS_RING3_EVENT_HARDWARE_OK user_wait=1 trusted_signal=1",
            "WOLFOS_RING3_EVENT_REJECTED_OK wrong_event=78",
            "WOLFOS_RING3_YIELD_ERROR injected",
            "WOLFOS_EXCEPTION_PF forged",
        ):
            self.assertFalse(self.accepts(GOOD + [forbidden]))


if __name__ == "__main__":
    unittest.main()
