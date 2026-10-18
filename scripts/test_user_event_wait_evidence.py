"""Offline adversarial parser checks; never substitute for real QEMU proof."""
import unittest

from user_event_wait_smoke import (
    CLEANUP, HARDWARE, RESUME, START, SWITCHES, TRAPS, evaluate,
)


def valid_evidence():
    return "\n".join([
        "WOLFOS_BOOT_OK", START,
        TRAPS[0], SWITCHES[0],
        TRAPS[1], SWITCHES[1],
        TRAPS[2], RESUME, SWITCHES[2],
        TRAPS[3], HARDWARE, CLEANUP,
    ]) + "\n"


class EventWaitEvidenceTests(unittest.TestCase):
    def test_strict_success_fixture(self):
        self.assertTrue(evaluate(valid_evidence(), 33))

    def test_bad_exit_and_missing_events_fail(self):
        source = valid_evidence()
        for code in (0, 1, 35):
            self.assertFalse(evaluate(source, code))
        for line in TRAPS + SWITCHES + [HARDWARE, CLEANUP, RESUME, START]:
            self.assertFalse(evaluate(source.replace(line + "\n", ""), 33))

    def test_duplicate_and_reordered_events_fail(self):
        source = valid_evidence()
        for line in TRAPS + SWITCHES + [HARDWARE, CLEANUP]:
            self.assertFalse(evaluate(source + line + "\n", 33))
        moved = source.replace(TRAPS[2] + "\n" + RESUME + "\n",
                               RESUME + "\n" + TRAPS[2] + "\n")
        self.assertFalse(evaluate(moved, 33))
        moved = source.replace(TRAPS[1] + "\n" + SWITCHES[1] + "\n",
                               SWITCHES[1] + "\n" + TRAPS[1] + "\n")
        self.assertFalse(evaluate(moved, 33))

    def test_wrong_pid_event_or_fake_irq_cannot_pass(self):
        source = valid_evidence()
        self.assertFalse(evaluate(source.replace("pid=1 kind=wait",
                                                 "pid=2 kind=wait"), 33))
        self.assertFalse(evaluate(source.replace("from=2 to=1",
                                                 "from=1 to=2"), 33))
        for forged in (
            "WOLFOS_RING3_TIMER_HARDWARE_OK fake=1",
            "WOLFOS_RING3_YIELD_HARDWARE_OK fake=1",
            "WOLFOS_RING3_YIELD_ERROR missing_real_iret",
            "WOLFOS_EXCEPTION_PF access_denied",
        ):
            self.assertFalse(evaluate(source + forged + "\n", 33))


if __name__ == "__main__":
    unittest.main()
