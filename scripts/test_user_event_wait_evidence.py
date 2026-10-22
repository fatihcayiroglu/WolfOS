"""Offline adversarial parser checks; never substitute for real QEMU proof."""
import unittest

from user_event_wait_smoke import (
    CLEANUP, HARDWARE, REJECTED, RESUME, START, SWITCHES, TRAPS, evaluate,
)


def valid_evidence():
    return "\n".join([
        "WOLFOS_BOOT_OK", START,
        TRAPS[0], SWITCHES[0],
        TRAPS[1], REJECTED, TRAPS[2], SWITCHES[1],
        TRAPS[3], RESUME, SWITCHES[2],
        TRAPS[4], HARDWARE, CLEANUP,
    ]) + "\n"


class EventWaitEvidenceTests(unittest.TestCase):
    def test_strict_success_fixture(self):
        self.assertTrue(evaluate(valid_evidence(), 33))

    def test_bad_exit_and_missing_events_fail(self):
        source = valid_evidence()
        for code in (0, 1, 35):
            self.assertFalse(evaluate(source, code))
        for line in TRAPS + SWITCHES + [HARDWARE, CLEANUP, REJECTED, RESUME, START]:
            self.assertFalse(evaluate(source.replace(line + "\n", ""), 33))

    def test_duplicate_and_reordered_events_fail(self):
        source = valid_evidence()
        for line in TRAPS + SWITCHES + [HARDWARE, CLEANUP, REJECTED]:
            self.assertFalse(evaluate(source + line + "\n", 33))
        moved = source.replace(TRAPS[3] + "\n" + RESUME + "\n",
                               RESUME + "\n" + TRAPS[3] + "\n")
        self.assertFalse(evaluate(moved, 33))
        moved = source.replace(TRAPS[2] + "\n" + SWITCHES[1] + "\n",
                               SWITCHES[1] + "\n" + TRAPS[2] + "\n")
        self.assertFalse(evaluate(moved, 33))

    def test_wrong_event_signal_must_precede_the_valid_one(self):
        source = valid_evidence()
        reordered = source.replace(
            TRAPS[1] + "\n" + REJECTED + "\n" + TRAPS[2] + "\n",
            TRAPS[2] + "\n" + TRAPS[1] + "\n" + REJECTED + "\n",
        )
        self.assertFalse(evaluate(reordered, 33))
        self.assertFalse(evaluate(source.replace("wrong_event=78",
                                                "wrong_event=77"), 33))
        self.assertFalse(evaluate(source.replace("pid1_still_blocked=1",
                                                "pid1_still_blocked=0"), 33))
        self.assertFalse(evaluate(source.replace("traps=5", "traps=4"), 33))

    def test_extra_malformed_or_embedded_evidence_fails_closed(self):
        source = valid_evidence()
        for marker in (
            "WOLFOS_BOOT_OK", START, REJECTED, RESUME, HARDWARE,
            CLEANUP, TRAPS[0], SWITCHES[0],
        ):
            stem = marker.split(" ", 1)[0]
            for forged in (
                "diagnostic: " + marker,
                marker + " forged=1",
                stem + "_FORGED",
                stem + "\\tforged",
            ):
                self.assertFalse(evaluate(source + forged + "\\n", 33), forged)

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
