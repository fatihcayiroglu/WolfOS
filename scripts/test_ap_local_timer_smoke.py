#!/usr/bin/env python3
"""Adversarial checks: the real AP PMM IF=1 proof must never be fake-green."""
import unittest

from ap_local_timer_smoke import check_pmm_irq_if1_evidence

TIMER = "WOLFOS_AP_LOCAL_TIMER_OK cpus=4 aps=3 ticks=17"
MARKER = "WOLFOS_PMM_IRQ_IF1_OK aps=3 probes=192 timer_ticks=17"


def checked(output: str, ticks: int = 17) -> str | None:
    end = output.index(TIMER) + len(TIMER)
    return check_pmm_irq_if1_evidence(output, end, ticks)


class PmmIf1EvidenceTests(unittest.TestCase):
    def test_exact_evidence_after_timer_is_accepted(self):
        self.assertIsNone(checked(TIMER + "\n" + MARKER + "\nWOLFOS_BOOT_OK"))

    def test_missing_marker_rejected(self):
        self.assertIsNotNone(checked(TIMER + "\nWOLFOS_BOOT_OK"))

    def test_duplicate_marker_rejected(self):
        self.assertIsNotNone(checked(TIMER + "\n" + MARKER + "\n" + MARKER))

    def test_duplicate_malformed_marker_rejected(self):
        self.assertIsNotNone(checked(TIMER + "\n" + MARKER + "\ntruncated WOLFOS_PMM_IRQ_IF1_OK"))

    def test_marker_must_follow_timer(self):
        self.assertIsNotNone(checked(MARKER + "\n" + TIMER))

    def test_wrong_ap_probe_count_and_tick_value_rejected(self):
        for candidate in (
            MARKER.replace("aps=3", "aps=2"),
            MARKER.replace("probes=192", "probes=191"),
            MARKER.replace("probes=192", "probes=0"),
            MARKER.replace("timer_ticks=17", "timer_ticks=16"),
        ):
            with self.subTest(candidate=candidate):
                self.assertIsNotNone(checked(TIMER + "\n" + candidate))

    def test_embedded_and_extra_payload_rejected(self):
        for candidate in ("log: " + MARKER, MARKER + " forged=1", MARKER + " "):
            with self.subTest(candidate=candidate):
                self.assertIsNotNone(checked(TIMER + "\n" + candidate))

    def test_wrong_external_timer_ticks_rejected(self):
        self.assertIsNotNone(checked(TIMER + "\n" + MARKER, ticks=19))


if __name__ == "__main__":
    unittest.main()
