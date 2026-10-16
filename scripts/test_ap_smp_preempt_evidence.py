#!/usr/bin/env python3
"""Offline adversarial tests for the AP SMP aggregate QEMU proof parser."""
import unittest

from ap_smp_preempt_smoke import unique_aggregate_proof, prerequisite_smp_proof

VALID = (
    "WOLFOS_AP_SMP_PREEMPT_OK cpus=4 aps=3 tasks_per_ap=2 "
    "switches=40 task0_irqs=20 task1_irqs=20 "
    "ticks=60 eois=60 work=100 invalid=0 "
    "xmm_bad=0 spurious=0 wrong_ipi=0 offline=3 "
    "bsp_if=0 migrated=0 deferred=15 nested_aps=3 guard_depth=0"
)


class AggregateEvidenceTests(unittest.TestCase):
    def test_accepts_one_complete_line(self):
        self.assertIsNotNone(unique_aggregate_proof("boot\n" + VALID + "\n"))

    def test_rejects_missing(self):
        self.assertIsNone(unique_aggregate_proof("boot\n"))

    def test_rejects_embedded(self):
        self.assertIsNone(unique_aggregate_proof("diagnostic: " + VALID))

    def test_rejects_duplicate(self):
        self.assertIsNone(unique_aggregate_proof(VALID + "\n" + VALID))

    def test_rejects_trailing_payload(self):
        self.assertIsNone(unique_aggregate_proof(VALID + " forged=1"))

    def test_rejects_embedded_marker_beside_valid(self):
        self.assertIsNone(unique_aggregate_proof(VALID + "\nlog: " + VALID))

    def test_rejects_malformed_duplicate_beside_valid(self):
        self.assertIsNone(unique_aggregate_proof(VALID + "\n" + VALID + " forged=1"))

    def test_rejects_truncated_duplicate_beside_valid(self):
        self.assertIsNone(unique_aggregate_proof(VALID + "\nWOLFOS_AP_SMP_PREEMPT_OK"))

    def test_rejects_truncated(self):
        self.assertIsNone(unique_aggregate_proof(VALID.rsplit(" guard_depth=", 1)[0]))



class PrerequisiteEvidenceTests(unittest.TestCase):
    VALID = "WOLFOS_SMP_APS_OK total=4 bsp=1 aps=3"

    def test_valid(self):
        self.assertTrue(prerequisite_smp_proof(self.VALID))

    def test_missing(self):
        self.assertFalse(prerequisite_smp_proof("boot"))

    def test_embedded(self):
        self.assertFalse(prerequisite_smp_proof("log: " + self.VALID))

    def test_duplicate(self):
        self.assertFalse(prerequisite_smp_proof(self.VALID + "\n" + self.VALID))

    def test_malformed_duplicate(self):
        self.assertFalse(prerequisite_smp_proof(self.VALID + "\nWOLFOS_SMP_APS_OK total=4"))

    def test_wrong_cpu_count(self):
        self.assertFalse(prerequisite_smp_proof(self.VALID.replace("total=4", "total=3")))


if __name__ == "__main__":
    unittest.main()
