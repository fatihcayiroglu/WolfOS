"""Adversarial fail-closed marker checks for owner-bound hardware retirement."""
import unittest

from smp_retirement_ipi_hardware_smoke import PROOF, validate

GOOD = (
    "WOLFOS_SMP_APS_OK total=4 aps=3\n"
    + PROOF + "\nWOLFOS_BOOT_OK\n"
)


class OwnerBoundIpiEvidenceTests(unittest.TestCase):
    def test_authentic_single_evidence(self):
        self.assertTrue(validate(GOOD, 33))

    def test_wrong_exit_rejected(self):
        self.assertFalse(validate(GOOD, 0))

    def test_missing_smp_startup_rejected(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_SMP_APS_OK", "HOST_APS_OK"), 33))

    def test_duplicate_evidence_rejected(self):
        self.assertFalse(validate(GOOD.replace(PROOF, PROOF + "\n" + PROOF), 33))

    def test_mutated_count_rejected(self):
        self.assertFalse(validate(GOOD.replace("ipis=3", "ipis=2"), 33))

    def test_ring3_misrepresentation_rejected(self):
        self.assertFalse(validate(GOOD.replace("ring3=0", "ring3=1"), 33))

    def test_fault_marker_rejected(self):
        self.assertFalse(validate(GOOD + "WOLFOS_EXCEPTION_PF forced\n", 33))

    def test_legacy_false_green_rejected(self):
        self.assertFalse(validate(GOOD + "WOLFOS_SMP_RETIRE_OK fake\n", 33))

    def test_marker_after_boot_rejected(self):
        lines = GOOD.splitlines()
        self.assertFalse(validate("\n".join([lines[0], lines[2], lines[1]]) + "\n", 33))


if __name__ == "__main__":
    unittest.main()
