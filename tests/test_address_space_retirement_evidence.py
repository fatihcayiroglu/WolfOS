"""Reject absent, forged, reordered and failed hardware-run evidence."""
import unittest
from scripts.address_space_retirement_smoke import PROOF, evaluate


class RetirementEvidenceTests(unittest.TestCase):
    def test_complete_ordered_hardware_evidence(self):
        self.assertTrue(evaluate(PROOF + "\nWOLFOS_BOOT_OK\n", 33))

    def test_missing_duplicate_or_out_of_order_proofs(self):
        for output in ["", "WOLFOS_BOOT_OK", PROOF, PROOF + "\n" + PROOF + "\nWOLFOS_BOOT_OK",
                       "WOLFOS_BOOT_OK\n" + PROOF, PROOF + "\nWOLFOS_BOOT_OK\nWOLFOS_BOOT_OK"]:
            self.assertFalse(evaluate(output, 33))

    def test_wrong_exit_code_even_with_positive_markers(self):
        for code in [0, 1, 35, -15]:
            self.assertFalse(evaluate(PROOF + "\nWOLFOS_BOOT_OK", code))

    def test_partial_or_decorated_markers_never_count(self):
        for proof in [PROOF[:-1], "prefix " + PROOF, PROOF + " forged=1",
                      PROOF.replace("active_rejected=1", "active_rejected=0")]:
            self.assertFalse(evaluate(proof + "\nWOLFOS_BOOT_OK", 33))

    def test_fault_or_kernel_rejection_after_proof_fails(self):
        for error in ["WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_UD",
                      "WOLFOS_EXCEPTION_DF", "WOLFOS_PANIC", "WOLFOS_ADDRESS_SPACE_RETIRE_ERROR",
                      "WOLFOS_ADDRESS_SPACE_RETIRE_TEST_FAILED"]:
            self.assertFalse(evaluate(PROOF + "\n" + error + "\nWOLFOS_BOOT_OK", 33))
