"""Reject absent, forged, reordered and failed hardware-run evidence."""
import unittest
from scripts.address_space_retirement_smoke import PROOF, SMP_PROOF, OWNERSHIP_PROOF, evaluate

SMP_OUTPUT = OWNERSHIP_PROOF + "\n" + SMP_PROOF + "\nWOLFOS_BOOT_OK"


class RetirementEvidenceTests(unittest.TestCase):
    def test_smp_requires_its_own_complete_proof(self):
        self.assertTrue(evaluate(SMP_OUTPUT, 33, smp=True))
        self.assertFalse(evaluate(PROOF + "\nWOLFOS_BOOT_OK", 33, smp=True))
        self.assertFalse(evaluate(SMP_PROOF + "\nWOLFOS_BOOT_OK", 33))

    def test_smp_rejects_missing_cpu_or_unproven_last_ap(self):
        for proof in [SMP_PROOF.replace("per_cpu_restored=4", "per_cpu_restored=3"),
                      SMP_PROOF.replace("last_ap_rejected=1", "last_ap_rejected=0"),
                      SMP_PROOF + "\n" + SMP_PROOF, "prefix " + SMP_PROOF]:
            self.assertFalse(evaluate(OWNERSHIP_PROOF + "\n" + proof + "\nWOLFOS_BOOT_OK", 33, smp=True))

    def test_smp_fault_exit_and_order_are_required(self):
        for output, code in [(SMP_OUTPUT, 35),
                             ("WOLFOS_BOOT_OK\n" + OWNERSHIP_PROOF + "\n" + SMP_PROOF, 33),
                             (SMP_OUTPUT + "\nWOLFOS_SMP_RETIRE_ERROR", 33),
                             (SMP_OUTPUT + "\nWOLFOS_SMP_RETIRE_TEST_FAILED", 33)]:
            self.assertFalse(evaluate(output, code, smp=True))

    def test_smp_requires_exact_ownership_and_active_drop_evidence(self):
        for proof in ["", OWNERSHIP_PROOF.replace("active_drop_retained=1", "active_drop_retained=0"),
                      OWNERSHIP_PROOF.replace("last_ap_pinned=1", "last_ap_pinned=0"),
                      OWNERSHIP_PROOF.replace("retired_owner_freed=1", "retired_owner_freed=0"),
                      "prefix " + OWNERSHIP_PROOF, OWNERSHIP_PROOF + " forged=1"]:
            self.assertFalse(evaluate(proof + "\n" + SMP_PROOF + "\nWOLFOS_BOOT_OK", 33, smp=True))

    def test_smp_rejects_duplicate_or_out_of_order_ownership(self):
        for output in [OWNERSHIP_PROOF + "\n" + SMP_OUTPUT,
                       SMP_PROOF + "\n" + OWNERSHIP_PROOF + "\nWOLFOS_BOOT_OK",
                       SMP_PROOF + "\nWOLFOS_BOOT_OK\n" + OWNERSHIP_PROOF]:
            self.assertFalse(evaluate(output, 33, smp=True))

    def test_ownership_proof_cannot_hide_a_hardware_fault(self):
        for error in ["WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_UD",
                      "WOLFOS_EXCEPTION_DF", "WOLFOS_PANIC"]:
            self.assertFalse(evaluate(SMP_OUTPUT + "\n" + error, 33, smp=True))

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
