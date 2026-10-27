"""Fail-closed parser tests for real ELF + remote owner-bound AP IPI."""
import unittest

from user_elf_smp_ipi_retire_smoke import PROOF, ACTIVATION, TLB, validate

GOOD = (
    "WOLFOS_SMP_APS_OK total=4 aps=3\n"
    "WOLFOS_BOOT_OK\n" + ACTIVATION + "\n"
    "WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=22\n"
    + TLB + "\n" + PROOF + "\n"
    "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1\n"
)


class RealUserOwnerIpiEvidenceTests(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(validate(GOOD, 33))

    def test_wrong_exit(self):
        self.assertFalse(validate(GOOD, 0))

    def test_missing_ap(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_SMP_APS_OK", "HOST_SMP"), 33))

    def test_missing_real_ring3_exit(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_ELF_EXIT_OK", "HOST_ELF_EXIT_OK"), 33))

    def test_remote_ipi_count_mutated(self):
        self.assertFalse(validate(GOOD.replace("remote_ipis=3", "remote_ipis=2"), 33))

    def test_duplicate_proof(self):
        self.assertFalse(validate(GOOD.replace(PROOF, PROOF + "\n" + PROOF), 33))

    def test_tlb_missing(self):
        self.assertFalse(validate(GOOD.replace(TLB, ""), 33))

    def test_ap_cpl3_false_claim(self):
        self.assertFalse(validate(GOOD.replace("ap_cpl0_root_borrowers=3", "ap_cpl3_root_borrowers=3"), 33))

    def test_fault(self):
        self.assertFalse(validate(GOOD + "WOLFOS_PANIC leaked\n", 33))

    def test_wrong_marker_order(self):
        self.assertFalse(validate(GOOD.replace(ACTIVATION, "HOLDER").replace(
            TLB, ACTIVATION).replace("HOLDER", TLB), 33))


if __name__ == "__main__":
    unittest.main()
