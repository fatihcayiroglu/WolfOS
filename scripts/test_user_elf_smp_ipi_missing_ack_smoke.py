"""Fail-closed adversarial evidence for the real missing-AP-IPI QEMU flavor."""
import unittest

from user_elf_smp_ipi_retire_smoke import ACTIVATION
from user_elf_smp_ipi_missing_ack_smoke import BLOCKED, EXIT, PROOF, validate

GOOD = (
    "WOLFOS_SMP_APS_OK total=4 bsp_lapic=0 ap_acks=3\n"
    + "WOLFOS_BOOT_OK\n" + ACTIVATION + "\n" + EXIT + "\n"
    + BLOCKED + "\n" + PROOF + "\n"
)


class MissingAckEvidenceTests(unittest.TestCase):
    def test_real_negative_witness(self):
        self.assertTrue(validate(GOOD, 33))

    def test_wrong_qemu_exit(self):
        self.assertFalse(validate(GOOD, 0))

    def test_not_four_cpus(self):
        self.assertFalse(validate(GOOD.replace("total=4 bsp_lapic=0 ap_acks=3", "total=2 bsp_lapic=0 ap_acks=1"), 33))

    def test_missing_ap_ack(self):
        self.assertFalse(validate(GOOD.replace("ap_acks=3", "ap_acks=2"), 33))

    def test_duplicate_ap_evidence(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_BOOT_OK",
                                       "WOLFOS_SMP_APS_OK total=4 bsp_lapic=0 ap_acks=3\nWOLFOS_BOOT_OK"), 33))

    def test_missing_boot(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_BOOT_OK", "BOOT"), 33))

    def test_no_real_ring3(self):
        self.assertFalse(validate(GOOD.replace(EXIT, ""), 33))

    def test_missing_owner_block(self):
        self.assertFalse(validate(GOOD.replace(BLOCKED, ""), 33))

    def test_missing_first_remote_eoi(self):
        self.assertFalse(validate(GOOD.replace("remote_eois=2", "remote_eois=1"), 33))

    def test_missing_remote_ipi(self):
        self.assertFalse(validate(GOOD.replace("remote_ipis_sent=2", "remote_ipis_sent=1"), 33))

    def test_last_ipi_delivered(self):
        self.assertFalse(validate(GOOD.replace("last_ipi_sent=0", "last_ipi_sent=1"), 33))

    def test_early_frame_free(self):
        self.assertFalse(validate(GOOD.replace("premature_free=0", "premature_free=1"), 33))

    def test_incorrect_frame_count(self):
        self.assertFalse(validate(GOOD.replace("frames_pinned=7", "frames_pinned=6"), 33))

    def test_last_ap_offline(self):
        self.assertFalse(validate(GOOD.replace("last_ap_online=1", "last_ap_online=0"), 33))

    def test_duplicate_evidence(self):
        self.assertFalse(validate(GOOD + PROOF + "\n", 33))

    def test_wrong_event_order(self):
        self.assertFalse(validate(GOOD.replace(EXIT, "X").replace(BLOCKED, EXIT)
                                  .replace("X", BLOCKED), 33))

    def test_cleanup_is_forbidden(self):
        self.assertFalse(validate(GOOD + "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1\n", 33))

    def test_fake_successful_reclaim(self):
        self.assertFalse(validate(GOOD + "WOLFOS_ELF_SMP_IPI_REAP_OK fraudulent\n", 33))

    def test_fatal_trap(self):
        self.assertFalse(validate(GOOD + "WOLFOS_EXCEPTION_PF crash\n", 33))

    def test_forged_prefix(self):
        self.assertFalse(validate(GOOD.replace(PROOF, PROOF + " extra=1"), 33))


if __name__ == "__main__":
    unittest.main()
