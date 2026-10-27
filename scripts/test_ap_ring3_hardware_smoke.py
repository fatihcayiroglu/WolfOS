"""Reject fake-green AP hardware Ring3/INT80/IRETQ QEMU evidence."""
import unittest
from ap_ring3_hardware_smoke import validate

GOOD = (
    "WOLFOS_SMP_APS_OK total=4 bsp_lapic=0 ap_acks=3\n"
    "WOLFOS_BOOT_OK\n"
    "WOLFOS_AP_RING3_OK cpus=4 target_index=1 bsp_lapic=0 ap_lapic=1 "
    "ap_cpl3=1 int80=2 iret_to_cpl3=1 private_tss_rsp0=1 actual_tr=1 "
    "rw_nx=2 rx=1 frames_pinned=6\n"
)


class ApRing3HardwareEvidenceTests(unittest.TestCase):
    def test_true_evidence(self):
        self.assertTrue(validate(GOOD, 33))

    def test_wrong_exit(self):
        self.assertFalse(validate(GOOD, 0))

    def test_missing_boot(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_BOOT_OK", "HOST_BOOT"), 33))

    def test_bsp_instead_of_ap(self):
        self.assertFalse(validate(GOOD.replace("ap_lapic=1", "ap_lapic=0"), 33))

    def test_wrong_bsp_identity(self):
        self.assertFalse(validate(GOOD.replace("bsp_lapic=0 ap_lapic", "bsp_lapic=2 ap_lapic"), 33))

    def test_only_single_vcpu(self):
        self.assertFalse(validate(GOOD.replace("total=4", "total=1"), 33))

    def test_ap_ack_missing(self):
        self.assertFalse(validate(GOOD.replace("ap_acks=3", "ap_acks=2"), 33))

    def test_no_real_cpl3(self):
        self.assertFalse(validate(GOOD.replace("ap_cpl3=1", "ap_cpl3=0"), 33))

    def test_single_syscall(self):
        self.assertFalse(validate(GOOD.replace("int80=2", "int80=1"), 33))

    def test_no_iret_resume(self):
        self.assertFalse(validate(GOOD.replace("iret_to_cpl3=1", "iret_to_cpl3=0"), 33))

    def test_missing_private_tss(self):
        self.assertFalse(validate(GOOD.replace("private_tss_rsp0=1", "private_tss_rsp0=0"), 33))

    def test_missing_actual_tr(self):
        self.assertFalse(validate(GOOD.replace("actual_tr=1", "actual_tr=0"), 33))

    def test_wrong_pmms(self):
        self.assertFalse(validate(GOOD.replace("frames_pinned=6", "frames_pinned=0"), 33))

    def test_duplicate_proof(self):
        self.assertFalse(validate(GOOD + GOOD.splitlines()[-1] + "\n", 33))

    def test_duplicate_smp(self):
        self.assertFalse(validate(GOOD + GOOD.splitlines()[0] + "\n", 33))

    def test_wrong_order(self):
        rows = GOOD.splitlines()
        self.assertFalse(validate("\n".join([rows[0], rows[2], rows[1]]) + "\n", 33))

    def test_fatal_gp(self):
        self.assertFalse(validate(GOOD + "WOLFOS_EXCEPTION_GP illegal\n", 33))

    def test_forged_extra_marker_field(self):
        self.assertFalse(validate(GOOD.replace("frames_pinned=6", "frames_pinned=6 extra=1"), 33))


if __name__ == "__main__":
    unittest.main()
