"""Adversarial zero-skip validation of real AP private CR3 serial evidence."""
import unittest
from ap_ring3_elf_smoke import validate

GOOD = (
    "WOLFOS_SMP_APS_OK total=4 bsp_lapic=0 ap_acks=3\n"
    "WOLFOS_BOOT_OK\n"
    "WOLFOS_AP_RING3_ELF_OK cpus=4 target_index=1 "
    "bsp_lapic=0 ap_lapic=1 ap_cpl3=1 linked_elf=1 et_exec=1 pt_load=2 derived_pages=1 int80=2 iret_to_cpl3=1 "
    "private_tss_rsp0=1 actual_tr=1 ap_private_cr3=1 bsp_boot_cr3=1 "
    "kernel_supervisor_pml4=1 boot_user_slot_empty=1 "
    "ap_restored_boot_cr3=1 rx=1 rw_nx=2 frames_pinned=7\n"
)


class ApRing3PrivateCr3EvidenceTests(unittest.TestCase):
    def test_true_evidence(self):
        self.assertTrue(validate(GOOD, 33))

    def test_bad_qemu_exit(self):
        self.assertFalse(validate(GOOD, 0))

    def test_wrong_cpu_count(self):
        self.assertFalse(validate(GOOD.replace("total=4", "total=3"), 33))

    def test_missing_ap_ack(self):
        self.assertFalse(validate(GOOD.replace("ap_acks=3", "ap_acks=2"), 33))

    def test_wrong_cpu_identity(self):
        self.assertFalse(validate(GOOD.replace("ap_lapic=1", "ap_lapic=0"), 33))

    def test_wrong_bsp_identity(self):
        self.assertFalse(validate(GOOD.replace("bsp_lapic=0 ap_lapic", "bsp_lapic=2 ap_lapic"), 33))

    def test_not_linked_elf(self):
        self.assertFalse(validate(GOOD.replace("linked_elf=1", "linked_elf=0"), 33))

    def test_not_et_exec(self):
        self.assertFalse(validate(GOOD.replace("et_exec=1", "et_exec=0"), 33))

    def test_wrong_segment_count(self):
        self.assertFalse(validate(GOOD.replace("pt_load=2", "pt_load=1"), 33))

    def test_no_derived_pages(self):
        self.assertFalse(validate(GOOD.replace("derived_pages=1", "derived_pages=0"), 33))

    def test_no_ring3(self):
        self.assertFalse(validate(GOOD.replace("ap_cpl3=1", "ap_cpl3=0"), 33))

    def test_no_real_private_root(self):
        self.assertFalse(validate(GOOD.replace("ap_private_cr3=1", "ap_private_cr3=0"), 33))

    def test_bsp_not_on_boot_root(self):
        self.assertFalse(validate(GOOD.replace("bsp_boot_cr3=1", "bsp_boot_cr3=0"), 33))

    def test_kernel_user_escalation(self):
        self.assertFalse(validate(GOOD.replace("kernel_supervisor_pml4=1",
                                               "kernel_supervisor_pml4=0"), 33))

    def test_boot_root_user_mapping(self):
        self.assertFalse(validate(GOOD.replace("boot_user_slot_empty=1",
                                               "boot_user_slot_empty=0"), 33))

    def test_no_terminal_restoration(self):
        self.assertFalse(validate(GOOD.replace("ap_restored_boot_cr3=1",
                                               "ap_restored_boot_cr3=0"), 33))

    def test_no_return_to_cpl3(self):
        self.assertFalse(validate(GOOD.replace("iret_to_cpl3=1", "iret_to_cpl3=0"), 33))

    def test_no_trusted_rsp0(self):
        self.assertFalse(validate(GOOD.replace("private_tss_rsp0=1", "private_tss_rsp0=0"), 33))

    def test_wrong_owned_frame_count(self):
        self.assertFalse(validate(GOOD.replace("frames_pinned=7", "frames_pinned=6"), 33))

    def test_fewer_traps(self):
        self.assertFalse(validate(GOOD.replace("int80=2", "int80=1"), 33))

    def test_duplicate_proof(self):
        self.assertFalse(validate(GOOD + GOOD.splitlines()[-1] + "\n", 33))

    def test_missing_boot(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_BOOT_OK", "BOOT"), 33))

    def test_wrong_order(self):
        rows = GOOD.splitlines()
        self.assertFalse(validate("\n".join([rows[2], rows[1], rows[0]]) + "\n", 33))

    def test_forged_extra_field(self):
        self.assertFalse(validate(GOOD.replace("frames_pinned=7",
                                               "frames_pinned=7 extra=1"), 33))

    def test_panic_contaminates_log(self):
        self.assertFalse(validate(GOOD + "WOLFOS_PANIC fault\n", 33))

    def test_fault_contaminates_log(self):
        self.assertFalse(validate(GOOD + "WOLFOS_EXCEPTION_PF fault\n", 33))


if __name__ == "__main__":
    unittest.main()
