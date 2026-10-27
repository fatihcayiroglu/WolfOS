"""Negative and true-evidence checks for AP Ring3 ELF with two CPL0 borrowers."""
import unittest
from ap_ring3_elf_multi_owner_smoke import validate

GOOD = (
    "WOLFOS_SMP_APS_OK total=4 bsp_lapic=0 ap_acks=3\n"
    "WOLFOS_BOOT_OK\n"
    "WOLFOS_AP_RING3_ELF_MULTI_REAP_OK cpus=4 target_index=1 "
    "bsp_lapic=0 ap_lapic=1 linked_elf=1 et_exec=1 pt_load=2 "
    "ap_cpl3=1 int80=2 iret_to_cpl3=1 ap_private_cr3=1 "
    "ap_restored_boot_cr3=1 cpl0_borrowers=2 borrower_cr3_entered=2 "
    "borrower_cr3_departed=2 all_user_cr3_departed=1 cr3_flushes=3 "
    "bsp_boot_cr3=1 root_exclusive_after_departure=1 "
    "high_half_supervisor=1 boot_user_slot_empty=1 "
    "scrubbed=7 frames_freed=7 pmm_no_leak=1 "
    "stale_root_revoked=1 double_free_denied=1\n"
)


class ApRing3ElfMultiOwnerTests(unittest.TestCase):
    def test_exact_real_evidence(self):
        self.assertTrue(validate(GOOD, 33))

    def test_bad_qemu_exit(self):
        self.assertFalse(validate(GOOD, 0))

    def test_bsp_instead_of_ap(self):
        self.assertFalse(validate(GOOD.replace("ap_lapic=1", "ap_lapic=0"), 33))

    def test_wrong_bsp_identity(self):
        self.assertFalse(validate(GOOD.replace("bsp_lapic=0 ap_lapic", "bsp_lapic=2 ap_lapic"), 33))

    def test_single_cpu(self):
        self.assertFalse(validate(GOOD.replace("total=4", "total=1"), 33))

    def test_ap_ack_missing(self):
        self.assertFalse(validate(GOOD.replace("ap_acks=3", "ap_acks=2"), 33))

    def test_missing_boot(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_BOOT_OK", "BOOT"), 33))

    def test_duplicate_boot(self):
        self.assertFalse(validate(GOOD + "WOLFOS_BOOT_OK\n", 33))

    def test_duplicate_proof(self):
        self.assertFalse(validate(GOOD + GOOD.splitlines()[-1] + "\n", 33))

    def test_wrong_order(self):
        rows = GOOD.splitlines()
        self.assertFalse(validate("\n".join([rows[2], rows[0], rows[1]]) + "\n", 33))

    def test_not_elf(self):
        self.assertFalse(validate(GOOD.replace("linked_elf=1", "linked_elf=0"), 33))

    def test_wrong_pt_load_count(self):
        self.assertFalse(validate(GOOD.replace("pt_load=2", "pt_load=1"), 33))

    def test_no_ring3(self):
        self.assertFalse(validate(GOOD.replace("ap_cpl3=1", "ap_cpl3=0"), 33))

    def test_single_trap(self):
        self.assertFalse(validate(GOOD.replace("int80=2", "int80=1"), 33))

    def test_no_iret(self):
        self.assertFalse(validate(GOOD.replace("iret_to_cpl3=1", "iret_to_cpl3=0"), 33))

    def test_wrong_private_root(self):
        self.assertFalse(validate(GOOD.replace("ap_private_cr3=1", "ap_private_cr3=0"), 33))

    def test_still_on_private_root(self):
        self.assertFalse(validate(GOOD.replace("ap_restored_boot_cr3=1", "ap_restored_boot_cr3=0"), 33))

    def test_bsp_switched_root(self):
        self.assertFalse(validate(GOOD.replace("bsp_boot_cr3=1", "bsp_boot_cr3=0"), 33))

    def test_root_still_borrowed_after_departure(self):
        self.assertFalse(validate(GOOD.replace("root_exclusive_after_departure=1", "root_exclusive_after_departure=0"), 33))

    def test_missing_cr3_flush(self):
        self.assertFalse(validate(GOOD.replace("cr3_flushes=3", "cr3_flushes=2"), 33))

    def test_kernel_user_accessible(self):
        self.assertFalse(validate(GOOD.replace("high_half_supervisor=1", "high_half_supervisor=0"), 33))

    def test_boot_root_user_mapping(self):
        self.assertFalse(validate(GOOD.replace("boot_user_slot_empty=1", "boot_user_slot_empty=0"), 33))

    def test_unscrubbed(self):
        self.assertFalse(validate(GOOD.replace("scrubbed=7", "scrubbed=6"), 33))

    def test_partial_free(self):
        self.assertFalse(validate(GOOD.replace("frames_freed=7", "frames_freed=6"), 33))

    def test_pmm_leak(self):
        self.assertFalse(validate(GOOD.replace("pmm_no_leak=1", "pmm_no_leak=0"), 33))

    def test_stale_root_not_revoked(self):
        self.assertFalse(validate(GOOD.replace("stale_root_revoked=1", "stale_root_revoked=0"), 33))

    def test_double_free_undetected(self):
        self.assertFalse(validate(GOOD.replace("double_free_denied=1", "double_free_denied=0"), 33))

    def test_appended_fake_field(self):
        self.assertFalse(validate(GOOD.replace("double_free_denied=1",
                                               "double_free_denied=1 extra=1"), 33))

    def test_guest_panic(self):
        self.assertFalse(validate(GOOD + "WOLFOS_PANIC\n", 33))

    def test_real_page_fault(self):
        self.assertFalse(validate(GOOD + "WOLFOS_EXCEPTION_PF\n", 33))

    def test_only_one_borrower(self):
        self.assertFalse(validate(GOOD.replace("cpl0_borrowers=2", "cpl0_borrowers=1"), 33))

    def test_too_many_borrowers(self):
        self.assertFalse(validate(GOOD.replace("cpl0_borrowers=2", "cpl0_borrowers=3"), 33))

    def test_second_borrower_never_loaded_private_root(self):
        self.assertFalse(validate(GOOD.replace("borrower_cr3_entered=2",
                                               "borrower_cr3_entered=1"), 33))

    def test_second_borrower_never_restored_supervisor_root(self):
        self.assertFalse(validate(GOOD.replace("borrower_cr3_departed=2",
                                               "borrower_cr3_departed=1"), 33))

    def test_any_private_root_still_loaded(self):
        self.assertFalse(validate(GOOD.replace("all_user_cr3_departed=1",
                                               "all_user_cr3_departed=0"), 33))

    def test_missing_two_cr3_flushes(self):
        self.assertFalse(validate(GOOD.replace("cr3_flushes=3", "cr3_flushes=1"), 33))

    def test_error_marker_after_proof(self):
        self.assertFalse(validate(GOOD + "WOLFOS_AP_RING3_RECLAIM_FAIL stage=lease\n", 33))

    def test_undelimited_false_proof_suffix(self):
        self.assertFalse(validate(GOOD.replace("cpl0_borrowers=2",
                                               "cpl0_borrowers=2xyz"), 33))



if __name__ == "__main__":
    unittest.main()
