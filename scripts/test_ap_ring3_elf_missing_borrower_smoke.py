"""Strict QEMU evidence for a genuinely held AP private CR3 and refused PMM reclaim."""
import unittest
from ap_ring3_elf_missing_borrower_smoke import validate

GOOD = (
    "WOLFOS_SMP_APS_OK total=4 bsp_lapic=0 ap_acks=3\n"
    "WOLFOS_BOOT_OK\n"
    "WOLFOS_AP_RING3_RECLAIM_FAIL stage=borrowers_still_live\n"
    "WOLFOS_AP_RING3_ELF_MISSING_BORROWER_OK cpus=4 target_index=1 bsp_lapic=0 ap_lapic=1 linked_elf=1 et_exec=1 pt_load=2 ap_cpl3=1 int80=2 iret_to_cpl3=1 ap_private_cr3=1 ap_restored_boot_cr3=1 cpl0_borrowers=2 borrower_cr3_entered=2 borrower_cr3_departed=1 borrower_held_private_cr3=1 all_user_cr3_departed=0 reclaim_refused=1 frames_pinned=7 frames_freed=0 pmm_held_lease=1 bsp_boot_cr3=1\n"
)

class MissingBorrowerTests(unittest.TestCase):
    def test_exact_negative_hardware_proof(self):
        self.assertTrue(validate(GOOD, 33))

    def test_wrong_exit(self):
        self.assertFalse(validate(GOOD, 0))

    def test_missing_ap_ack(self):
        self.assertFalse(validate(GOOD.replace("ap_acks=3", "ap_acks=2"), 33))

    def test_wrong_cpu_total(self):
        self.assertFalse(validate(GOOD.replace("total=4", "total=3"), 33))

    def test_wrong_bsp_lapic(self):
        self.assertFalse(validate(GOOD.replace("bsp_lapic=0 ap_lapic", "bsp_lapic=2 ap_lapic"), 33))

    def test_same_target_bsp(self):
        self.assertFalse(validate(GOOD.replace("target_index=1", "target_index=0"), 33))

    def test_target_wrong_lapic(self):
        self.assertFalse(validate(GOOD.replace("ap_lapic=1", "ap_lapic=0"), 33))

    def test_missing_elf(self):
        self.assertFalse(validate(GOOD.replace("linked_elf=1", "linked_elf=0"), 33))

    def test_not_et_exec(self):
        self.assertFalse(validate(GOOD.replace("et_exec=1", "et_exec=0"), 33))

    def test_wrong_load_count(self):
        self.assertFalse(validate(GOOD.replace("pt_load=2", "pt_load=1"), 33))

    def test_fake_ring3(self):
        self.assertFalse(validate(GOOD.replace("ap_cpl3=1", "ap_cpl3=0"), 33))

    def test_one_trap(self):
        self.assertFalse(validate(GOOD.replace("int80=2", "int80=1"), 33))

    def test_no_iret(self):
        self.assertFalse(validate(GOOD.replace("iret_to_cpl3=1", "iret_to_cpl3=0"), 33))

    def test_no_private_root(self):
        self.assertFalse(validate(GOOD.replace("ap_private_cr3=1", "ap_private_cr3=0"), 33))

    def test_target_not_departed(self):
        self.assertFalse(validate(GOOD.replace("ap_restored_boot_cr3=1", "ap_restored_boot_cr3=0"), 33))

    def test_only_one_borrower(self):
        self.assertFalse(validate(GOOD.replace("cpl0_borrowers=2", "cpl0_borrowers=1"), 33))

    def test_one_borrower_not_entered(self):
        self.assertFalse(validate(GOOD.replace("borrower_cr3_entered=2", "borrower_cr3_entered=1"), 33))

    def test_both_departed(self):
        self.assertFalse(validate(GOOD.replace("borrower_cr3_departed=1", "borrower_cr3_departed=2"), 33))

    def test_none_departed(self):
        self.assertFalse(validate(GOOD.replace("borrower_cr3_departed=1", "borrower_cr3_departed=0"), 33))

    def test_no_held_private_root(self):
        self.assertFalse(validate(GOOD.replace("borrower_held_private_cr3=1", "borrower_held_private_cr3=0"), 33))

    def test_false_root_empty(self):
        self.assertFalse(validate(GOOD.replace("all_user_cr3_departed=0", "all_user_cr3_departed=1"), 33))

    def test_no_refusal(self):
        self.assertFalse(validate(GOOD.replace("reclaim_refused=1", "reclaim_refused=0"), 33))

    def test_partial_free(self):
        self.assertFalse(validate(GOOD.replace("frames_freed=0", "frames_freed=1"), 33))

    def test_pinned_only_six(self):
        self.assertFalse(validate(GOOD.replace("frames_pinned=7", "frames_pinned=6"), 33))

    def test_missing_pmm_lease(self):
        self.assertFalse(validate(GOOD.replace("pmm_held_lease=1", "pmm_held_lease=0"), 33))

    def test_bsp_private_cr3(self):
        self.assertFalse(validate(GOOD.replace("bsp_boot_cr3=1", "bsp_boot_cr3=0"), 33))

    def test_wrong_reject_stage(self):
        self.assertFalse(validate(GOOD.replace("stage=borrowers_still_live", "stage=mapping"), 33))

    def test_missing_rejection(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_AP_RING3_RECLAIM_FAIL stage=borrowers_still_live\n", ""), 33))

    def test_duplicate_rejection(self):
        self.assertFalse(validate(GOOD + "WOLFOS_AP_RING3_RECLAIM_FAIL stage=borrowers_still_live\n", 33))

    def test_duplicate_proof(self):
        self.assertFalse(validate(GOOD + GOOD.splitlines()[-1] + "\n", 33))

    def test_duplicate_boot(self):
        self.assertFalse(validate(GOOD + "WOLFOS_BOOT_OK\n", 33))

    def test_no_boot(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_BOOT_OK", "BOOT"), 33))

    def test_bad_order(self):
        rows = GOOD.splitlines()
        self.assertFalse(validate("\n".join([rows[0], rows[1], rows[3], rows[2]]) + "\n", 33))

    def test_extra_success_field(self):
        self.assertFalse(validate(GOOD.replace("pmm_held_lease=1", "pmm_held_lease=1 extra=1"), 33))

    def test_generic_ap_error(self):
        self.assertFalse(validate(GOOD + "WOLFOS_AP_RING3_ERROR\n", 33))

    def test_guest_panic(self):
        self.assertFalse(validate(GOOD + "WOLFOS_PANIC\n", 33))

    def test_real_page_fault(self):
        self.assertFalse(validate(GOOD + "WOLFOS_EXCEPTION_PF\n", 33))

    def test_faked_normal_reclaim(self):
        self.assertFalse(validate(GOOD + "WOLFOS_AP_RING3_ELF_MULTI_REAP_OK\n", 33))

    def test_extra_failure_stage(self):
        self.assertFalse(validate(GOOD + "WOLFOS_AP_RING3_RECLAIM_FAIL stage=lease\n", 33))

if __name__ == "__main__":
    unittest.main()
