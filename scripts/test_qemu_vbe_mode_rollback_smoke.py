"""Strict positive and adversarial parser tests for genuine QEMU mode rollback."""
import unittest
from qemu_vbe_mode_rollback_smoke import validate, MARKER
from test_qemu_vbe_full_state_smoke import GOOD as BASE_GOOD

GOOD = BASE_GOOD.replace(
    "WOLFOS_FB_TEXT_OK",
    MARKER + "\nWOLFOS_FB_TEXT_OK"
)

class VbeModeRollbackEvidenceTests(unittest.TestCase):
    def test_realistic_iso_success(self):
        self.assertTrue(validate(GOOD, 33))

    def test_exit_status_required(self):
        self.assertFalse(validate(GOOD, 0))

    def test_lost_marker(self):
        self.assertFalse(validate(BASE_GOOD, 33))

    def test_duplicate_marker(self):
        self.assertFalse(validate(GOOD + MARKER + "\n", 33))

    def test_repeated_proof_marker(self):
        self.assertFalse(validate(GOOD + "WOLFOS_QEMU_VBE_MODE_ROLLBACK_OK invalid\n", 33))

    def test_mode_writes_must_be_eleven(self):
        self.assertFalse(validate(GOOD.replace("writes=11", "writes=10"), 33))

    def test_physical_gpu_acceleration_claim_disallowed(self):
        self.assertFalse(validate(GOOD.replace("native_accel=0", "native_accel=1"), 33))

    def test_exact_resolutions_required(self):
        self.assertFalse(validate(GOOD.replace("to=1024x768", "to=1280x720"), 33))

    def test_exact_original_restoration_required(self):
        self.assertFalse(validate(GOOD.replace("restored=1280x800", "restored=1024x768"), 33))

    def test_must_use_noclear_on_transient_enable(self):
        self.assertFalse(validate(GOOD.replace("temporary_enable=00c1", "temporary_enable=0041"), 33))

    def test_exact_restored_control_flags(self):
        self.assertFalse(validate(GOOD.replace("restored_enable=0041", "restored_enable=00c1"), 33))

    def test_index_restoration_proof_required(self):
        self.assertFalse(validate(GOOD.replace("selector_restored=1 full_state_restored=1",
                                               "selector_restored=0 full_state_restored=1"), 33))

    def test_full_layout_restoration_proof_required(self):
        self.assertFalse(validate(GOOD.replace("full_state_restored=1", "full_state_restored=0"), 33))

    def test_pixel_witness_required(self):
        self.assertFalse(validate(GOOD.replace("pixel_preserved=1", "pixel_preserved=0"), 33))

    def test_early_switch_before_full_readback_refused(self):
        rows = GOOD.splitlines()
        a = next(i for i, r in enumerate(rows) if r.startswith("WOLFOS_QEMU_VBE_MODE_ROLLBACK_OK"))
        b = next(i for i, r in enumerate(rows) if r.startswith("WOLFOS_QEMU_VBE_FULL_STATE_OK"))
        rows[a], rows[b] = rows[b], rows[a]
        self.assertFalse(validate("\n".join(rows) + "\n", 33))

    def test_late_switch_after_framebuffer_render_refused(self):
        rows = GOOD.splitlines()
        a = next(i for i, r in enumerate(rows) if r.startswith("WOLFOS_QEMU_VBE_MODE_ROLLBACK_OK"))
        b = next(i for i, r in enumerate(rows) if r.startswith("WOLFOS_FB_TEXT_OK"))
        rows[a], rows[b] = rows[b], rows[a]
        self.assertFalse(validate("\n".join(rows) + "\n", 33))

    def test_preexisting_full_state_failure_refused(self):
        self.assertFalse(validate(GOOD + "WOLFOS_QEMU_VBE_FULL_FAIL stage=after\n", 33))

    def test_native_mode_rollback_failure_refused(self):
        self.assertFalse(validate(GOOD + "WOLFOS_QEMU_VBE_MODE_ROLLBACK_FAIL stage=verified\n", 33))

    def test_mode_rollback_test_failure_refused(self):
        self.assertFalse(validate(GOOD + "WOLFOS_QEMU_VBE_MODE_ROLLBACK_TEST_FAILED\n", 33))

    def test_invalid_virtual_width_in_previous_proof(self):
        self.assertFalse(validate(GOOD.replace("FULL_AFTER bank=0 virtw=1280",
                                               "FULL_AFTER bank=0 virtw=1288"), 33))

    def test_wrong_pci_device_in_previous_proof(self):
        self.assertFalse(validate(GOOD.replace("pci=1234:1111", "pci=10de:2684"), 33))

    def test_no_boot_refused(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_BOOT_OK", "NO_BOOT"), 33))

    def test_no_fake_green_with_native_driver_marker(self):
        self.assertFalse(validate(GOOD + "WOLFOS_GPU_DRIVER_LOADED\n", 33))

    def test_extra_success_text_not_accepted(self):
        self.assertFalse(validate(GOOD.replace(MARKER, MARKER + " extra=1"), 33))

if __name__ == "__main__":
    unittest.main()
