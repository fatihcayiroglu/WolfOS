"""Strict forged/valid evidence for VBE full-state equality around real writes."""
import unittest
from qemu_vbe_full_state_smoke import validate

GOOD = (
    "WOLFOS_GPU_DETECTED vendor=1234 device=1111 bus=00 slot=01\n"
    "WOLFOS_PCI_TEST_OK\n"
    "WOLFOS_QEMU_DISPI_PROBE_OK pci=1234:1111 id=b0c5 "
    "xres=1280 yres=800 bpp=32 enabled=65 vram64k=256 "
    "selector_restored=1 mode_writes=0 native_accel=0\n"
    "WOLFOS_QEMU_DISPLAY_ATTEST_OK width=1280 height=800 "
    "pitch=5120 bpp=32 vram64k=256 rgb=1 mode_writes=0\n"
    "WOLFOS_QEMU_VBE_FULL_BEFORE bank=0 virtw=1280 virth=3276 "
    "xoff=0 yoff=0 selector_restored=1 data_writes=0\n"
    "WOLFOS_QEMU_VBE_ENABLE_TX_OK pci=1234:1111 initial=0041 "
    "temporary=00c1 restored=0041 writes=2 selector_restored=1 "
    "geometry_preserved=1 pixel_preserved=1 native_accel=0\n"
    "WOLFOS_QEMU_VBE_FULL_AFTER bank=0 virtw=1280 virth=3276 "
    "xoff=0 yoff=0 selector_restored=1 data_writes=0\n"
    "WOLFOS_QEMU_VBE_FULL_STATE_OK snapshots_equal=1 bank_zero=1 "
    "pan_zero=1 virtual_plane_bounded=1 tx_writes=2 native_accel=0\n"
    "WOLFOS_FB_TEXT_OK glyph_pixels=89 first_pixel=verified\n"
    "WOLFOS_FRAMEBUFFER_OK 1280x800\n"
    "WOLFOS_BOOT_OK\n"
)

class VbeFullStateEvidenceTests(unittest.TestCase):
    def test_realistic_full_state_conservation(self):
        self.assertTrue(validate(GOOD, 33))

    def test_missing_before(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_QEMU_VBE_FULL_BEFORE", "WOLFOS_UNKNOWN_BEFORE"), 33))

    def test_missing_after(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_QEMU_VBE_FULL_AFTER", "WOLFOS_UNKNOWN_AFTER"), 33))

    def test_duplicate_before(self):
        self.assertFalse(validate(GOOD + GOOD.splitlines()[4] + "\n", 33))

    def test_duplicate_after(self):
        self.assertFalse(validate(GOOD + GOOD.splitlines()[6] + "\n", 33))

    def test_before_after_swapped(self):
        rows = GOOD.splitlines()
        rows[4], rows[6] = rows[6], rows[4]
        self.assertFalse(validate("\n".join(rows) + "\n", 33))

    def test_real_mode_must_be_captured_before_control_write(self):
        rows = GOOD.splitlines()
        rows[4], rows[5] = rows[5], rows[4]
        self.assertFalse(validate("\n".join(rows) + "\n", 33))

    def test_after_must_be_before_framebuffer_pixels(self):
        rows = GOOD.splitlines()
        rows[6], rows[8] = rows[8], rows[6]
        self.assertFalse(validate("\n".join(rows) + "\n", 33))

    def test_bank_does_not_change(self):
        self.assertFalse(validate(GOOD.replace("FULL_AFTER bank=0", "FULL_AFTER bank=1"), 33))

    def test_nonzero_bank_cannot_be_used_as_start_state(self):
        self.assertFalse(validate(GOOD.replace("FULL_BEFORE bank=0", "FULL_BEFORE bank=1"), 33))

    def test_horizontal_pan_prohibited(self):
        self.assertFalse(validate(GOOD.replace("xoff=0", "xoff=1"), 33))

    def test_vertical_pan_prohibited(self):
        self.assertFalse(validate(GOOD.replace("yoff=0", "yoff=10"), 33))

    def test_virtual_width_less_than_visible(self):
        self.assertFalse(validate(GOOD.replace("virtw=1280", "virtw=1000"), 33))

    def test_virtual_height_less_than_visible(self):
        self.assertFalse(validate(GOOD.replace("virth=3276", "virth=799"), 33))

    def test_virtual_plane_overflows_vram(self):
        self.assertFalse(validate(GOOD.replace("virth=3276", "virth=5000"), 33))

    def test_virtual_width_not_restored(self):
        self.assertFalse(validate(GOOD.replace("FULL_AFTER bank=0 virtw=1280",
                                               "FULL_AFTER bank=0 virtw=1288"), 33))

    def test_virtual_height_not_restored(self):
        self.assertFalse(validate(GOOD.replace("FULL_AFTER bank=0 virtw=1280 virth=3276",
                                               "FULL_AFTER bank=0 virtw=1280 virth=3275"), 33))

    def test_index_must_be_restored(self):
        self.assertFalse(validate(GOOD.replace("selector_restored=1 data_writes=0",
                                               "selector_restored=0 data_writes=0"), 33))

    def test_no_data_writes_during_snapshot(self):
        self.assertFalse(validate(GOOD.replace("data_writes=0", "data_writes=1"), 33))

    def test_success_marker_requires_exact_proof(self):
        self.assertFalse(validate(GOOD.replace("snapshots_equal=1", "snapshots_equal=0"), 33))

    def test_late_snapshot_failure_invalidates_success(self):
        self.assertFalse(validate(GOOD + "WOLFOS_QEMU_VBE_FULL_FAIL stage=after\n", 33))

    def test_qemu_control_rollback_failure_invalidates_success(self):
        self.assertFalse(validate(GOOD.replace("restored=0041", "restored=00c1"), 33))

    def test_wrong_exit_status(self):
        self.assertFalse(validate(GOOD, 0))

    def test_missing_boot(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_BOOT_OK", "NO_BOOT"), 33))

    def test_no_native_gpu_driver_claim(self):
        self.assertFalse(validate(GOOD + "WOLFOS_GPU_DRIVER_LOADED\n", 33))

if __name__ == "__main__":
    unittest.main()
