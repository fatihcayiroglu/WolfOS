"""Synthetic adversarial evidence for a real, reversible QEMU VBE control write."""
import unittest
from qemu_vbe_enable_tx_smoke import validate

GOOD = (
    "WOLFOS_GPU_DETECTED vendor=1234 device=1111 bus=00 slot=01\n"
    "WOLFOS_PCI_TEST_OK\n"
    "WOLFOS_QEMU_DISPI_PROBE_OK pci=1234:1111 id=b0c5 "
    "xres=1280 yres=800 bpp=32 enabled=65 vram64k=256 "
    "selector_restored=1 mode_writes=0 native_accel=0\n"
    "WOLFOS_QEMU_DISPLAY_ATTEST_OK width=1280 height=800 "
    "pitch=5120 bpp=32 vram64k=256 rgb=1 mode_writes=0\n"
    "WOLFOS_QEMU_VBE_ENABLE_TX_OK pci=1234:1111 initial=0041 "
    "temporary=00c1 restored=0041 writes=2 selector_restored=1 "
    "geometry_preserved=1 pixel_preserved=1 native_accel=0\n"
    "WOLFOS_FB_TEXT_OK glyph_pixels=89 first_pixel=verified\n"
    "WOLFOS_FRAMEBUFFER_OK 1280x800\n"
    "WOLFOS_BOOT_OK\n"
)

class TransactionEvidenceTests(unittest.TestCase):
    def test_realistic_reversible_transaction(self):
        self.assertTrue(validate(GOOD, 33))

    def test_wrong_qemu_exit(self):
        self.assertFalse(validate(GOOD, 0))

    def test_missing_tx_marker(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_QEMU_VBE_ENABLE_TX_OK", "WOLFOS_TX_UNKNOWN"), 33))

    def test_duplicate_tx_marker(self):
        self.assertFalse(validate(GOOD + GOOD.splitlines()[4] + "\n", 33))

    def test_bogus_extra_field(self):
        self.assertFalse(validate(GOOD.replace("pixel_preserved=1 native_accel=0",
                                               "pixel_preserved=1 native_accel=0 dma=1"), 33))

    def test_incorrect_original_control(self):
        self.assertFalse(validate(GOOD.replace("initial=0041", "initial=0040"), 33))

    def test_incorrect_temporary_control(self):
        self.assertFalse(validate(GOOD.replace("temporary=00c1", "temporary=0041"), 33))

    def test_incorrect_rollback_control(self):
        self.assertFalse(validate(GOOD.replace("restored=0041", "restored=00c1"), 33))

    def test_transaction_write_count_is_exact(self):
        for count in (0, 1, 3, 65535):
            self.assertFalse(validate(GOOD.replace("writes=2", f"writes={count}"), 33))

    def test_selector_not_restored(self):
        self.assertFalse(validate(GOOD.replace("writes=2 selector_restored=1",
                                               "writes=2 selector_restored=0"), 33))

    def test_geometry_changed_during_transaction(self):
        self.assertFalse(validate(GOOD.replace("geometry_preserved=1", "geometry_preserved=0"), 33))

    def test_framebuffer_pixel_was_erased(self):
        self.assertFalse(validate(GOOD.replace("pixel_preserved=1", "pixel_preserved=0"), 33))

    def test_accelerated_claim_fails(self):
        self.assertFalse(validate(GOOD.replace("pixel_preserved=1 native_accel=0",
                                               "pixel_preserved=1 native_accel=1"), 33))

    def test_wrong_pci_device(self):
        self.assertFalse(validate(GOOD.replace("TX_OK pci=1234:1111",
                                               "TX_OK pci=10de:1234"), 33))

    def test_tx_before_hw_attestation(self):
        rows = GOOD.splitlines()
        rows[3], rows[4] = rows[4], rows[3]
        self.assertFalse(validate("\n".join(rows) + "\n", 33))

    def test_tx_after_framebuffer_paint(self):
        rows = GOOD.splitlines()
        rows[4], rows[5] = rows[5], rows[4]
        self.assertFalse(validate("\n".join(rows) + "\n", 33))

    def test_fail_marker_after_success(self):
        self.assertFalse(validate(GOOD + "WOLFOS_QEMU_VBE_ENABLE_TX_FAIL stage=rollback\n", 33))

    def test_failed_guest_tx_gate(self):
        self.assertFalse(validate(GOOD + "WOLFOS_QEMU_VBE_ENABLE_TX_TEST_FAILED\n", 33))

    def test_unverified_graphics_claim(self):
        self.assertFalse(validate(GOOD + "WOLFOS_GPU_DRIVER_LOADED\n", 33))

    def test_missing_first_read_only_evidence(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_QEMU_DISPI_PROBE_OK",
                                               "WOLFOS_QEMU_DISPI_PROBE_FAIL"), 33))

    def test_wrong_framebuffer_dimensions(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_FRAMEBUFFER_OK 1280x800",
                                               "WOLFOS_FRAMEBUFFER_OK 1024x768"), 33))

    def test_wrong_vram_attestation(self):
        self.assertFalse(validate(GOOD.replace("pitch=5120 bpp=32 vram64k=256",
                                               "pitch=5120 bpp=32 vram64k=1"), 33))

    def test_duplicate_boot(self):
        self.assertFalse(validate(GOOD + "WOLFOS_BOOT_OK\n", 33))

    def test_tx_only_without_boot(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_BOOT_OK", "NO_BOOT"), 33))

if __name__ == "__main__":
    unittest.main()
