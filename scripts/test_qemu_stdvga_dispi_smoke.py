"""Strict positive/negative evidence for QEMU stdvga DISPI port access."""
import unittest
from qemu_stdvga_dispi_smoke import validate

GOOD = (
    "WOLFOS_GPU_DETECTED vendor=1234 device=1111 bus=00 slot=01\n"
    "WOLFOS_PCI_TEST_OK\n"
    "WOLFOS_QEMU_DISPI_PROBE_OK pci=1234:1111 id=b0c5 "
    "xres=1024 yres=768 bpp=32 enabled=65 vram64k=256 "
    "selector_restored=1 mode_writes=0 native_accel=0\n"
    "WOLFOS_QEMU_DISPLAY_ATTEST_OK width=1024 height=768 "
    "pitch=4096 bpp=32 vram64k=256 rgb=1 mode_writes=0\n"
    "WOLFOS_FB_TEXT_OK glyph_pixels=89 first_pixel=verified\n"
    "WOLFOS_FRAMEBUFFER_OK 1024x768\n"
    "WOLFOS_BOOT_OK\n"
)

class QemuDispiEvidenceTests(unittest.TestCase):
    def test_genuine_observation(self):
        self.assertTrue(validate(GOOD, 33))

    def test_missing_gpu(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_GPU_DETECTED", "WOLFOS_GPU_UNKNOWN"), 33))

    def test_bad_pci_id(self):
        self.assertFalse(validate(GOOD.replace("pci=1234:1111", "pci=10de:1111"), 33))

    def test_bad_gpu_identity(self):
        self.assertFalse(validate(GOOD.replace("vendor=1234 device=1111", "vendor=1234 device=2222"), 33))

    def test_wrong_io_id(self):
        self.assertFalse(validate(GOOD.replace("id=b0c5", "id=0000"), 33))

    def test_id_out_of_range(self):
        self.assertFalse(validate(GOOD.replace("id=b0c5", "id=b0c6"), 33))

    def test_id_too_low(self):
        self.assertFalse(validate(GOOD.replace("id=b0c5", "id=b0bf"), 33))

    def test_id_junk(self):
        self.assertFalse(validate(GOOD.replace("id=b0c5", "id=zzzz"), 33))

    def test_zero_vram(self):
        self.assertFalse(validate(GOOD.replace("vram64k=256", "vram64k=0"), 33))

    def test_huge_vram(self):
        self.assertFalse(validate(GOOD.replace("vram64k=256", "vram64k=65536"), 33))

    def test_missing_xres(self):
        self.assertFalse(validate(GOOD.replace("xres=1024", "xres=0"), 33))

    def test_missing_yres(self):
        self.assertFalse(validate(GOOD.replace("yres=768", "yres=0"), 33))

    def test_too_wide(self):
        self.assertFalse(validate(GOOD.replace("xres=1024", "xres=8193"), 33))

    def test_too_tall(self):
        self.assertFalse(validate(GOOD.replace("yres=768", "yres=8193"), 33))

    def test_unsupported_bpp(self):
        self.assertFalse(validate(GOOD.replace("bpp=32", "bpp=30"), 33))

    def test_insufficient_vram(self):
        self.assertFalse(validate(GOOD.replace("vram64k=256", "vram64k=1"), 33))

    def test_selector_not_restored(self):
        self.assertFalse(validate(GOOD.replace("selector_restored=1", "selector_restored=0"), 33))

    def test_mode_written(self):
        self.assertFalse(validate(GOOD.replace("mode_writes=0", "mode_writes=1"), 33))

    def test_accelerated_claim(self):
        self.assertFalse(validate(GOOD.replace("native_accel=0", "native_accel=1"), 33))

    def test_extra_field(self):
        self.assertFalse(validate(GOOD.replace("native_accel=0", "native_accel=0 dma=1"), 33))

    def test_malformed_pci_marker(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_PCI_TEST_OK", "WOLFOS_PCI_TEST_FAIL"), 33))

    def test_wrong_hex_case(self):
        self.assertFalse(validate(GOOD.replace("id=b0c5", "id=B0C5"), 33))

    def test_premature_proof(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_QEMU_DISPI_PROBE_OK", "WOLFOS_QEMU_DISPI_PROBE_FAIL"), 33))

    def test_wrong_exit(self):
        self.assertFalse(validate(GOOD, 0))

    def test_missing_boot(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_BOOT_OK", "NOT_BOOT"), 33))

    def test_duplicate_boot(self):
        self.assertFalse(validate(GOOD + "WOLFOS_BOOT_OK\n", 33))

    def test_duplicate_proof(self):
        self.assertFalse(validate(GOOD + GOOD.splitlines()[2] + "\n", 33))

    def test_duplicate_gpu(self):
        self.assertFalse(validate(GOOD + GOOD.splitlines()[0] + "\n", 33))

    def test_duplicate_pci_gate(self):
        self.assertFalse(validate(GOOD + "WOLFOS_PCI_TEST_OK\n", 33))

    def test_wrong_order(self):
        rows = GOOD.splitlines()
        self.assertFalse(validate("\n".join([rows[0], rows[2], rows[1], rows[3]]) + "\n", 33))

    def test_later_gpu_error(self):
        self.assertFalse(validate(GOOD + "WOLFOS_QEMU_DISPI_PROBE_FAIL stage=pci\n", 33))

    def test_disabled_mode_is_not_an_attested_scanout(self):
        self.assertFalse(validate(GOOD.replace(
            "xres=1024 yres=768 bpp=32 enabled=65",
            "xres=0 yres=0 bpp=0 enabled=0"), 33))

    def test_missing_attestation(self):
        self.assertFalse(validate("".join(row + "\n" for row in GOOD.splitlines()
                                          if not row.startswith("WOLFOS_QEMU_DISPLAY_ATTEST_OK")), 33))

    def test_duplicate_attestation(self):
        self.assertFalse(validate(GOOD + GOOD.splitlines()[3] + "\n", 33))

    def test_attestation_after_pixel_writes(self):
        rows = GOOD.splitlines()
        rows[3], rows[4] = rows[4], rows[3]
        self.assertFalse(validate("\n".join(rows) + "\n", 33))

    def test_forged_scanout_width(self):
        self.assertFalse(validate(GOOD.replace("width=1024", "width=1023"), 33))

    def test_forged_scanout_height(self):
        self.assertFalse(validate(GOOD.replace("height=768", "height=769"), 33))

    def test_attestation_bit_depth_mismatch(self):
        self.assertFalse(validate(GOOD.replace("pitch=4096 bpp=32", "pitch=4096 bpp=24"), 33))

    def test_attestation_vram_mismatch(self):
        self.assertFalse(validate(GOOD.replace("pitch=4096 bpp=32 vram64k=256",
                                               "pitch=4096 bpp=32 vram64k=255"), 33))

    def test_short_scanline_pitch(self):
        self.assertFalse(validate(GOOD.replace("pitch=4096", "pitch=4092"), 33))

    def test_unaligned_scanline_pitch(self):
        self.assertFalse(validate(GOOD.replace("pitch=4096", "pitch=4097"), 33))

    def test_framebuffer_outside_reported_vram(self):
        self.assertFalse(validate(GOOD.replace("pitch=4096", "pitch=30000"), 33))

    def test_mismatched_framebuffer_marker(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_FRAMEBUFFER_OK 1024x768",
                                               "WOLFOS_FRAMEBUFFER_OK 1024x700"), 33))

    def test_attestation_rgb_must_be_valid(self):
        self.assertFalse(validate(GOOD.replace("rgb=1 mode_writes=0",
                                               "rgb=0 mode_writes=0"), 33))

    def test_late_attestation_error_invalidates_proof(self):
        self.assertFalse(validate(GOOD + "WOLFOS_QEMU_DISPLAY_ATTEST_FAILED stage=mode_or_vram\n", 33))

    def test_display_proof_must_be_before_fb_text(self):
        rows = GOOD.splitlines()
        rows[2], rows[4] = rows[4], rows[2]
        self.assertFalse(validate("\n".join(rows) + "\n", 33))

    def test_allowed_older_id(self):
        self.assertTrue(validate(GOOD.replace("id=b0c5", "id=b0c3"), 33))

    def test_unrecognized_loaded_driver(self):
        self.assertFalse(validate(GOOD + "WOLFOS_GPU_DRIVER_LOADED\n", 33))

if __name__ == "__main__":
    unittest.main()
