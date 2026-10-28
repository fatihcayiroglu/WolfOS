"""Strict positive/negative evidence for QEMU stdvga DISPI port access."""
import unittest
from qemu_stdvga_dispi_smoke import validate

GOOD = (
    "WOLFOS_GPU_DETECTED vendor=1234 device=1111 bus=00 slot=01\n"
    "WOLFOS_PCI_TEST_OK\n"
    "WOLFOS_QEMU_DISPI_PROBE_OK pci=1234:1111 id=b0c5 "
    "xres=1024 yres=768 bpp=32 enabled=65 vram64k=256 "
    "selector_restored=1 mode_writes=0 native_accel=0\n"
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

    def test_disabled_mode_may_have_empty_size(self):
        self.assertTrue(validate(GOOD.replace(
            "xres=1024 yres=768 bpp=32 enabled=65",
            "xres=0 yres=0 bpp=0 enabled=0"), 33))

    def test_allowed_older_id(self):
        self.assertTrue(validate(GOOD.replace("id=b0c5", "id=b0c3"), 33))

    def test_unrecognized_loaded_driver(self):
        self.assertFalse(validate(GOOD + "WOLFOS_GPU_DRIVER_LOADED\n", 33))

if __name__ == "__main__":
    unittest.main()
