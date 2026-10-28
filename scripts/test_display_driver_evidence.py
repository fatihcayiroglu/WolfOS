"""Reject fake accelerated display-driver claims and mismatched PCI identities."""
import unittest
from display_driver_evidence import validate_display_evidence

GOOD = "WOLFOS_GPU_DETECTED vendor=1234 device=1111 bus=00 slot=01\nWOLFOS_GPU_DRIVER_POLICY vendor=1234 device=1111 family=qemu native=none cfg_write=0\nWOLFOS_PCI_OK devices=5 displays=1 networks=1 storage=1\nWOLFOS_PCI_TEST_OK\nWOLFOS_DISPLAY_BOOT_POLICY backend=limine-framebuffer native_accel=0 driver_loaded=0\nWOLFOS_FRAMEBUFFER_OK 1024x768\n"

class DisplayDriverEvidenceTests(unittest.TestCase):
    def test_verified_read_only_qemu_fallback(self):
        self.assertTrue(validate_display_evidence(GOOD))

    def test_no_gpu_detect(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("WOLFOS_GPU_DETECTED", "NOT_GPU_DETECTED")))

    def test_no_policy(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("WOLFOS_GPU_DRIVER_POLICY", "NOT_GPU_DRIVER_POLICY")))

    def test_wrong_vendor(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("vendor=1234 device=1111 family=qemu", "vendor=8086 device=1111 family=qemu")))

    def test_wrong_device(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("device=1111 family=qemu", "device=2222 family=qemu")))

    def test_driver_claim(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("native=none", "native=loaded")))

    def test_config_write(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("cfg_write=0", "cfg_write=1")))

    def test_backend_claim(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("backend=limine-framebuffer", "backend=nvidia-native")))

    def test_acceleration_claim(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("native_accel=0", "native_accel=1")))

    def test_loaded_claim(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("driver_loaded=0", "driver_loaded=1")))

    def test_no_pci_summary(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("WOLFOS_PCI_OK", "WOLFOS_PCI_FAIL")))

    def test_no_framebuffer(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("WOLFOS_FRAMEBUFFER_OK", "WOLFOS_FRAMEBUFFER_FAIL")))

    def test_wrong_classification(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("family=qemu", "family=unsupported")))

    def test_upper_hex(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("vendor=1234", "vendor=ABCD")))

    def test_extra_field(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("cfg_write=0", "cfg_write=0 trusted=true")))

    def test_bad_cfg_field(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("native=none cfg_write=0", "cfg_write=0 native=none")))

    def test_wrong_backend_caps(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("native_accel=0 driver_loaded=0", "native_accel=0 driver_loaded=0 signed=1")))

    def test_device_missing(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("device=1111 family", "device=ffff family")))

    def test_gpu_extra(self):
        self.assertFalse(validate_display_evidence(GOOD.replace("family=qemu native=none", "family=qemu gpu=real native=none")))

    def test_duplicate_policy(self):
        self.assertFalse(validate_display_evidence(GOOD.replace(
            "WOLFOS_PCI_OK", GOOD.splitlines()[1] + "\nWOLFOS_PCI_OK")))

    def test_duplicate_boot(self):
        self.assertFalse(validate_display_evidence(GOOD + GOOD.splitlines()[4] + "\n"))

    def test_duplicate_pci_summary(self):
        self.assertFalse(validate_display_evidence(GOOD + GOOD.splitlines()[2] + "\n"))

    def test_wrong_order(self):
        lines = GOOD.splitlines()
        lines[4], lines[5] = lines[5], lines[4]
        self.assertFalse(validate_display_evidence("\n".join(lines)))

    def test_declared_loaded_driver(self):
        self.assertFalse(validate_display_evidence(GOOD + "WOLFOS_GPU_DRIVER_LOADED\n"))

    def test_two_valid_distinct_displays(self):
        lines = GOOD.splitlines()
        lines.insert(2, "WOLFOS_GPU_DETECTED vendor=10de device=2222 bus=00 slot=02")
        lines.insert(3, "WOLFOS_GPU_DRIVER_POLICY vendor=10de device=2222 family=nvidia native=none cfg_write=0")
        self.assertTrue(validate_display_evidence("\n".join(lines) + "\n"))

    def test_second_display_identity_mismatch(self):
        lines = GOOD.splitlines()
        lines.insert(2, "WOLFOS_GPU_DETECTED vendor=10de device=2222 bus=00 slot=02")
        lines.insert(3, "WOLFOS_GPU_DRIVER_POLICY vendor=1002 device=2222 family=amd native=none cfg_write=0")
        self.assertFalse(validate_display_evidence("\n".join(lines) + "\n"))

    def test_policy_before_detection(self):
        lines = GOOD.splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        self.assertFalse(validate_display_evidence("\n".join(lines) + "\n"))

if __name__ == "__main__":
    unittest.main()
