"""Offline validator tests; these do not substitute for actual QEMU boot."""
import unittest
from qemu_virtio_gpu_pci_smoke import validate

SAMPLE = "\n".join([
    "WOLFOS_LIMINE_OK",
    "WOLFOS_GPU_DETECTED vendor=1af4 device=1050 bus=00 slot=02",
    "WOLFOS_GPU_DRIVER_POLICY vendor=1af4 device=1050 family=virtio native=none cfg_write=0",
    "WOLFOS_VIRTIO_GPU_PCI_CAPS_OK vendor=1af4 device=1050 common=4 notify=4 isr=4 device=4 multiplier=4 cap_reads=64 cfg_writes=0 dma=0 accel=0",
    "WOLFOS_PCI_OK devices=5 displays=1 networks=0 storage=2",
    "WOLFOS_PCI_TEST_OK",
    "WOLFOS_VIRTIO_GPU_PCI_TEST_OK",
    "WOLFOS_DISPLAY_BOOT_POLICY backend=limine-framebuffer native_accel=0 driver_loaded=0",
    "WOLFOS_FRAMEBUFFER_OK 1024x768",
    "WOLFOS_BOOT_OK",
])

BAR_LINE = (
    "WOLFOS_VIRTIO_GPU_BARS_OK common=mem64 notify=mem64 "
    "isr=mem64 device=mem64 cfg_writes=0 bar_probe_writes=0 mmio=0 dma=0"
)
WITH_BARS = SAMPLE.replace("WOLFOS_PCI_TEST_OK", BAR_LINE + "\nWOLFOS_PCI_TEST_OK")

SIZE_LINE = (
    "WOLFOS_VIRTIO_GPU_BAR_SIZE_OK kind=mem64 bytes=4096 "
    "common_offset=256 common_length=64 command_writes=2 bar_writes=4 "
    "restored=1 decode_stopped=1 mmio=0 dma=0"
)
WITH_SIZE = WITH_BARS.replace("WOLFOS_PCI_TEST_OK",
                              SIZE_LINE + "\nWOLFOS_PCI_TEST_OK")
WITH_SIZE = WITH_SIZE.replace("WOLFOS_VIRTIO_GPU_PCI_TEST_OK",
                              "WOLFOS_VIRTIO_GPU_PCI_TEST_OK\n"
                              "WOLFOS_VIRTIO_GPU_BAR_SIZE_TEST_OK")

class VirtioGpuPciEvidenceTests(unittest.TestCase):
    def test_requires_all_exact_markers(self):
        self.assertTrue(validate(SAMPLE,33))

    def test_wrong_exit_and_no_gpu_fails(self):
        self.assertFalse(validate(SAMPLE,0))
        self.assertFalse(validate(SAMPLE.replace("WOLFOS_GPU_DETECTED", "WOLFOS_FAKE_GPU"),33))

    def test_duplicate_marker_fails(self):
        self.assertFalse(validate(SAMPLE+"\nWOLFOS_VIRTIO_GPU_PCI_TEST_OK",33))
        self.assertFalse(validate(SAMPLE+"\nWOLFOS_BOOT_OK",33))

    def test_no_fake_capability_proof(self):
        self.assertFalse(validate(SAMPLE.replace("cap_reads=64","cap_reads=0"),33))
        self.assertFalse(validate(SAMPLE.replace("dma=0","dma=1"),33))

    def test_unknown_display_vendor_not_virtio(self):
        self.assertFalse(validate(SAMPLE.replace("vendor=1af4","vendor=1234"),33))
        self.assertFalse(validate(SAMPLE.replace("device=1050","device=1111"),33))

    def test_wrong_order_fails(self):
        rows=SAMPLE.splitlines()
        rows[3],rows[5]=rows[5],rows[3]
        self.assertFalse(validate("\n".join(rows),33))

    def test_strict_bar_proof_only_in_bar_mode(self):
        self.assertTrue(validate(WITH_BARS,33,require_bars=True))
        self.assertFalse(validate(SAMPLE,33,require_bars=True))
        self.assertFalse(validate(WITH_BARS,33))

    def test_malformed_or_duplicate_bar_proof_rejected(self):
        self.assertFalse(validate(WITH_BARS.replace("mem64","bogus",1),33,require_bars=True))
        self.assertFalse(validate(WITH_BARS + "\n" + BAR_LINE,33,require_bars=True))
        self.assertFalse(validate(WITH_BARS.replace("bar_probe_writes=0",
                                                    "bar_probe_writes=1"),33,require_bars=True))

    def test_size_mode_requires_both_real_restoration_proofs(self):
        self.assertTrue(validate(WITH_SIZE,33,require_size=True))
        self.assertFalse(validate(WITH_SIZE,33,require_bars=True))
        self.assertFalse(validate(WITH_BARS,33,require_size=True))

    def test_size_mode_rejects_power_and_aperture_lies(self):
        self.assertFalse(validate(WITH_SIZE.replace("bytes=4096","bytes=3000"),
                                  33,require_size=True))
        self.assertFalse(validate(WITH_SIZE.replace("common_offset=256",
                                                   "common_offset=4096"),
                                  33,require_size=True))

    def test_size_mode_rejects_missing_or_wrong_rollback(self):
        self.assertFalse(validate(WITH_SIZE.replace("restored=1","restored=0"),
                                  33,require_size=True))
        self.assertFalse(validate(WITH_SIZE.replace("decode_stopped=1",
                                                   "decode_stopped=0"),
                                  33,require_size=True))
        self.assertFalse(validate(WITH_SIZE.replace("bar_writes=4","bar_writes=2"),
                                  33,require_size=True))

    def test_size_mode_rejects_duplicate_or_failed_marker(self):
        self.assertFalse(validate(WITH_SIZE + "\n" + SIZE_LINE,33,require_size=True))
        self.assertFalse(validate(WITH_SIZE + "\nWOLFOS_VIRTIO_GPU_BAR_SIZE_FAIL restore",
                                  33,require_size=True))
        self.assertFalse(validate(WITH_SIZE.replace("WOLFOS_VIRTIO_GPU_BAR_SIZE_TEST_OK",
                                                   "WOLFOS_VIRTIO_GPU_BAR_SIZE_TEST_FAILED"),
                                  33,require_size=True))

    def test_failure_and_acceleration_claims_fail(self):
        self.assertFalse(validate(SAMPLE+"\nWOLFOS_VIRTIO_GPU_PCI_CAPS_FAIL BadPointer",33))
        self.assertFalse(validate(SAMPLE+"\nWOLFOS_GPU_DRIVER_LOADED",33))
        self.assertFalse(validate(SAMPLE+"\naccel=1",33))
