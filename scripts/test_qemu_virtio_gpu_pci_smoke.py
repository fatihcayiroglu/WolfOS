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

MMIO_LINE = (
    "WOLFOS_VIRTIO_GPU_COMMON_MMIO_OK queues=2 status=0 generation=0 "
    "ro=1 uc=1 pages=1 writes=0 dma=0"
)
WITH_MMIO = WITH_SIZE.replace(
    "WOLFOS_FRAMEBUFFER_OK 1024x768",
    MMIO_LINE + "\nWOLFOS_VIRTIO_GPU_COMMON_MMIO_TEST_OK\n"
    "WOLFOS_FRAMEBUFFER_OK 1024x768",
)

DEVICE_LINE = (
    "WOLFOS_VIRTIO_GPU_DEVICE_MMIO_OK scanouts=1 capsets=0 events=0 "
    "ro=1 uc=1 pages=1 writes=0 dma=0"
)
WITH_DEVICE = WITH_MMIO.replace(
    "WOLFOS_FRAMEBUFFER_OK 1024x768",
    DEVICE_LINE + "\nWOLFOS_VIRTIO_GPU_DEVICE_MMIO_TEST_OK\n"
    "WOLFOS_FRAMEBUFFER_OK 1024x768",
)

PREFLIGHT_LINE = (
    "WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_OK feature_select=0 "
    "features=2 edid=1 queue_select=0 queue_size=256 "
    "queue_enabled=0 status=0 ro=1 uc=1 pages=1 writes=0 dma=0"
)
WITH_PREFLIGHT = WITH_DEVICE.replace(
    "WOLFOS_FRAMEBUFFER_OK 1024x768",
    PREFLIGHT_LINE + "\nWOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_TEST_OK\n"
    "WOLFOS_FRAMEBUFFER_OK 1024x768",
)

BANK1_LINE = (
    "WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_OK bank0=2 bank1=1 "
    "version1=1 selector_writes=2 restored=1 "
    "status=0 queue_enabled=0 dma=0"
)
WITH_BANK1 = WITH_PREFLIGHT.replace(
    "WOLFOS_FRAMEBUFFER_OK 1024x768",
    BANK1_LINE + "\nWOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_TEST_OK\n"
    "WOLFOS_FRAMEBUFFER_OK 1024x768",
)

NEGOTIATION_LINE = (
    "WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_OK accepted_version1=1 "
    "ack=1 driver=3 features_ok=11 status_writes=5 feature_writes=1 "
    "selector_writes=2 reset=0 queue_enabled=0 dma=0"
)
WITH_NEGOTIATION = WITH_BANK1.replace(
    "WOLFOS_FRAMEBUFFER_OK 1024x768",
    NEGOTIATION_LINE + "\nWOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_TEST_OK\n"
    "WOLFOS_FRAMEBUFFER_OK 1024x768",
)

CONTROLQ_LINE = (
    "WOLFOS_VIRTIO_GPU_CONTROLQ_RO_OK queues=2 selected=0 size=256 "
    "notify_off=0 desc=0 driver=0 device=0 enabled=0 layout_n=256 "
    "desc_bytes=4096 avail_bytes=518 used_bytes=2054 "
    "ro=1 uc=1 pages=1 writes=0 dma=0"
)
WITH_CONTROLQ = WITH_NEGOTIATION.replace(
    "WOLFOS_FRAMEBUFFER_OK 1024x768",
    CONTROLQ_LINE + "\nWOLFOS_VIRTIO_GPU_CONTROLQ_RO_TEST_OK\n"
    "WOLFOS_FRAMEBUFFER_OK 1024x768",
)

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

    def test_mmio_requires_real_proof_and_excludes_other_flavors(self):
        self.assertTrue(validate(WITH_MMIO, 33, require_mmio=True))
        self.assertFalse(validate(WITH_SIZE, 33, require_mmio=True))
        self.assertFalse(validate(WITH_MMIO, 33, require_size=True))
        self.assertFalse(validate(WITH_MMIO, 33))

    def test_mmio_rejects_malformed_duplicate_and_fake_readonly(self):
        self.assertFalse(validate(WITH_MMIO.replace("ro=1", "ro=0"),
                                  33, require_mmio=True))
        self.assertFalse(validate(WITH_MMIO.replace("uc=1", "uc=0"),
                                  33, require_mmio=True))
        self.assertFalse(validate(WITH_MMIO.replace("writes=0", "writes=1"),
                                  33, require_mmio=True))
        self.assertFalse(validate(WITH_MMIO + "\n" + MMIO_LINE,
                                  33, require_mmio=True))

    def test_mmio_rejects_invalid_hardware_values_and_failure(self):
        self.assertFalse(validate(WITH_MMIO.replace("queues=2", "queues=0"),
                                  33, require_mmio=True))
        self.assertFalse(validate(WITH_MMIO.replace("status=0", "status=16"),
                                  33, require_mmio=True))
        self.assertFalse(validate(WITH_MMIO.replace("generation=0", "generation=256"),
                                  33, require_mmio=True))
        self.assertFalse(validate(WITH_MMIO + "\nWOLFOS_VIRTIO_GPU_COMMON_MMIO_FAIL map",
                                  33, require_mmio=True))

    def test_mmio_rejects_wrong_order_short_capability_and_missing_gate(self):
        self.assertFalse(validate(
            WITH_MMIO.replace("common_length=64", "common_length=32"),
            33, require_mmio=True))
        self.assertFalse(validate(
            WITH_MMIO.replace("WOLFOS_VIRTIO_GPU_COMMON_MMIO_TEST_OK", ""),
            33, require_mmio=True))
        self.assertFalse(validate(
            WITH_MMIO.replace("WOLFOS_VIRTIO_GPU_BAR_SIZE_TEST_OK",
                              "WOLFOS_VIRTIO_GPU_COMMON_MMIO_TEST_OK"),
            33, require_mmio=True))

    def test_device_proof_requires_earlier_common_mmio_and_real_gate(self):
        self.assertTrue(validate(WITH_DEVICE, 33, require_device=True))
        self.assertFalse(validate(WITH_MMIO, 33, require_device=True))
        self.assertFalse(validate(WITH_DEVICE, 33, require_mmio=True))
        self.assertFalse(validate(WITH_DEVICE, 33, require_size=True))

    def test_device_proof_rejects_invalid_scanout_and_event_values(self):
        for field in ("scanouts=0", "scanouts=17", "events=2",
                      "events=4294967296", "capsets=4294967296"):
            old = ("scanouts=1" if field.startswith("scanouts") else
                   "events=0" if field.startswith("events") else
                   "capsets=0")
            self.assertFalse(validate(WITH_DEVICE.replace(old, field),
                                      33, require_device=True))

    def test_device_proof_rejects_invalid_flags_and_duplicate(self):
        self.assertFalse(validate(WITH_DEVICE.replace("ro=1", "ro=0"),
                                  33, require_device=True))
        self.assertFalse(validate(WITH_DEVICE.replace("uc=1", "uc=0"),
                                  33, require_device=True))
        self.assertFalse(validate(WITH_DEVICE.replace("writes=0", "writes=1"),
                                  33, require_device=True))
        self.assertFalse(validate(WITH_DEVICE + "\n" + DEVICE_LINE,
                                  33, require_device=True))

    def test_device_proof_rejects_missing_gate_and_failure(self):
        self.assertFalse(validate(
            WITH_DEVICE.replace("WOLFOS_VIRTIO_GPU_DEVICE_MMIO_TEST_OK", ""),
            33, require_device=True))
        self.assertFalse(validate(
            WITH_DEVICE + "\nWOLFOS_VIRTIO_GPU_DEVICE_MMIO_FAIL map",
            33, require_device=True))
        self.assertFalse(validate(
            WITH_DEVICE.replace("WOLFOS_VIRTIO_GPU_COMMON_MMIO_TEST_OK", ""),
            33, require_device=True))

    def test_preflight_is_only_accepted_with_all_real_prior_proofs(self):
        self.assertTrue(validate(WITH_PREFLIGHT, 33, require_preflight=True))
        self.assertFalse(validate(WITH_DEVICE, 33, require_preflight=True))
        self.assertFalse(validate(WITH_PREFLIGHT, 33, require_device=True))
        self.assertFalse(validate(WITH_PREFLIGHT, 33, require_mmio=True))

    def test_preflight_rejects_nonzero_selectors_enabled_queue_status(self):
        for original, modified in [
            ("feature_select=0", "feature_select=1"),
            ("queue_select=0", "queue_select=1"),
            ("queue_enabled=0", "queue_enabled=1"),
            ("status=0", "status=4"),
        ]:
            self.assertFalse(validate(
                WITH_PREFLIGHT.replace(original, modified), 33,
                require_preflight=True))

    def test_preflight_rejects_edid_lies_queue_overflow_and_bad_flags(self):
        for original, modified in [
            ("edid=1", "edid=0"), ("features=2", "features=4294967296"),
            ("queue_size=256", "queue_size=0"),
            ("queue_size=256", "queue_size=32769"),
            ("writes=0", "writes=1"), ("ro=1", "ro=0")
        ]:
            self.assertFalse(validate(
                WITH_PREFLIGHT.replace(original, modified), 33,
                require_preflight=True))

    def test_preflight_rejects_duplicate_missing_or_failed_proof(self):
        self.assertFalse(validate(WITH_PREFLIGHT + "\n" + PREFLIGHT_LINE,
                                  33, require_preflight=True))
        self.assertFalse(validate(WITH_PREFLIGHT.replace(
            "WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_TEST_OK", ""
        ), 33, require_preflight=True))
        self.assertFalse(validate(
            WITH_PREFLIGHT + "\nWOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_FAIL map",
            33, require_preflight=True))

    def test_bank1_requires_full_real_preflight_chain(self):
        self.assertTrue(validate(WITH_BANK1, 33, require_bank1=True))
        self.assertFalse(validate(WITH_PREFLIGHT, 33, require_bank1=True))
        self.assertFalse(validate(WITH_BANK1, 33, require_preflight=True))
        self.assertFalse(validate(WITH_BANK1, 33, require_mmio=True))

    def test_bank1_rejects_selector_or_restore_lies(self):
        for old, new in [
            ("selector_writes=2", "selector_writes=1"),
            ("restored=1", "restored=0"),
            ("version1=1", "version1=0"),
            ("status=0", "status=4"),
            ("queue_enabled=0", "queue_enabled=1"),
        ]:
            self.assertFalse(validate(
                WITH_BANK1.replace(old,new), 33, require_bank1=True))

    def test_bank1_rejects_no_version_one_and_changed_bank_zero(self):
        self.assertFalse(validate(
            WITH_BANK1.replace("bank1=1", "bank1=0"),
            33, require_bank1=True))
        self.assertFalse(validate(
            WITH_BANK1.replace("bank0=2", "bank0=4"),
            33, require_bank1=True))
        self.assertFalse(validate(
            WITH_BANK1.replace("bank1=1", "bank1=4294967296"),
            33, require_bank1=True))

    def test_bank1_rejects_duplicate_failure_and_missing_gate(self):
        self.assertFalse(validate(WITH_BANK1 + "\n" + BANK1_LINE,
                                  33, require_bank1=True))
        self.assertFalse(validate(WITH_BANK1.replace(
            "WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_TEST_OK", ""),
            33, require_bank1=True))
        self.assertFalse(validate(
            WITH_BANK1 + "\nWOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_FAIL restore",
            33, require_bank1=True))

    def test_negotiation_requires_every_real_qemu_gate(self):
        self.assertTrue(validate(WITH_NEGOTIATION,33,require_negotiation=True))
        self.assertFalse(validate(WITH_BANK1,33,require_negotiation=True))
        self.assertFalse(validate(WITH_NEGOTIATION,33,require_bank1=True))
        self.assertFalse(validate(WITH_NEGOTIATION,33,require_preflight=True))

    def test_negotiation_rejects_status_or_restore_lies(self):
        for old, replacement in [
            ("accepted_version1=1","accepted_version1=0"),
            ("ack=1","ack=0"),
            ("driver=3","driver=1"),
            ("features_ok=11","features_ok=3"),
            ("status_writes=5","status_writes=4"),
            ("feature_writes=1","feature_writes=0"),
            ("selector_writes=2","selector_writes=1"),
            ("reset=0","reset=11"),
            ("queue_enabled=0","queue_enabled=1"),
        ]:
            self.assertFalse(validate(WITH_NEGOTIATION.replace(old,replacement),
                                      33,require_negotiation=True))

    def test_negotiation_rejects_duplicate_and_missing_proof(self):
        self.assertFalse(validate(WITH_NEGOTIATION+"\n"+NEGOTIATION_LINE,
                                  33,require_negotiation=True))
        self.assertFalse(validate(WITH_NEGOTIATION.replace(
            "WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_TEST_OK",""),
            33,require_negotiation=True))

    def test_negotiation_rejects_failure_marker(self):
        self.assertFalse(validate(WITH_NEGOTIATION+
            "\nWOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_FAIL reset",
            33,require_negotiation=True))

    def test_controlq_requires_all_prior_genuine_qemu_proofs(self):
        self.assertTrue(validate(WITH_CONTROLQ,33,require_controlq=True))
        self.assertFalse(validate(WITH_NEGOTIATION,33,require_controlq=True))
        self.assertFalse(validate(WITH_CONTROLQ,33,require_negotiation=True))
        self.assertFalse(validate(WITH_CONTROLQ,33,require_bank1=True))

    def test_controlq_rejects_addresses_or_writes_and_missing_marker(self):
        for old, replacement in [
            ("desc=0", "desc=4096"), ("driver=0", "driver=8192"),
            ("device=0", "device=12288"), ("enabled=0", "enabled=1"),
            ("ro=1", "ro=0"), ("writes=0", "writes=1"),
            ("dma=0", "dma=1"), ("selected=0", "selected=1"),
        ]:
            self.assertFalse(validate(
                WITH_CONTROLQ.replace(old, replacement),33,require_controlq=True))
        self.assertFalse(validate(
            WITH_CONTROLQ.replace("WOLFOS_VIRTIO_GPU_CONTROLQ_RO_TEST_OK", ""),
            33,require_controlq=True))

    def test_controlq_rejects_faked_split_layout(self):
        for old, replacement in [
            ("queues=2", "queues=1"), ("size=256", "size=255"),
            ("layout_n=256", "layout_n=128"),
            ("desc_bytes=4096", "desc_bytes=4097"),
            ("avail_bytes=518", "avail_bytes=517"),
            ("used_bytes=2054", "used_bytes=2055"),
            ("notify_off=0", "notify_off=65536"),
        ]:
            self.assertFalse(validate(
                WITH_CONTROLQ.replace(old, replacement),33,require_controlq=True))

    def test_controlq_rejects_duplicate_and_failure(self):
        self.assertFalse(validate(WITH_CONTROLQ+"\n"+CONTROLQ_LINE,
                                  33,require_controlq=True))
        self.assertFalse(validate(WITH_CONTROLQ+
            "\nWOLFOS_VIRTIO_GPU_CONTROLQ_RO_FAIL bad_queue",
            33,require_controlq=True))

    def test_failure_and_acceleration_claims_fail(self):
        self.assertFalse(validate(SAMPLE+"\nWOLFOS_VIRTIO_GPU_PCI_CAPS_FAIL BadPointer",33))
        self.assertFalse(validate(SAMPLE+"\nWOLFOS_GPU_DRIVER_LOADED",33))
        self.assertFalse(validate(SAMPLE+"\naccel=1",33))
