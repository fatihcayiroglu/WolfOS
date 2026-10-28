#!/usr/bin/env python3
"""Offline mutations of strict live EDID proof. No fake green in real CI."""
import unittest
from qemu_virtio_gpu_edid_live_smoke import validate_edid_marker

DISPLAY = (
    "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK req=256 resp=4353 "
    "used_idx=1 used_head=0 used_len=408 scanout0_enabled=1 "
    "width=1920 height=1080 notify_writes=1 driver_ok=15 "
    "reset=0 queue_disabled=1 frames_allocated=5 frames_released=5 "
    "response_dma_verified=1 pmm_leak=0 qemu_only=1"
)
EDID = (
    "WOLFOS_VIRTIO_GPU_EDID_LIVE_OK scanout=0 edid_size=128 modes=1 "
    "preferred_width=1920 preferred_height=1080 refresh_millihz=60000 "
    "used_idx=2 used_head=0 used_len=1056 fence_verified=1 "
    "negotiated_edid=1 notify_writes=2 driver_ok=15 reset=0 "
    "queue_disabled=1 frames_allocated=5 frames_released=5 "
    "pmm_leak=0 qemu_only=1"
)
OK = "WOLFOS_VIRTIO_GPU_EDID_LIVE_TEST_OK"
TEXT = "\n".join((DISPLAY,EDID,
                 "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK",OK))

class TestLiveEdidProof(unittest.TestCase):
    def test_positive_marker_only_does_not_replace_real_qemu(self):
        self.assertTrue(validate_edid_marker(TEXT))
    def test_no_edid_or_no_test_ok(self):
        self.assertFalse(validate_edid_marker(TEXT.replace(EDID,"")))
        self.assertFalse(validate_edid_marker(TEXT.replace(OK,"")))
    def test_no_duplicate_proofs(self):
        self.assertFalse(validate_edid_marker(TEXT+"\n"+EDID))
        self.assertFalse(validate_edid_marker(TEXT+"\n"+OK))
    def test_bad_second_used_ring(self):
        for old,new in [
            ("used_idx=2","used_idx=1"),
            ("used_head=0 used_len=1056","used_head=1 used_len=1056"),
            ("used_len=1056","used_len=408"),
        ]:
            with self.subTest(old=old):
                self.assertFalse(validate_edid_marker(TEXT.replace(old,new)))
    def test_no_feature_or_fence_or_reset(self):
        for old,new in [
            ("negotiated_edid=1","negotiated_edid=0"),
            ("fence_verified=1","fence_verified=0"),
            ("notify_writes=2","notify_writes=1"),
            ("reset=0","reset=15"),
            ("pmm_leak=0","pmm_leak=1"),
            ("frames_released=5","frames_released=0"),
        ]:
            with self.subTest(old=old):
                self.assertFalse(validate_edid_marker(TEXT.replace(EDID,EDID.replace(old,new))))
    def test_invalid_edid_sizes_and_mhz(self):
        for old,new in [
            ("edid_size=128","edid_size=0"),
            ("edid_size=128","edid_size=129"),
            ("edid_size=128","edid_size=1152"),
            ("modes=1","modes=0"),
            ("preferred_width=1920","preferred_width=0"),
            ("refresh_millihz=60000","refresh_millihz=0"),
        ]:
            with self.subTest(old=old):
                self.assertFalse(validate_edid_marker(TEXT.replace(EDID,EDID.replace(old,new))))
    def test_reordered_acks_or_missing_display(self):
        self.assertFalse(validate_edid_marker(TEXT.replace(DISPLAY,"")))
        self.assertFalse(validate_edid_marker("\n".join((EDID,DISPLAY,
                "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK",OK))))
    def test_first_failure_is_not_success(self):
        self.assertFalse(validate_edid_marker(TEXT+"\nWOLFOS_VIRTIO_GPU_EDID_LIVE_FAIL stage=decode"))

if __name__=="__main__":
    unittest.main()
