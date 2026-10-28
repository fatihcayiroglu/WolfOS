#!/usr/bin/env python3
"""Offline adversarial fixtures; the real QEMU boot is separately mandatory."""
import unittest
from qemu_virtio_gpu_transfer2d_smoke import validate_transfer_marker
from test_qemu_virtio_gpu_attach_backing_smoke import DISPLAY9, EDID9

TRANSFER=(
    "WOLFOS_VIRTIO_GPU_TRANSFER2D_OK resource_id=1 format=2 width=64 height=64 "
    "create_type=257 attach_type=262 transfer_type=261 detach_type=263 "
    "unref_type=258 response_type=4352 used_idx=7 used_head=0 used_len=24 "
    "fences_verified=5 notify_writes=7 backing_entries=4 backing_bytes=16384 "
    "pattern_nonzero_bytes=16384 guest_pattern_verified=2 transfer_ack=1 "
    "detach_ack=1 unref_ack=1 host_readback=0 scanout_writes=0 "
    "reset=0 queue_disabled=1 frames_allocated=9 frames_released=9 "
    "pmm_leak=0 qemu_only=1"
)
DISPLAY_OK="WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK"
EDID_OK="WOLFOS_VIRTIO_GPU_EDID_LIVE_TEST_OK"
OK="WOLFOS_VIRTIO_GPU_TRANSFER2D_TEST_OK"
TEXT="\n".join((DISPLAY9,EDID9,TRANSFER,DISPLAY_OK,EDID_OK,OK))

class Transfer2dProofTests(unittest.TestCase):
    def test_positive_fixture_only_proves_parser_not_hardware(self):
        self.assertTrue(validate_transfer_marker(TEXT))
    def test_missing_or_duplicate_transfer_proof_ack(self):
        for broken in (TEXT.replace(TRANSFER,""),TEXT.replace(OK,""),
                       TEXT+"\n"+TRANSFER,TEXT+"\n"+OK):
            self.assertFalse(validate_transfer_marker(broken))
    def test_exact_real_seven_completions_and_five_fences(self):
        for old,new in [
            ("create_type=257","create_type=0"),
            ("attach_type=262","attach_type=0"),
            ("transfer_type=261","transfer_type=260"),
            ("detach_type=263","detach_type=0"),
            ("unref_type=258","unref_type=0"),
            ("response_type=4352","response_type=4353"),
            ("used_idx=7","used_idx=6"),
            ("used_head=0","used_head=1"),
            ("used_len=24","used_len=23"),
            ("fences_verified=5","fences_verified=4"),
            ("notify_writes=7","notify_writes=6"),
            ("backing_entries=4","backing_entries=1"),
            ("backing_bytes=16384","backing_bytes=4096"),
            ("pattern_nonzero_bytes=16384","pattern_nonzero_bytes=0"),
            ("guest_pattern_verified=2","guest_pattern_verified=1"),
            ("transfer_ack=1","transfer_ack=0"),
            ("detach_ack=1","detach_ack=0"),
            ("unref_ack=1","unref_ack=0"),
            ("host_readback=0","host_readback=1"),
            ("scanout_writes=0","scanout_writes=1"),
            ("reset=0","reset=15"),
            ("queue_disabled=1","queue_disabled=0"),
            ("frames_allocated=9","frames_allocated=5"),
            ("frames_released=9","frames_released=8"),
            ("pmm_leak=0","pmm_leak=1"),
        ]:
            with self.subTest(old=old):
                self.assertFalse(validate_transfer_marker(TEXT.replace(
                    TRANSFER,TRANSFER.replace(old,new)
                )))
    def test_prerequisite_display_and_edid_remain_strict_nine_frame_proofs(self):
        self.assertFalse(validate_transfer_marker(TEXT.replace(DISPLAY9,"")))
        self.assertFalse(validate_transfer_marker(TEXT.replace(EDID9,"")))
        self.assertFalse(validate_transfer_marker(TEXT.replace(EDID_OK,"")))
        self.assertFalse(validate_transfer_marker(TEXT.replace(TRANSFER,"")+"\n"+OK))
        self.assertFalse(validate_transfer_marker("\n".join((
            TRANSFER,DISPLAY9,EDID9,DISPLAY_OK,EDID_OK,OK
        ))))
        self.assertFalse(validate_transfer_marker("\n".join((
            DISPLAY9,EDID9,DISPLAY_OK,EDID_OK,TRANSFER,OK
        ))))
    def test_all_errors_and_legacy_markers_override_success(self):
        for suffix in ["WOLFOS_VIRTIO_GPU_RESOURCE2D_FAIL stage=completion",
                       "WOLFOS_VIRTIO_GPU_TRANSFER2D_FAIL stage=timeout",
                       "WOLFOS_VIRTIO_GPU_EDID_LIVE_FAIL stage=decode",
                       "WOLFOS_VIRTIO_GPU_ATTACH_BACKING_TEST_OK"]:
            self.assertFalse(validate_transfer_marker(TEXT+"\n"+suffix))

if __name__=="__main__":
    unittest.main()
