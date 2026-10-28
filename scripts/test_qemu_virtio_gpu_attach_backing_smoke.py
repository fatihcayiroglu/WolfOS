#!/usr/bin/env python3
"""Offline adversarial fixtures; genuine QEMU proof is a separate mandatory CI gate."""
import unittest
from qemu_virtio_gpu_attach_backing_smoke import validate_backing_marker
from test_qemu_virtio_gpu_edid_live_smoke import DISPLAY, EDID

DISPLAY9=DISPLAY.replace("frames_allocated=5 frames_released=5",
                         "frames_allocated=9 frames_released=9")
EDID9=EDID.replace("frames_allocated=5 frames_released=5",
                   "frames_allocated=9 frames_released=9")
BACKING=(
    "WOLFOS_VIRTIO_GPU_ATTACH_BACKING_OK resource_id=1 format=2 width=64 height=64 "
    "create_type=257 attach_type=262 detach_type=263 unref_type=258 "
    "response_type=4352 used_idx=6 used_head=0 used_len=24 "
    "fences_verified=4 notify_writes=6 backing_entries=4 backing_bytes=16384 "
    "pages_zeroed=4 attach_ack=1 detach_ack=1 unref_ack=1 "
    "transfer_writes=0 scanout_writes=0 reset=0 queue_disabled=1 "
    "frames_allocated=9 frames_released=9 pmm_leak=0 qemu_only=1"
)
DISPLAY_OK="WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK"
EDID_OK="WOLFOS_VIRTIO_GPU_EDID_LIVE_TEST_OK"
OK="WOLFOS_VIRTIO_GPU_ATTACH_BACKING_TEST_OK"
TEXT="\n".join((DISPLAY9,EDID9,BACKING,DISPLAY_OK,EDID_OK,OK))

class RealBackingProofTests(unittest.TestCase):
    def test_positive_fixture_is_only_validator_unit_test(self):
        self.assertTrue(validate_backing_marker(TEXT))
    def test_no_missing_or_duplicated_marker_or_ack(self):
        for broken in [TEXT.replace(BACKING,""),TEXT.replace(OK,""),
                       TEXT+"\n"+BACKING,TEXT+"\n"+OK]:
            self.assertFalse(validate_backing_marker(broken))
    def test_strict_four_fenced_completions_and_ownership(self):
        for old,new in [
            ("attach_type=262","attach_type=261"),
            ("detach_type=263","detach_type=262"),
            ("unref_type=258","unref_type=0"),
            ("used_idx=6","used_idx=5"),
            ("used_head=0","used_head=1"),
            ("used_len=24","used_len=23"),
            ("fences_verified=4","fences_verified=3"),
            ("notify_writes=6","notify_writes=5"),
            ("backing_entries=4","backing_entries=1"),
            ("backing_bytes=16384","backing_bytes=4096"),
            ("pages_zeroed=4","pages_zeroed=3"),
            ("attach_ack=1","attach_ack=0"),
            ("detach_ack=1","detach_ack=0"),
            ("unref_ack=1","unref_ack=0"),
            ("transfer_writes=0","transfer_writes=1"),
            ("scanout_writes=0","scanout_writes=1"),
            ("reset=0","reset=15"),
            ("queue_disabled=1","queue_disabled=0"),
            ("frames_allocated=9","frames_allocated=5"),
            ("frames_released=9","frames_released=8"),
            ("pmm_leak=0","pmm_leak=1"),
        ]:
            with self.subTest(old=old):
                self.assertFalse(validate_backing_marker(TEXT.replace(
                    BACKING,BACKING.replace(old,new)
                )))
    def test_refuse_fake_five_frame_prior_proofs(self):
        self.assertFalse(validate_backing_marker(TEXT.replace(DISPLAY9,DISPLAY)))
        self.assertFalse(validate_backing_marker(TEXT.replace(EDID9,EDID)))
    def test_real_edid_proof_order_and_both_acks_required(self):
        self.assertFalse(validate_backing_marker(TEXT.replace(EDID9,"")))
        self.assertFalse(validate_backing_marker(TEXT.replace(EDID_OK,"")))
        self.assertFalse(validate_backing_marker("\n".join((
            BACKING,DISPLAY9,EDID9,DISPLAY_OK,EDID_OK,OK
        ))))
        self.assertFalse(validate_backing_marker("\n".join((
            DISPLAY9,EDID9,DISPLAY_OK,EDID_OK,BACKING,OK
        ))))
    def test_failures_and_prior_resource_proof_are_not_success(self):
        for line in ["WOLFOS_VIRTIO_GPU_RESOURCE2D_FAIL stage=completion",
                     "WOLFOS_VIRTIO_GPU_ATTACH_BACKING_FAIL stage=detach",
                     "WOLFOS_VIRTIO_GPU_EDID_LIVE_FAIL stage=decode",
                     "WOLFOS_VIRTIO_GPU_RESOURCE2D_TEST_OK"]:
            self.assertFalse(validate_backing_marker(TEXT+"\n"+line))

if __name__=="__main__":
    unittest.main()
