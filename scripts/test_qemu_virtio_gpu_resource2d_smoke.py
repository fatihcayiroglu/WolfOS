#!/usr/bin/env python3
"""Offline negative mutations of the genuine QEMU CREATE_2D/UNREF proof."""
import unittest
from qemu_virtio_gpu_resource2d_smoke import validate_resource_marker
from test_qemu_virtio_gpu_edid_live_smoke import DISPLAY,EDID,OK as EDID_OK

RESOURCE=(
    "WOLFOS_VIRTIO_GPU_RESOURCE2D_OK resource_id=1 format=2 width=64 height=64 "
    "create_type=257 unref_type=258 response_type=4352 used_idx=4 "
    "used_head=0 used_len=24 fences_verified=2 notify_writes=4 "
    "scanout_writes=0 attach_backing=0 reset=0 queue_disabled=1 "
    "frames_allocated=5 frames_released=5 pmm_leak=0 qemu_only=1"
)
DISPLAY_OK="WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK"
OK="WOLFOS_VIRTIO_GPU_RESOURCE2D_TEST_OK"
TEXT="\n".join((DISPLAY,EDID,RESOURCE,DISPLAY_OK,EDID_OK,OK))

class Resource2dProofTests(unittest.TestCase):
    def test_positive_fixture_only_tests_validator_not_real_qemu(self):
        self.assertTrue(validate_resource_marker(TEXT))
    def test_missing_or_duplicated_resource_proof_or_ack(self):
        for broken in [
            TEXT.replace(RESOURCE,""), TEXT.replace(OK,""),
            TEXT+"\n"+RESOURCE,TEXT+"\n"+OK,
        ]:
            self.assertFalse(validate_resource_marker(broken))
    def test_create_unref_both_must_complete_with_fences(self):
        changes=[
            ("resource_id=1","resource_id=0"),
            ("format=2","format=1"),
            ("width=64","width=65"),
            ("height=64","height=0"),
            ("create_type=257","create_type=256"),
            ("unref_type=258","unref_type=257"),
            ("response_type=4352","response_type=4353"),
            ("used_idx=4","used_idx=3"),
            ("used_head=0","used_head=1"),
            ("used_len=24","used_len=40"),
            ("fences_verified=2","fences_verified=1"),
            ("notify_writes=4","notify_writes=3"),
        ]
        for old,new in changes:
            with self.subTest(old=old):
                self.assertFalse(validate_resource_marker(TEXT.replace(
                    RESOURCE,RESOURCE.replace(old,new)
                )))
    def test_no_scanout_backing_reset_or_pmm_shortcuts(self):
        changes=[
            ("scanout_writes=0","scanout_writes=1"),
            ("attach_backing=0","attach_backing=1"),
            ("reset=0","reset=15"),
            ("queue_disabled=1","queue_disabled=0"),
            ("frames_released=5","frames_released=0"),
            ("pmm_leak=0","pmm_leak=1"),
        ]
        for old,new in changes:
            with self.subTest(old=old):
                self.assertFalse(validate_resource_marker(TEXT.replace(
                    RESOURCE,RESOURCE.replace(old,new)
                )))
    def test_prior_real_edid_proof_and_order_are_required(self):
        self.assertFalse(validate_resource_marker(TEXT.replace(EDID,"")))
        self.assertFalse(validate_resource_marker(TEXT.replace(EDID_OK,"")))
        self.assertFalse(validate_resource_marker("\n".join((
            RESOURCE,DISPLAY,EDID,DISPLAY_OK,EDID_OK,OK
        ))))
        self.assertFalse(validate_resource_marker("\n".join((
            DISPLAY,EDID,DISPLAY_OK,EDID_OK,RESOURCE,OK
        ))))
    def test_failure_markers_always_override_success(self):
        self.assertFalse(validate_resource_marker(
            TEXT+"\nWOLFOS_VIRTIO_GPU_RESOURCE2D_FAIL stage=completion"
        ))
        self.assertFalse(validate_resource_marker(
            TEXT+"\nWOLFOS_VIRTIO_GPU_EDID_LIVE_FAIL stage=decode"
        ))

if __name__=="__main__":
    unittest.main()
