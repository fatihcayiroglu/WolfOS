#!/usr/bin/env python3
"""Adversarial native resize+rollback tests; genuine QEMU is separately mandatory."""
import unittest

from qemu_virtio_gpu_scanout_live_smoke import (
    MARKER,NATIVE_MARKER,PREFIX,ProofError,validate_serial,
    expected_rgb,verify_active,verify_reduced,verify_reexpanded,
)
from test_qemu_virtio_gpu_scanout_live_smoke import (
    CAPTURE1,CAPTURE2,TEXT,image,
)

REDUCED=PREFIX+"reduced"
REEXPANDED=PREFIX+"reexpanded"
RESTORED=PREFIX+"restored"
NATIVE_TEXT=TEXT.replace(
    CAPTURE1+"\n",CAPTURE1+"\n"+REDUCED+"\n"+REEXPANDED+"\n"
).replace(
    CAPTURE2+"\n",CAPTURE2+"\n"+RESTORED+"\n"
).replace(MARKER,NATIVE_MARKER)

def reduced_image():
    return (32,32,bytes(
        component
        for y in range(32) for x in range(32)
        for component in expected_rgb(x,y)
    ))

class NativeRollbackTests(unittest.TestCase):
    def test_exact_six_stage_proof_and_legacy_rejection(self):
        self.assertTrue(validate_serial(NATIVE_TEXT,native_rollback=True))
        self.assertFalse(validate_serial(NATIVE_TEXT))
        self.assertFalse(validate_serial(NATIVE_TEXT,reset_restore=True))
        self.assertFalse(validate_serial(TEXT,native_rollback=True))

    def test_missing_duplicate_swapped_and_fake_markers_fail(self):
        for broken in (
            NATIVE_TEXT.replace(REDUCED+"\n",""),
            NATIVE_TEXT.replace(REEXPANDED+"\n",""),
            NATIVE_TEXT.replace(RESTORED+"\n",""),
            NATIVE_TEXT+"\n"+REDUCED,
            NATIVE_TEXT.replace(REDUCED+"\n"+REEXPANDED,
                                REEXPANDED+"\n"+REDUCED),
            NATIVE_TEXT.replace(NATIVE_MARKER,MARKER),
            NATIVE_TEXT+"\n"+MARKER,
            NATIVE_TEXT+"\nWOLFOS_VIRTIO_GPU_NATIVE_ROLLBACK_FAIL stage=reexpanded",
        ):
            with self.subTest(input=broken[:80]):
                self.assertFalse(validate_serial(broken,native_rollback=True))

    def test_fences_completions_and_cleanup_strict(self):
        for old,new in (
            ("used_idx=14","used_idx=10"),
            ("used_len=24","used_len=23"),
            ("fences_verified=12","fences_verified=8"),
            ("notify_writes=14","notify_writes=10"),
            ("native_switch_acks=4","native_switch_acks=3"),
            ("capture_acks=6","capture_acks=4"),
            ("reset_to_vga_ack=1","reset_to_vga_ack=0"),
            ("queue_disabled=1","queue_disabled=0"),
            ("frames_released=9","frames_released=8"),
            ("pmm_leak=0","pmm_leak=1"),
            ("width_changed=32","width_changed=64"),
            ("height_restored=64","height_restored=32"),
        ):
            with self.subTest(field=old):
                self.assertFalse(validate_serial(
                    NATIVE_TEXT.replace(NATIVE_MARKER,NATIVE_MARKER.replace(old,new)),
                    native_rollback=True,
                ))

    def test_genuine_32x32_pixel_subset_and_64x64_rollback(self):
        verify_reduced(reduced_image())
        active=image()
        verify_active(active)
        verify_reexpanded(active,active)

    def test_wrong_shrink_geometry_fails(self):
        _,_,rgb=reduced_image()
        with self.assertRaises(ProofError):
            verify_reduced((64,64,bytes(64*64*3)))
        with self.assertRaises(ProofError):
            verify_reduced((31,32,rgb))

    def test_one_pixel_mutated_in_32x32_fails(self):
        w,h,rgb=reduced_image()
        buf=bytearray(rgb)
        buf[3*(20*32+11)+2]^=1
        with self.assertRaisesRegex(ProofError,"Reduced QMP pixel mismatch"):
            verify_reduced((w,h,bytes(buf)))

    def test_rollback_single_rgb_byte_mutation_fails(self):
        active=image()
        changed=bytearray(active[2])
        changed[3*(48*64+19)]^=1
        with self.assertRaisesRegex(ProofError,"rollback differs"):
            verify_reexpanded(active,(64,64,bytes(changed)))

    def test_stale_32x32_rollback_fails(self):
        with self.assertRaises(ProofError):
            verify_reexpanded(image(),reduced_image())

if __name__=="__main__":
    unittest.main()
