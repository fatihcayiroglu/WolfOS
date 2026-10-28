#!/usr/bin/env python3
"""Adversarial serial/QMP fixture tests. Real QEMU boot remains mandatory."""
import tempfile
import unittest
from pathlib import Path

from qemu_virtio_gpu_scanout_live_smoke import (
    MARKER,PREFIX,TEST_OK,ProofError,validate_serial,
    expected_rgb,ppm,verify_active,verify_disabled,
)
from test_qemu_virtio_gpu_attach_backing_smoke import DISPLAY9,EDID9

CAPTURE0=PREFIX+"baseline"
CAPTURE1=PREFIX+"active"
CAPTURE2=PREFIX+"disabled"
DISPLAY_ACK="WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK"
EDID_ACK="WOLFOS_VIRTIO_GPU_EDID_LIVE_TEST_OK"
TEXT="\n".join((CAPTURE0,CAPTURE1,CAPTURE2,DISPLAY9,EDID9,MARKER,
                DISPLAY_ACK,EDID_ACK,TEST_OK))

def image()->tuple[int,int,bytes]:
    pixels=bytearray()
    for y in range(64):
        for x in range(64):
            pixels.extend(expected_rgb(x,y))
    return (64,64,bytes(pixels))

class ScanoutProofTests(unittest.TestCase):
    def test_positive_fixture_does_not_replace_real_qmp_screenshot(self):
        self.assertTrue(validate_serial(TEXT))
    def test_exact_ten_completions_eight_fences_and_rollback(self):
        for old,new in [
            ("set_type=259","set_type=260"),
            ("flush_type=260","flush_type=261"),
            ("clear_type=259","clear_type=0"),
            ("used_idx=10","used_idx=9"),
            ("used_head=0","used_head=1"),
            ("used_len=24","used_len=23"),
            ("fences_verified=8","fences_verified=7"),
            ("notify_writes=10","notify_writes=9"),
            ("set_ack=1","set_ack=0"),
            ("flush_ack=1","flush_ack=0"),
            ("clear_ack=1","clear_ack=0"),
            ("detach_ack=1","detach_ack=0"),
            ("unref_ack=1","unref_ack=0"),
            ("capture_acks=3","capture_acks=2"),
            ("host_pixels_verified_by_kernel=0","host_pixels_verified_by_kernel=1"),
            ("reset=0","reset=15"),
            ("queue_disabled=1","queue_disabled=0"),
            ("frames_allocated=9","frames_allocated=5"),
            ("frames_released=9","frames_released=8"),
            ("pmm_leak=0","pmm_leak=1"),
        ]:
            with self.subTest(old=old):
                self.assertFalse(validate_serial(TEXT.replace(MARKER,MARKER.replace(old,new))))
    def test_missing_duplicate_or_misordered_capture(self):
        for broken in (
            TEXT.replace(CAPTURE0,""),
            TEXT.replace(CAPTURE1,""),
            TEXT.replace(CAPTURE2,""),
            TEXT+"\n"+CAPTURE2,
            TEXT.replace(CAPTURE0,"TEMP_STAGE").replace(CAPTURE1,CAPTURE0).replace("TEMP_STAGE",CAPTURE1),
            "\n".join((DISPLAY9,EDID9,CAPTURE0,CAPTURE1,CAPTURE2,MARKER,
                       DISPLAY_ACK,EDID_ACK,TEST_OK)),
        ):
            self.assertFalse(validate_serial(broken))
    def test_failure_and_legacy_proof_rejected(self):
        for broken in (
            TEXT.replace(MARKER,""),
            TEXT.replace(TEST_OK,""),
            TEXT+"\n"+TEST_OK,
            TEXT+"\nWOLFOS_VIRTIO_GPU_SCANOUT_FAIL stage=timeout",
            TEXT+"\nWOLFOS_VIRTIO_GPU_RESOURCE2D_FAIL command_idx=8",
            TEXT+"\nWOLFOS_VIRTIO_GPU_TRANSFER2D_TEST_OK",
            TEXT.replace(EDID9,""),
            TEXT.replace(DISPLAY9,""),
        ):
            self.assertFalse(validate_serial(broken))
    def test_expected_bgr_to_ppm_rgb_not_all_black(self):
        self.assertEqual(expected_rgb(0,0),(36,19,2))
        self.assertNotEqual(expected_rgb(0,0),expected_rgb(0,16))
        verify_active(image())
    def test_actual_pixel_mismatch_and_wrong_geometry_fail(self):
        width,height,pixels=image()
        broken=bytearray(pixels)
        broken[3*(32*64+17)+1]^=1
        with self.assertRaises(ProofError):
            verify_active((width,height,bytes(broken)))
        with self.assertRaises(ProofError):
            verify_active((63,64,pixels))
    def test_binary_ppm_decoder_exact_bytes_and_reject_truncation(self):
        w,h,pixels=image()
        with tempfile.TemporaryDirectory() as d:
            file=Path(d)/"capture.ppm"
            file.write_bytes(b"P6\n64 64\n255\n"+pixels)
            self.assertEqual(ppm(file),(w,h,pixels))
            file.write_bytes(b"P6\n64 64\n255\n"+pixels[:-1])
            with self.assertRaises(ProofError):
                ppm(file)
    def test_disable_screenshot_rejects_stale_active_pixels(self):
        active=image()
        blank=(64,64,bytes(64*64*3))
        verify_disabled(active,blank)
        with self.assertRaises(ProofError):
            verify_disabled(active,active)
        with self.assertRaises(ProofError):
            verify_disabled(active,(1024,768,bytes(1024*768*3)))
        stale=bytearray(active[2])
        stale[0]=0
        with self.assertRaises(ProofError):
            verify_disabled(active,(64,64,bytes(stale)))

if __name__=="__main__":
    unittest.main()
