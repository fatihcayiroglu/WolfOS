#!/usr/bin/env python3
"""Independent adversarial tests; a real QEMU boot is mandatory in CI."""
import unittest

from qemu_virtio_gpu_scanout_live_smoke import (
    MARKER,PREFIX,RESET_MARKER,ProofError,validate_serial,verify_restored,
)
from test_qemu_virtio_gpu_scanout_live_smoke import (
    CAPTURE2,TEXT,image,
)

RESET_STAGE=PREFIX+"restored"
RESET_TEXT=TEXT.replace(CAPTURE2+"\n",CAPTURE2+"\n"+RESET_STAGE+"\n")
RESET_TEXT=RESET_TEXT.replace(MARKER+"\n",MARKER+"\n"+RESET_MARKER+"\n")

def baseline():
    width,height=320,200
    return width,height,bytes((i*17+3)%251 for i in range(width*height*3))

class ResetRestorationProofTests(unittest.TestCase):
    def test_correct_four_stage_serial_and_previous_three_stage_gate(self):
        self.assertTrue(validate_serial(RESET_TEXT,reset_restore=True))
        self.assertFalse(validate_serial(RESET_TEXT))
        self.assertFalse(validate_serial(TEXT,reset_restore=True))

    def test_missing_duplicate_misordered_stage(self):
        for bad in (
            RESET_TEXT.replace(RESET_STAGE+"\n",""),
            RESET_TEXT+"\n"+RESET_STAGE,
            RESET_TEXT.replace(RESET_STAGE, PREFIX+"baseline"),
            RESET_TEXT.replace(CAPTURE2+"\n"+RESET_STAGE,
                               RESET_STAGE+"\n"+CAPTURE2),
        ):
            with self.subTest(bad=bad[:60]):
                self.assertFalse(validate_serial(bad,reset_restore=True))

    def test_reset_ack_and_cleanup_not_merely_claimed(self):
        for old,new in (
            ("reset_to_vga_ack=1","reset_to_vga_ack=0"),
            ("capture_acks=4","capture_acks=3"),
            ("geometry_and_pixels_verified_by_kernel=0",
             "geometry_and_pixels_verified_by_kernel=1"),
            ("queue_disabled=1","queue_disabled=0"),
            ("frames_released=9","frames_released=8"),
            ("pmm_leak=0","pmm_leak=1"),
        ):
            with self.subTest(field=old):
                self.assertFalse(validate_serial(
                    RESET_TEXT.replace(RESET_MARKER,RESET_MARKER.replace(old,new)),
                    reset_restore=True,
                ))

    def test_marker_missing_duplicate_or_misordered(self):
        for bad in (
            RESET_TEXT.replace(RESET_MARKER+"\n",""),
            RESET_TEXT+"\n"+RESET_MARKER,
            RESET_TEXT.replace(MARKER+"\n"+RESET_MARKER,
                               RESET_MARKER+"\n"+MARKER),
            RESET_TEXT+"\nWOLFOS_VIRTIO_GPU_SCANOUT_RESET_FAIL capture=timeout",
        ):
            self.assertFalse(validate_serial(bad,reset_restore=True))

    def test_exact_baseline_geometry_and_all_pixels(self):
        base=baseline()
        verify_restored(base,image(),(64,64,bytes(64*64*3)),base)

    def test_wrong_geometry_rejected_even_if_64x64_pixel_pattern_cleared(self):
        base=baseline()
        with self.assertRaises(ProofError):
            verify_restored(base,image(),(64,64,bytes(64*64*3)),
                            (64,64,bytes(64*64*3)))

    def test_single_baseline_pixel_mutation_rejected(self):
        base=baseline()
        altered=bytearray(base[2])
        altered[3*(103*320+219)+1]^=1
        with self.assertRaisesRegex(ProofError,"pixel mismatch"):
            verify_restored(base,image(),(64,64,bytes(64*64*3)),
                            (320,200,bytes(altered)))

    def test_unchanged_64x64_mode_is_not_accepted_as_baseline(self):
        pattern=image()
        with self.assertRaises(ProofError):
            verify_restored(pattern,pattern,(64,64,bytes(64*64*3)),pattern)

if __name__=="__main__":
    unittest.main()
