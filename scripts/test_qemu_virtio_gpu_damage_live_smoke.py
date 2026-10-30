#!/usr/bin/env python3
"""Adversarial host proof of one real 32x32 GPU damage transfer.

The real QEMU target separately boots WolfOS, submits two real fenced
TRANSFER+FLUSH pairs, and compares each 1024x768 QMP screenshot. These
offline fixtures must never substitute for the genuine QEMU step.
"""
import unittest

from qemu_virtio_gpu_desktop_scanout import (
    WIDTH, HEIGHT, DAMAGE_RECT, DAMAGE_LIVE, DAMAGE_MARKER,
    ProofError, expected_bytes, damage_bytes, verify_damage_pixels,
    verify_pixels, validate_desktop_serial, CAPTURE_PREFIX,
)
from test_qemu_virtio_gpu_desktop_scanout import (
    TEXT, ATTEST_P, mark,
)


def proof_fixture():
    original = mark(used=38, acks=3)
    extended = mark(used=42, acks=5)
    assert TEXT.count(original) == 1
    assert TEXT.count(ATTEST_P+"\n") == 1
    return TEXT.replace(original, extended).replace(
        ATTEST_P+"\n",
        ATTEST_P+"\n"+
        CAPTURE_PREFIX+"damage\n"+
        CAPTURE_PREFIX+"damage_restored\n"+
        DAMAGE_MARKER+"\n",
    )


class RealPartialWidthContract(unittest.TestCase):
    def test_undamaged_every_pixel_matches_original(self):
        original = expected_bytes()
        changed = damage_bytes()
        self.assertEqual(len(original), WIDTH*HEIGHT*3)
        self.assertEqual(len(changed), WIDTH*HEIGHT*3)
        x0, y0, width, height = DAMAGE_RECT
        modified = 0
        outside = 0
        for y in range(HEIGHT):
            for x in range(WIDTH):
                at = 3*(y*WIDTH+x)
                if x0 <= x < x0+width and y0 <= y < y0+height:
                    self.assertEqual(changed[at:at+3],
                                     bytes(v^0xff for v in original[at:at+3]))
                    modified += 1
                else:
                    self.assertEqual(changed[at:at+3], original[at:at+3])
                    outside += 1
        self.assertEqual(modified, 1024)
        self.assertEqual(outside, 785408)
        verify_damage_pixels((WIDTH, HEIGHT, changed))
        verify_pixels((WIDTH, HEIGHT, original))

    def test_single_pixel_inside_or_outside_invalidates_screenshot(self):
        result=bytearray(damage_bytes())
        result[(91*WIDTH+73)*3] ^= 1
        with self.assertRaises(ProofError):
            verify_damage_pixels((WIDTH, HEIGHT, bytes(result)))
        result=bytearray(damage_bytes())
        result[(91*WIDTH+72)*3] ^= 1
        with self.assertRaises(ProofError):
            verify_damage_pixels((WIDTH, HEIGHT, bytes(result)))
        result=bytearray(damage_bytes())
        result[((91+32)*WIDTH+73)*3] ^= 1
        with self.assertRaises(ProofError):
            verify_damage_pixels((WIDTH, HEIGHT, bytes(result)))
        with self.assertRaises(ProofError):
            verify_damage_pixels((32, 32, damage_bytes()))
        with self.assertRaises(ProofError):
            verify_pixels((WIDTH, HEIGHT, damage_bytes()))

    def test_real_guest_serial_marker_and_capture_order_are_mandatory(self):
        self.assertTrue(DAMAGE_LIVE, "run with WOLFOS_DAMAGE_LIVE=1")
        valid=proof_fixture()
        self.assertTrue(validate_desktop_serial(valid))
        mutations=(
            valid.replace(DAMAGE_MARKER+"\n",""),
            valid.replace(DAMAGE_MARKER+"\n",DAMAGE_MARKER+"\n"*2),
            valid.replace("transfer_acks=2","transfer_acks=1"),
            valid.replace("flush_acks=2","flush_acks=1"),
            valid.replace("outside_pixels=785408","outside_pixels=785407"),
            valid.replace("capture_acks=5","capture_acks=3"),
            valid.replace("used_idx=42","used_idx=38"),
            valid.replace("fences_verified=40","fences_verified=36"),
            valid.replace(CAPTURE_PREFIX+"damage\n",""),
            valid.replace(CAPTURE_PREFIX+"damage_restored\n",""),
            valid.replace(CAPTURE_PREFIX+"damage_restored\n",
                          CAPTURE_PREFIX+"damage\n"),
            valid.replace(CAPTURE_PREFIX+"damage\n"+
                          CAPTURE_PREFIX+"damage_restored\n",
                          CAPTURE_PREFIX+"damage_restored\n"+
                          CAPTURE_PREFIX+"damage\n"),
        )
        for tampered in mutations:
            with self.subTest(tampered=tampered[-100:]):
                self.assertFalse(validate_desktop_serial(tampered))


if __name__ == "__main__":
    unittest.main()
