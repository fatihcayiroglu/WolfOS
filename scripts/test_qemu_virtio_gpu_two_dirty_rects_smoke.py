#!/usr/bin/env python3
"""Host-only adversarial witnesses for the QEMU two-disjoint-region path.

Real GPU and pixel success is separately required from the actual QEMU P0
smoke; these fixtures cannot substitute for a guest screenshot.
"""
import unittest

from qemu_virtio_gpu_desktop_scanout import (
    WIDTH, HEIGHT, MULTI_RECTS, MULTI_MARKER, MULTI_DAMAGE_LIVE,
    DAMAGE_MARKER, CAPTURE_PREFIX, ProofError, expected_bytes,
    multi_damage_bytes, verify_multi_damage_pixels, verify_pixels,
    validate_desktop_serial,
)
from test_qemu_virtio_gpu_damage_live_smoke import proof_fixture
from test_qemu_virtio_gpu_desktop_scanout import mark


def multi_fixture():
    base=proof_fixture()
    original=mark(used=42,acks=5)
    extended=mark(used=50,acks=7)
    assert base.count(original)==1
    assert base.count(DAMAGE_MARKER+"\n")==1
    return base.replace(original,extended).replace(
        DAMAGE_MARKER+"\n",
        DAMAGE_MARKER+"\n"+
        CAPTURE_PREFIX+"multi\n"+
        CAPTURE_PREFIX+"multi_restored\n"+
        MULTI_MARKER+"\n",
    )


class IndependentDirtyRegions(unittest.TestCase):
    def test_only_768_pixels_change_without_union_amplification(self):
        self.assertTrue(MULTI_DAMAGE_LIVE)
        expected=expected_bytes()
        changed=multi_damage_bytes()
        self.assertEqual(len(changed), WIDTH*HEIGHT*3)
        affected=0
        outside=0
        for y in range(HEIGHT):
            for x in range(WIDTH):
                at=3*(y*WIDTH+x)
                inside=any(x0<=x<x0+w and y0<=y<y0+h
                           for x0,y0,w,h in MULTI_RECTS)
                if inside:
                    self.assertEqual(changed[at:at+3],
                                     bytes(t^0xff for t in expected[at:at+3]))
                    affected+=1
                else:
                    self.assertEqual(changed[at:at+3],expected[at:at+3])
                    outside+=1
        self.assertEqual(affected,768)
        self.assertEqual(outside,785664)
        verify_multi_damage_pixels((WIDTH,HEIGHT,changed))
        verify_pixels((WIDTH,HEIGHT,expected))

    def test_any_inside_outside_or_gap_pixel_corruption_fails(self):
        for x,y in ((11,19),(26,34),(811,401),(842,416),
                    (10,19),(27,19),(800,300),(811,417)):
            b=bytearray(multi_damage_bytes())
            b[3*(y*WIDTH+x)]^=1
            with self.subTest(x=x,y=y):
                with self.assertRaises(ProofError):
                    verify_multi_damage_pixels((WIDTH,HEIGHT,bytes(b)))
        with self.assertRaises(ProofError):
            verify_multi_damage_pixels((32,32,multi_damage_bytes()))
        with self.assertRaises(ProofError):
            verify_pixels((WIDTH,HEIGHT,multi_damage_bytes()))

    def test_all_serial_acks_and_stage_order_are_mandatory(self):
        valid=multi_fixture()
        self.assertTrue(validate_desktop_serial(valid))
        mutations=[
            valid.replace(MULTI_MARKER+"\n",""),
            valid.replace(MULTI_MARKER+"\n",MULTI_MARKER+"\n"+MULTI_MARKER+"\n"),
            valid.replace("pixels_changed=768","pixels_changed=769"),
            valid.replace("outside_pixels=785664","outside_pixels=785665"),
            valid.replace("no_bounding_transfer=1","no_bounding_transfer=0"),
            valid.replace("transfer_acks=4","transfer_acks=3"),
            valid.replace("flush_acks=4","flush_acks=3"),
            valid.replace("capture_acks=7","capture_acks=5"),
            valid.replace("used_idx=50","used_idx=42"),
            valid.replace("fences_verified=48","fences_verified=40"),
            valid.replace(CAPTURE_PREFIX+"multi\n",""),
            valid.replace(CAPTURE_PREFIX+"multi_restored\n",""),
            valid.replace(CAPTURE_PREFIX+"multi_restored\n",
                          CAPTURE_PREFIX+"multi\n"),
            valid.replace(CAPTURE_PREFIX+"multi\n"+
                          CAPTURE_PREFIX+"multi_restored\n",
                          CAPTURE_PREFIX+"multi_restored\n"+
                          CAPTURE_PREFIX+"multi\n"),
        ]
        for bad in mutations:
            with self.subTest(tail=bad[-75:]):
                self.assertFalse(validate_desktop_serial(bad))


if __name__=="__main__":
    unittest.main()
