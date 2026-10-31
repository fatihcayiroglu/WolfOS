#!/usr/bin/env python3
"""Adversarial two-window move evidence: host pixels, ordering and fences.

This fixture cannot prove GPU I/O; the separate real QEMU CI step is mandatory.
"""
import unittest

from qemu_virtio_gpu_desktop_scanout import (
    WIDTH, HEIGHT, WINDOW_MOVE_LIVE, WINDOW_MARKER, WINDOW_OLD, WINDOW_NEW,
    WINDOW_FIXED, CAPTURE_PREFIX, MULTI_MARKER, expected_bytes,
    multi_damage_bytes, moved_window_bytes, verify_multi_damage_pixels,
    verify_moved_window, verify_pixels, validate_desktop_serial, ProofError,
)
from test_qemu_virtio_gpu_two_dirty_rects_smoke import multi_fixture
from test_qemu_virtio_gpu_desktop_scanout import mark


def window_fixture():
    base=multi_fixture()
    orig=mark(used=50,acks=7)
    expanded=mark(used=62,acks=10)
    assert base.count(orig)==1
    assert base.count(MULTI_MARKER+"\n")==1
    return base.replace(orig,expanded).replace(
        MULTI_MARKER+"\n",
        MULTI_MARKER+"\n"+
        CAPTURE_PREFIX+"windows\n"+
        CAPTURE_PREFIX+"window_moved\n"+
        CAPTURE_PREFIX+"windows_restored\n"+
        WINDOW_MARKER+"\n",
    )


class WindowMoveHostProof(unittest.TestCase):
    def test_exact_full_screen_old_new_fixed_and_restore(self):
        self.assertTrue(WINDOW_MOVE_LIVE)
        base=expected_bytes()
        initial=multi_damage_bytes()
        moved=moved_window_bytes()
        verify_multi_damage_pixels((WIDTH,HEIGHT,initial))
        verify_moved_window((WIDTH,HEIGHT,moved))
        verify_pixels((WIDTH,HEIGHT,base))
        self.assertEqual(len(initial),WIDTH*HEIGHT*3)
        self.assertEqual(len(moved),WIDTH*HEIGHT*3)
        changed=0
        untouched=0
        for y in range(HEIGHT):
            for x in range(WIDTH):
                i=3*(y*WIDTH+x)
                is_window=any(rx<=x<rx+rw and ry<=y<ry+rh
                              for rx,ry,rw,rh in (WINDOW_NEW,WINDOW_FIXED))
                if is_window:
                    self.assertEqual(moved[i:i+3],
                                     bytes(t^0xff for t in base[i:i+3]))
                    changed+=1
                else:
                    self.assertEqual(moved[i:i+3],base[i:i+3])
                    untouched+=1
        self.assertEqual(changed,768)
        self.assertEqual(untouched,785664)
        oldx,oldy,oldw,oldh=WINDOW_OLD
        for y in range(oldy,oldy+oldh):
            for x in range(oldx,oldx+oldw):
                at=3*(y*WIDTH+x)
                self.assertEqual(moved[at:at+3],base[at:at+3])

    def test_pixel_mutation_in_old_new_fixed_or_gap_is_detected(self):
        for x,y in ((11,19),(26,34),(211,119),(226,134),
                    (811,401),(842,416),(210,119),(100,50),
                    (811,417),(0,0)):
            b=bytearray(moved_window_bytes())
            b[3*(y*WIDTH+x)]^=1
            with self.subTest(x=x,y=y):
                with self.assertRaises(ProofError):
                    verify_moved_window((WIDTH,HEIGHT,bytes(b)))
        with self.assertRaises(ProofError):
            verify_moved_window((32,32,moved_window_bytes()))
        with self.assertRaises(ProofError):
            verify_pixels((WIDTH,HEIGHT,moved_window_bytes()))

    def test_no_missing_extra_forged_or_reordered_stages(self):
        valid=window_fixture()
        self.assertTrue(validate_desktop_serial(valid))
        cases=(
            valid.replace(WINDOW_MARKER+"\n",""),
            valid.replace(WINDOW_MARKER+"\n",WINDOW_MARKER+"\n"+WINDOW_MARKER+"\n"),
            valid.replace("visible_pixels=768","visible_pixels=769"),
            valid.replace("transfer_acks=6","transfer_acks=5"),
            valid.replace("flush_acks=6","flush_acks=5"),
            valid.replace("capture_acks=3 host_pixel_authority",
                          "capture_acks=2 host_pixel_authority"),
            valid.replace("no_union_transfer=1","no_union_transfer=0"),
            valid.replace("used_idx=62","used_idx=58"),
            valid.replace("fences_verified=60","fences_verified=56"),
            valid.replace("capture_acks=10","capture_acks=7"),
            valid.replace(CAPTURE_PREFIX+"windows\n",""),
            valid.replace(CAPTURE_PREFIX+"window_moved\n",""),
            valid.replace(CAPTURE_PREFIX+"windows_restored\n",""),
            valid.replace(CAPTURE_PREFIX+"window_moved\n",
                          CAPTURE_PREFIX+"windows\n"),
            valid.replace(CAPTURE_PREFIX+"windows\n"+
                          CAPTURE_PREFIX+"window_moved\n",
                          CAPTURE_PREFIX+"window_moved\n"+
                          CAPTURE_PREFIX+"windows\n"),
        )
        for bad in cases:
            with self.subTest(tail=bad[-80:]):
                self.assertFalse(validate_desktop_serial(bad))


if __name__=="__main__":
    unittest.main()
