#!/usr/bin/env python3
"""Adversarial QEMU opaque overlap and z-order pixel witnesses.

Offline fixtures are not GPU evidence. The real QEMU P0 step is mandatory.
"""
import unittest

from qemu_virtio_gpu_desktop_scanout import (
    WIDTH, HEIGHT, OCCLUSION_LIVE, OPAQUE_MARKER, CAPTURE_PREFIX,
    WINDOW_OLD, WINDOW_FIXED, OPAQUE_OVERLAP, WINDOW_MARKER,
    expected_bytes, opaque_bytes, verify_opaque_pixels, verify_pixels,
    validate_desktop_serial, ProofError,
)
from test_qemu_virtio_gpu_window_move_smoke import window_fixture
from test_qemu_virtio_gpu_desktop_scanout import mark


def occlusion_fixture():
    base=window_fixture()
    original=mark(used=62,acks=10)
    extended=mark(used=76,acks=15)
    assert base.count(original)==1
    assert base.count(WINDOW_MARKER+"\n")==1
    return base.replace(original,extended).replace(
        WINDOW_MARKER+"\n",
        WINDOW_MARKER+"\n"+
        CAPTURE_PREFIX+"opaque_initial\n"+
        CAPTURE_PREFIX+"opaque_overlap\n"+
        CAPTURE_PREFIX+"opaque_blue_front\n"+
        CAPTURE_PREFIX+"opaque_red_front\n"+
        CAPTURE_PREFIX+"opaque_restored\n"+
        OPAQUE_MARKER+"\n",
    )


class OpaqueWindowPixels(unittest.TestCase):
    def test_exact_clipped_color_channels_and_opaque_overlap_owner(self):
        self.assertTrue(OCCLUSION_LIVE)
        background=expected_bytes()
        frames={phase:opaque_bytes(phase) for phase in
                ("initial","overlap","blue_front","red_front")}
        for phase,frame in frames.items():
            self.assertEqual(len(frame),WIDTH*HEIGHT*3)
            verify_opaque_pixels((WIDTH,HEIGHT,frame),phase)
        verify_pixels((WIDTH,HEIGHT,background))
        first=WINDOW_OLD
        blue=WINDOW_FIXED
        red=OPAQUE_OVERLAP
        for phase,data in frames.items():
            count_changed=0
            for y in range(HEIGHT):
                for x in range(WIDTH):
                    at=3*(y*WIDTH+x)
                    owner_blue=(blue[0]<=x<blue[0]+blue[2] and
                                blue[1]<=y<blue[1]+blue[3])
                    owner_red=first if phase=="initial" else red
                    visible_red=(phase!="blue_front" and
                                 owner_red[0]<=x<owner_red[0]+owner_red[2] and
                                 owner_red[1]<=y<owner_red[1]+owner_red[3])
                    expected=bytearray(background[at:at+3])
                    if owner_blue:
                        expected[2]^=0xff
                    if visible_red:
                        expected[2]=background[at+2]
                        expected[0]^=0xff
                    self.assertEqual(data[at:at+3],expected)
                    if data[at:at+3]!=background[at:at+3]:
                        count_changed+=1
            self.assertEqual(count_changed,768 if phase=="initial" else 512)

    def test_one_bad_pixel_in_overlap_blue_only_old_window_or_gap_fails(self):
        for phase in ("initial","overlap","blue_front","red_front"):
            original=opaque_bytes(phase)
            for x,y in ((819,401),(820,402),(811,401),(842,416),
                        (11,19),(26,34),(810,401),(400,300)):
                tampered=bytearray(original)
                tampered[(y*WIDTH+x)*3+1]^=1
                with self.subTest(phase=phase,x=x,y=y):
                    with self.assertRaises(ProofError):
                        verify_opaque_pixels((WIDTH,HEIGHT,bytes(tampered)),phase)
            with self.assertRaises(ProofError):
                verify_opaque_pixels((32,32,original),phase)
        with self.assertRaises(ProofError):
            verify_pixels((WIDTH,HEIGHT,opaque_bytes("red_front")))

    def test_serial_rejects_forged_z_order_and_missing_extra_captures(self):
        valid=occlusion_fixture()
        self.assertTrue(validate_desktop_serial(valid))
        stages=["opaque_initial","opaque_overlap","opaque_blue_front",
                "opaque_red_front","opaque_restored"]
        cases=[
            valid.replace(OPAQUE_MARKER+"\n",""),
            valid.replace(OPAQUE_MARKER+"\n",OPAQUE_MARKER+"\n"+OPAQUE_MARKER+"\n"),
            valid.replace("transfer_acks=7","transfer_acks=6"),
            valid.replace("flush_acks=7","flush_acks=6"),
            valid.replace("capture_acks=5 host_pixel_authority",
                          "capture_acks=4 host_pixel_authority"),
            valid.replace("no_full_frame=1","no_full_frame=0"),
            valid.replace("used_idx=76","used_idx=70"),
            valid.replace("fences_verified=74","fences_verified=68"),
            valid.replace("capture_acks=15","capture_acks=10"),
        ]
        for stage in stages:
            marker=CAPTURE_PREFIX+stage+"\n"
            cases.append(valid.replace(marker,""))
            cases.append(valid.replace(marker,marker+marker))
        for a,b in zip(stages,stages[1:]):
            first=CAPTURE_PREFIX+a+"\n"
            second=CAPTURE_PREFIX+b+"\n"
            cases.append(valid.replace(first+second,second+first))
        for bad in cases:
            with self.subTest(tail=bad[-85:]):
                self.assertNotEqual(bad,valid)
                self.assertFalse(validate_desktop_serial(bad))


if __name__=="__main__":
    unittest.main()
