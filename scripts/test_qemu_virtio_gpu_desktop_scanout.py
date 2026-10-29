#!/usr/bin/env python3
"""Adversarial serial/pixel fixtures for the desktop scanout proof.

The real QEMU boot remains mandatory: this file only proves that the host
validator rejects weak, forged or reordered evidence, so a green CI run
cannot be produced by a plausible-looking log alone.
"""
import unittest

from qemu_virtio_gpu_desktop_scanout import (
    CAPTURE_PREFIX, HEIGHT, MARKER, NONCE, PIXELS, WIDTH, ProofError,
    expected_bytes, expected_rgb, pattern_digest, validate_desktop_serial,
    verify_pixels,
)

ATTEST = ("WOLFOS_GPU_STAGE_ATTEST stage=desktop geometry=1024x768 "
          "nonce=574f4445534b0004 source_digest=0b6b1dc5")
CAPTURE = CAPTURE_PREFIX + "restored"
DISPLAY = ("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK req=256 resp=4353 used_idx=1 "
           "used_head=0 used_len=408 scanout0_enabled=1 width=1280 "
           "height=800 notify_writes=1 driver_ok=15 reset=0 queue_disabled=1 "
           "frames_allocated=773 frames_released=773 response_dma_verified=1 "
           "pmm_leak=0 qemu_only=1")
EDID = ("WOLFOS_VIRTIO_GPU_EDID_LIVE_OK scanout=0 edid_size=1024 modes=7 "
        "preferred_width=1280 preferred_height=800 refresh_millihz=74994 "
        "gpu_timing_proof_required=1 mode_writes=0 used_idx=2 used_head=0 "
        "used_len=1056 fence_verified=1 negotiated_edid=1 notify_writes=2 "
        "driver_ok=15 reset=0 queue_disabled=1 frames_allocated=773 "
        "frames_released=773 pmm_leak=0 qemu_only=1")
MARK = ("WOLFOS_VIRTIO_GPU_DESKTOP_SCANOUT_OK resource_id=1 width=1024 "
        "height=768 format=2 create_type=257 attach_type=262 transfer_type=261 "
        "set_type=259 flush_type=260 clear_type=259 detach_type=263 "
        "unref_type=258 response_type=4352 used_idx=21 used_head=0 used_len=24 "
        "fences_verified=19 notify_writes=21 backing_entries=2 "
        "backing_bytes=3145728 transfer_bands=12 band_rows=64 pixels=786432 "
        "guest_copy_verified=1 host_pixels_verified_by_kernel=0 capture_acks=1 "
        "reset_to_vga_ack=1 reset=0 queue_disabled=1 frames_allocated=773 "
        "frames_released=773 pmm_leak=0 qemu_only=1")
ACK = "WOLFOS_VIRTIO_GPU_SCANOUT_TEST_OK"
TEXT = "\n".join((ATTEST, CAPTURE, DISPLAY, EDID, MARK,
                  "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK", ACK,
                  "WOLFOS_FRAMEBUFFER_OK 1024x768"))


def desktop_image() -> tuple[int, int, bytes]:
    return (WIDTH, HEIGHT, expected_bytes())


class DesktopSerialTests(unittest.TestCase):
    def test_positive_fixture_does_not_replace_the_real_qmp_screenshot(self):
        self.assertTrue(validate_desktop_serial(TEXT))

    def test_marker_fields_are_exact(self):
        for old, new in [
            ("used_idx=21", "used_idx=20"),
            ("used_idx=21", "used_idx=22"),
            ("used_head=0", "used_head=1"),
            ("used_len=24", "used_len=23"),
            ("fences_verified=19", "fences_verified=18"),
            ("fences_verified=19", "fences_verified=20"),
            ("notify_writes=21", "notify_writes=20"),
            ("pixels=786432", "pixels=786431"),
            ("transfer_bands=12", "transfer_bands=11"),
            ("band_rows=64", "band_rows=63"),
            ("backing_bytes=3145728", "backing_bytes=3145727"),
            ("guest_copy_verified=1", "guest_copy_verified=0"),
            ("host_pixels_verified_by_kernel=0", "host_pixels_verified_by_kernel=1"),
            ("capture_acks=1", "capture_acks=0"),
            ("capture_acks=1", "capture_acks=2"),
            ("reset_to_vga_ack=1", "reset_to_vga_ack=0"),
            ("reset=0", "reset=15"),
            ("queue_disabled=1", "queue_disabled=0"),
            ("frames_allocated=773", "frames_allocated=769"),
            ("frames_released=773", "frames_released=772"),
            ("pmm_leak=0", "pmm_leak=1"),
            ("width=1024", "width=1023"),
            ("height=768", "height=767"),
        ]:
            with self.subTest(old=old, new=new):
                self.assertFalse(validate_desktop_serial(
                    TEXT.replace(old, new)))

    def test_backing_entry_budget_is_bounded(self):
        for entries in ("0", "255", "768"):
            with self.subTest(entries=entries):
                self.assertFalse(validate_desktop_serial(
                    TEXT.replace("backing_entries=2",
                                 f"backing_entries={entries}")))
        for entries in ("1", "192", "254"):
            with self.subTest(entries=entries):
                self.assertTrue(validate_desktop_serial(
                    TEXT.replace("backing_entries=2",
                                 f"backing_entries={entries}")))

    def test_attestation_must_be_genuine_unique_and_bound(self):
        broken = (
            TEXT.replace(ATTEST, ""),
            TEXT + "\n" + ATTEST,
            TEXT.replace("source_digest=0b6b1dc5", "source_digest=0b6b1dc4"),
            TEXT.replace("nonce=574f4445534b0004", "nonce=574f4445534b0005"),
            TEXT.replace("geometry=1024x768", "geometry=1024x769"),
            TEXT.replace("stage=desktop", "stage=active"),
            TEXT.replace("WOLFOS_GPU_STAGE_ATTEST", "WOLFOS_GPU_STAGE_ATTEST "),
        )
        for index, candidate in enumerate(broken):
            with self.subTest(case=index):
                self.assertFalse(validate_desktop_serial(candidate))

    def test_capture_stage_must_be_present_once_and_ordered(self):
        broken = (
            TEXT.replace(CAPTURE, ""),
            TEXT + "\n" + CAPTURE,
            TEXT.replace("stage=restored", "stage=baseline"),
            TEXT.replace("stage=restored", "stage=disabled"),
            TEXT.replace(CAPTURE, "") + "\n" + CAPTURE,
            "\n".join((CAPTURE, ATTEST, DISPLAY, EDID, MARK,
                       "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK", ACK,
                       "WOLFOS_FRAMEBUFFER_OK 1024x768")),
            "\n".join((ATTEST, CAPTURE, MARK, DISPLAY, EDID,
                       "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK", ACK,
                       "WOLFOS_FRAMEBUFFER_OK 1024x768")),
        )
        for index, candidate in enumerate(broken):
            with self.subTest(case=index):
                self.assertFalse(validate_desktop_serial(candidate))

    def test_failures_and_foreign_flavors_are_rejected(self):
        broken = (
            TEXT + "\nWOLFOS_VIRTIO_GPU_DESKTOP_FAIL stage=attest_reply",
            TEXT + "\nWOLFOS_GPU_ATTEST_FAIL stage=desktop reason=digest_mismatch",
            TEXT + "\nWOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL preflight=false",
            TEXT + "\nWOLFOS_VIRTIO_GPU_EDID_LIVE_FAIL decode=WrongResponseType",
            TEXT + "\nWOLFOS_VIRTIO_GPU_SCANOUT_FAIL stage=timeout",
            TEXT + "\nWOLFOS_FB_TEXT_FAILED invalid_geometry",
        )
        for index, candidate in enumerate(broken):
            with self.subTest(case=index):
                self.assertFalse(validate_desktop_serial(candidate))

    def test_other_scanout_claims_cannot_coexist(self):
        for foreign in (
            "WOLFOS_VIRTIO_GPU_SCANOUT_OK resource_id=1 width=64 height=64",
            "WOLFOS_VIRTIO_GPU_SCANOUT_RESET_OK reset_to_vga_ack=1",
            "WOLFOS_VIRTIO_GPU_NATIVE_ROLLBACK_OK resource_id=1",
            "WOLFOS_VIRTIO_GPU_TRANSFER2D_OK resource_id=1",
        ):
            with self.subTest(foreign=foreign):
                self.assertFalse(validate_desktop_serial(TEXT + "\n" + foreign))

    def test_display_and_framebuffer_evidence_are_required(self):
        broken = (
            TEXT.replace(DISPLAY, ""),
            TEXT + "\n" + DISPLAY,
            TEXT.replace(DISPLAY, DISPLAY.replace("frames_allocated=773",
                                                  "frames_allocated=9")),
            TEXT.replace(DISPLAY, DISPLAY.replace("frames_released=773",
                                                  "frames_released=9")),
            TEXT.replace(DISPLAY, DISPLAY.replace("width=1280", "width=0")),
            TEXT.replace(EDID, ""),
            TEXT + "\n" + EDID,
            TEXT.replace("WOLFOS_FRAMEBUFFER_OK 1024x768", ""),
            TEXT.replace("WOLFOS_FRAMEBUFFER_OK 1024x768",
                         "WOLFOS_FRAMEBUFFER_OK 1280x800"),
            TEXT.replace("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK", ""),
            TEXT + "\nWOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK",
            TEXT.replace(ACK, ""),
            TEXT + "\n" + ACK,
        )
        for index, candidate in enumerate(broken):
            with self.subTest(case=index):
                self.assertFalse(validate_desktop_serial(candidate))

    def test_geometry_and_nonce_constants_match_the_kernel(self):
        self.assertEqual((WIDTH, HEIGHT, PIXELS), (1024, 768, 786432))
        self.assertEqual(NONCE, 0x574F4445534B0004)
        self.assertIsNotNone(MARKER.fullmatch(MARK))
        self.assertIsNotNone(
            __import__("qemu_virtio_gpu_desktop_scanout").ATTEST.fullmatch(ATTEST))


class DesktopPixelTests(unittest.TestCase):
    def test_pattern_matches_the_kernel_and_changes_everywhere(self):
        # Mirrors virtio_gpu_desktop_wire::pixel_rgb.
        self.assertEqual(expected_rgb(0, 0), (29, 71, 173))
        self.assertEqual(expected_rgb(1023, 767),
                         ((1023 * 3 + 767 * 7 + 29) & 0xFF,
                          (1023 * 11 + 767 * 5 + 71) & 0xFF,
                          (1023 * 13 + 767 * 17 + 173) & 0xFF))
        image = desktop_image()
        self.assertEqual(len(image[2]), PIXELS * 3)
        self.assertEqual(image[2][0:3], bytes(expected_rgb(0, 0)))
        last = (PIXELS - 1) * 3
        self.assertEqual(image[2][last:last + 3], bytes(expected_rgb(1023, 767)))
        value = 0x811C9DC5
        for byte in image[2]:
            value ^= byte
            value = (value * 0x01000193) & 0xFFFFFFFF
        self.assertEqual(value, pattern_digest())

    def test_every_pixel_is_verified_and_corruption_fails(self):
        self.assertEqual(verify_pixels(desktop_image()), PIXELS)
        width, height, rgb = desktop_image()
        for index in (0, (300 * WIDTH + 17) * 3 + 1, PIXELS * 3 - 1):
            broken = bytearray(rgb)
            broken[index] ^= 0x01
            with self.subTest(index=index):
                with self.assertRaises(ProofError):
                    verify_pixels((width, height, bytes(broken)))
        # Row and band boundaries must not be swappable.
        first_row = rgb[0:WIDTH * 3]
        second_row = rgb[WIDTH * 3:2 * WIDTH * 3]
        swapped = second_row + first_row + rgb[2 * WIDTH * 3:]
        with self.assertRaises(ProofError):
            verify_pixels((width, height, swapped))
        with self.assertRaises(ProofError):
            verify_pixels((WIDTH, HEIGHT, rgb[:-1]))

    def test_wrong_geometry_fails(self):
        width, height, rgb = desktop_image()
        for geometry in ((1024, 767), (1023, 768), (1280, 800), (64, 64)):
            with self.subTest(geometry=geometry):
                with self.assertRaises(ProofError):
                    verify_pixels((geometry[0], geometry[1], rgb))


if __name__ == "__main__":
    unittest.main()
