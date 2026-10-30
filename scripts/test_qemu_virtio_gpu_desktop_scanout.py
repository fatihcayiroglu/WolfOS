#!/usr/bin/env python3
"""Adversarial serial/pixel fixtures for the transactional desktop proof.

The real QEMU boot remains mandatory: this file only proves that the host
validator rejects weak, forged or reordered evidence, so a green CI run
cannot be produced by a plausible-looking log alone.
"""
import unittest

from qemu_virtio_gpu_desktop_scanout import (
    ALT_HEIGHT, ALT_WIDTH, CAPTURE_PREFIX, HEIGHT, MARKER, PIXELS, WIDTH,
    ProofError, alt_bytes, alt_rgb, expected_bytes, expected_rgb,
    alt_pattern_digest, pattern_digest, validate_desktop_serial,
    verify_alt_pixels, verify_pixels,
)

DESKTOP_DIGEST = f"{pattern_digest():08x}"
ALT_DIGEST = f"{alt_pattern_digest():08x}"
ATTEST_P = ("WOLFOS_GPU_STAGE_ATTEST stage=desktop geometry=1024x768 "
            f"nonce=574f4445534b0004 source_digest={DESKTOP_DIGEST}")
ATTEST_S = ("WOLFOS_GPU_STAGE_ATTEST stage=reduced geometry=1024x384 "
            f"nonce=574f4445534b0005 source_digest={ALT_DIGEST}")
ATTEST_T = ("WOLFOS_GPU_STAGE_ATTEST stage=applied geometry=1024x768 "
            f"nonce=574f4445534b0006 source_digest={DESKTOP_DIGEST}")
ATTEST_R = ("WOLFOS_GPU_STAGE_ATTEST stage=rollback geometry=1024x384 "
            f"nonce=574f4445534b0007 source_digest={ALT_DIGEST}")
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
CATALOG = ("WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_OK generation=1 entries=3 "
           "selectable=2 attested=2 device_reported=1 device_width=1280 "
           "device_height=800 selected=1024x768 selected_refresh=unavailable "
           "second=1024x384 device_claim=rejected:unproven_gpu_timing "
           "edid_millihz=74994 "
           "edid_hz_request=rejected:refresh_not_programmable "
           "applied_change_plan=none "
           "unattested_catalog=rejected:no_selectable_mode gpu_commands_sent=0")
HPET = ("WOLFOS_HPET_CLOCK_OK vendor=0x8086 revision=1 timers=3 "
        "counter_bits=64 period_fs=10000000 base=0xfed00000 uncached=1 "
        "main_counter_enabled=1 mmio_writes=1 comparators_programmed=0 "
        "interrupts_routed=0")
TX_OK = ("WOLFOS_VIRTIO_GPU_MODE_TX_OK generation=1 token=574f4c4654580001 "
         "from=1024x384 to=1024x768 deadline_ms=15000 deadline_clock=hpet "
         "verdict_elapsed_ms=3 verdict_source=host "
         "readback=console_enabled state=confirmed outcome=confirmed "
         "restore=unused window_enforced_by=guest "
         "host_pixels_verified_by_kernel=0")
TX_EXPIRED = ("WOLFOS_VIRTIO_GPU_MODE_TX_OK generation=1 token=574f4c4654580001 "
              "from=1024x384 to=1024x768 deadline_ms=15000 deadline_clock=hpet "
              "verdict_elapsed_ms=15204 verdict_source=guest "
              "readback=console_enabled "
              "state=rolled_back outcome=rolled_back restore=verified "
              "window_enforced_by=guest host_pixels_verified_by_kernel=0")
TX_SILENT = ("WOLFOS_VIRTIO_GPU_MODE_TX_OK generation=1 token=574f4c4654580001 "
             "from=1024x384 to=1024x768 deadline_ms=15000 deadline_clock=hpet "
             "verdict_elapsed_ms=15009 verdict_source=guest "
             "readback=console_enabled "
             "state=rolled_back outcome=rolled_back restore=verified "
             "window_enforced_by=guest host_pixels_verified_by_kernel=0")


def mark(used=38, entries=2, acks=3):
    return ("WOLFOS_VIRTIO_GPU_DESKTOP_SCANOUT_OK resource_id=1 width=1024 "
            "height=768 format=2 create_type=257 attach_type=262 "
            "transfer_type=261 set_type=259 flush_type=260 clear_type=259 "
            "detach_type=263 unref_type=258 response_type=4352 "
            f"used_idx={used} used_head=0 used_len=24 "
            f"fences_verified={used - 2} notify_writes={used} "
            f"backing_entries={entries} backing_bytes=3145728 "
            "transfer_bands=12 band_rows=64 alt=1024x384 alt_bands=6 "
            "pixels=786432 guest_copy_verified=1 "
            "host_pixels_verified_by_kernel=0 "
            f"capture_acks={acks} reset_to_vga_ack=1 reset=0 queue_disabled=1 "
            "frames_allocated=773 frames_released=773 pmm_leak=0 qemu_only=1")


TAIL = ("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK",
        "WOLFOS_VIRTIO_GPU_SCANOUT_TEST_OK",
        "WOLFOS_FRAMEBUFFER_OK 1024x768")


def serial(tx=TX_OK, used=38, acks=3, stages=(ATTEST_P, ATTEST_S, ATTEST_T),
           marker=None, clock=HPET):
    return "\n".join((DISPLAY, EDID, clock, *stages, CATALOG, tx,
                      CAPTURE, marker or mark(used=used, acks=acks), *TAIL))


TEXT = serial()
EXPIRED = serial(tx=TX_EXPIRED, used=46, acks=4,
                 stages=(ATTEST_P, ATTEST_S, ATTEST_T, ATTEST_R))
SILENT = serial(tx=TX_SILENT, used=46, acks=4,
                stages=(ATTEST_P, ATTEST_S, ATTEST_T, ATTEST_R))


class DesktopSerialTests(unittest.TestCase):
    def test_positive_and_expired_fixtures_are_the_host_contract(self):
        self.assertTrue(validate_desktop_serial(TEXT))
        self.assertTrue(validate_desktop_serial(EXPIRED, expired=True))
        # The two outcomes are not interchangeable.
        self.assertFalse(validate_desktop_serial(EXPIRED))
        self.assertFalse(validate_desktop_serial(TEXT, expired=True))

    def test_the_window_belongs_to_the_guest_clock(self):
        self.assertTrue(validate_desktop_serial(SILENT, expired=True, silent=True))
        # Serial evidence cannot tell "silent" from "answered late": both show a
        # guest-expired window. Only the host knows which one it did, and both
        # must validate for their own run.
        self.assertTrue(validate_desktop_serial(SILENT, expired=True))
        self.assertTrue(validate_desktop_serial(EXPIRED, expired=True, silent=True))
        # A silent peer can never be reported as a peer-sourced verdict.
        self.assertFalse(validate_desktop_serial(
            SILENT.replace("verdict_source=guest", "verdict_source=host"),
            expired=True, silent=True))
        # The late answer may be graded by either clock, but only after a real
        # elapsed window; the guest reports which one it used.
        self.assertTrue(validate_desktop_serial(
            EXPIRED.replace("verdict_source=guest", "verdict_source=host"),
            expired=True))
        # A peer answer can never confirm a change inside the window.
        self.assertFalse(validate_desktop_serial(
            TEXT.replace("verdict_source=host", "verdict_source=guest")))
        # Neither outcome is acceptable without a validated guest clock.
        for broken in (
            TEXT.replace("deadline_clock=hpet", "deadline_clock=absent"),
            TEXT.replace("window_enforced_by=guest", "window_enforced_by=host"),
            TEXT.replace("verdict_source=host", "verdict_source=guest"),
            TEXT.replace(HPET, ""),
            TEXT.replace(HPET, "WOLFOS_HPET_CLOCK_ABSENT reason=bad_period"),
            TEXT.replace(HPET, HPET + "\n" + HPET),
            TEXT.replace("period_fs=10000000", "period_fs=0"),
            TEXT.replace("period_fs=10000000", "period_fs=100000001"),
            TEXT.replace("counter_bits=64", "counter_bits=32"),
            TEXT.replace("vendor=0x8086", "vendor=0x1234"),
            TEXT.replace("uncached=1", "uncached=0"),
            TEXT.replace("comparators_programmed=0", "comparators_programmed=1"),
            TEXT.replace("main_counter_enabled=1", "main_counter_enabled=0"),
            TEXT.replace("interrupts_routed=0", "interrupts_routed=1"),
        ):
            with self.subTest(broken=broken[:48]):
                self.assertFalse(validate_desktop_serial(broken))
        # The clock must be established before the transaction it grades.
        reordered = "\n".join((DISPLAY, EDID, ATTEST_P, ATTEST_S, ATTEST_T,
                                CATALOG, TX_OK, HPET, CAPTURE, mark(), *TAIL))
        self.assertFalse(validate_desktop_serial(reordered))
        # A guest-measured expiry below the window is still a lie.
        self.assertFalse(validate_desktop_serial(
            SILENT.replace("verdict_elapsed_ms=15009", "verdict_elapsed_ms=9999"),
            expired=True, silent=True))

    def test_marker_fields_are_exact(self):
        for old, new in [
            ("used_idx=38", "used_idx=37"),
            ("used_idx=38", "used_idx=39"),
            ("fences_verified=36", "fences_verified=35"),
            ("fences_verified=36", "fences_verified=37"),
            ("notify_writes=38", "notify_writes=37"),
            ("capture_acks=3", "capture_acks=2"),
            ("capture_acks=3", "capture_acks=4"),
            ("pixels=786432", "pixels=786431"),
            ("transfer_bands=12", "transfer_bands=11"),
            ("alt_bands=6", "alt_bands=5"),
            ("alt=1024x384", "alt=1024x768"),
            ("backing_bytes=3145728", "backing_bytes=3145727"),
            ("guest_copy_verified=1", "guest_copy_verified=0"),
            ("host_pixels_verified_by_kernel=0", "host_pixels_verified_by_kernel=1"),
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
                self.assertFalse(validate_desktop_serial(TEXT.replace(old, new)))

    def test_the_expired_path_needs_its_own_exact_counts(self):
        for marker in (mark(used=38, acks=4), mark(used=46, acks=3),
                       mark(used=44, acks=4), mark(used=46, acks=4)):
            with self.subTest(marker=marker.split()[3]):
                expected = marker == mark(used=46, acks=4)
                self.assertEqual(
                    validate_desktop_serial(EXPIRED.replace(mark(used=46, acks=4),
                                                            marker), expired=True),
                    expected)

    def test_backing_entry_budget_is_bounded(self):
        for entries in ("0", "255", "768"):
            with self.subTest(entries=entries):
                self.assertFalse(validate_desktop_serial(TEXT.replace(
                    "backing_entries=2", f"backing_entries={entries}")))
        for entries in ("1", "192", "254"):
            with self.subTest(entries=entries):
                self.assertTrue(validate_desktop_serial(TEXT.replace(
                    "backing_entries=2", f"backing_entries={entries}")))

    def test_each_stage_challenge_must_be_genuine_unique_and_bound(self):
        broken = (
            TEXT.replace(ATTEST_S, ""),
            TEXT + "\n" + ATTEST_T,
            TEXT.replace("nonce=574f4445534b0005", "nonce=574f4445534b0004"),
            TEXT.replace("nonce=574f4445534b0006", "nonce=574f4445534b0005"),
            TEXT.replace("geometry=1024x384", "geometry=1024x385"),
            TEXT.replace("stage=applied", "stage=desktop"),
            TEXT.replace("stage=reduced", "stage=applied"),
            TEXT.replace(ATTEST_S, ATTEST_S.replace(ALT_DIGEST, DESKTOP_DIGEST)),
            TEXT.replace(ATTEST_T, ATTEST_T.replace(DESKTOP_DIGEST, ALT_DIGEST)),
            TEXT.replace(ATTEST_P, ATTEST_P.replace(DESKTOP_DIGEST, "deadbeef")),
            TEXT.replace("WOLFOS_GPU_STAGE_ATTEST", "WOLFOS_GPU_STAGE_ATTEST "),
        )
        for index, candidate in enumerate(broken):
            with self.subTest(case=index):
                self.assertFalse(validate_desktop_serial(candidate))

    def test_stage_order_and_missing_restoration_capture(self):
        broken = (
            "\n".join((DISPLAY, EDID, ATTEST_S, ATTEST_P, ATTEST_T, CATALOG,
                       TX_OK, CAPTURE, mark(), *TAIL)),
            "\n".join((DISPLAY, EDID, ATTEST_P, ATTEST_S, ATTEST_T, TX_OK,
                       CATALOG, CAPTURE, mark(), *TAIL)),
            TEXT.replace(CAPTURE, ""),
            TEXT + "\n" + CAPTURE,
            TEXT.replace("stage=restored", "stage=disabled"),
        )
        for index, candidate in enumerate(broken):
            with self.subTest(case=index):
                self.assertFalse(validate_desktop_serial(candidate))

    def test_confirmation_inside_the_window_and_rollback_after_it(self):
        broken = (
            TEXT.replace("verdict_elapsed_ms=3", "verdict_elapsed_ms=15000"),
            TEXT.replace("verdict_elapsed_ms=3", "verdict_elapsed_ms=90000"),
            TEXT.replace("restore=unused", "restore=verified"),
            TEXT.replace("state=confirmed outcome=confirmed",
                         "state=rolled_back outcome=rolled_back"),
            TEXT.replace("deadline_ms=15000", "deadline_ms=1000"),
            TEXT.replace("from=1024x384 to=1024x768",
                         "from=1024x768 to=1024x384"),
            TEXT.replace("token=574f4c4654580001", "token=574f4c4654580002"),
            TEXT + "\nWOLFOS_VIRTIO_GPU_MODE_TX_FAIL stage=deadline_not_reached "
                   "state=pending",
        )
        for index, candidate in enumerate(broken):
            with self.subTest(case=index):
                self.assertFalse(validate_desktop_serial(candidate))
        for index, candidate in enumerate((
            EXPIRED.replace("verdict_elapsed_ms=15204",
                            "verdict_elapsed_ms=14999"),
            EXPIRED.replace("verdict_elapsed_ms=15204",
                            "verdict_elapsed_ms=90000"),
            EXPIRED.replace("restore=verified", "restore=unused"),
        )):
            with self.subTest(expired_case=index):
                self.assertFalse(validate_desktop_serial(candidate, expired=True))

    def test_catalog_needs_two_proven_geometries(self):
        broken = (
            TEXT.replace(CATALOG, ""),
            TEXT + "\n" + CATALOG,
            TEXT.replace("selectable=2", "selectable=1"),
            TEXT.replace("attested=2", "attested=1"),
            TEXT.replace("second=1024x384", "second=1024x768"),
            TEXT.replace("selected=1024x768", "selected=1024x384"),
            TEXT.replace("selected_refresh=unavailable",
                         "selected_refresh=verified"),
            TEXT.replace(" entries=3 ", " entries=2 "),
            TEXT.replace("device_claim=rejected:unproven_gpu_timing",
                         "device_claim=accepted"),
            TEXT.replace("edid_hz_request=rejected:refresh_not_programmable",
                         "edid_hz_request=accepted"),
            TEXT.replace("unattested_catalog=rejected:no_selectable_mode",
                         "unattested_catalog=selectable"),
            TEXT.replace("gpu_commands_sent=0", "gpu_commands_sent=38"),
            TEXT.replace("generation=1 entries=3", "generation=2 entries=3"),
            TEXT.replace("edid_millihz=74994", "edid_millihz=60000"),
            TEXT.replace("device_width=1280", "device_width=1024"),
            TEXT.replace("device_height=800", "device_height=768"),
        )
        for index, candidate in enumerate(broken):
            with self.subTest(case=index):
                self.assertFalse(validate_desktop_serial(candidate))

    def test_failures_and_foreign_flavors_are_rejected(self):
        broken = (
            TEXT + "\nWOLFOS_VIRTIO_GPU_DESKTOP_FAIL stage=attest_reply",
            TEXT + "\nWOLFOS_GPU_ATTEST_FAIL stage=applied reason=digest_mismatch",
            TEXT + "\nWOLFOS_VIRTIO_GPU_MODE_TX_FAIL stage=rollback_unverified "
                   "state=unreconciled",
            TEXT + "\nWOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL preflight=false",
            TEXT + "\nWOLFOS_VIRTIO_GPU_EDID_LIVE_FAIL decode=WrongResponseType",
            TEXT + "\nWOLFOS_FB_TEXT_FAILED invalid_geometry",
        )
        for index, candidate in enumerate(broken):
            with self.subTest(case=index):
                self.assertFalse(validate_desktop_serial(candidate))
        for foreign in (
            "WOLFOS_VIRTIO_GPU_SCANOUT_OK resource_id=1 width=64 height=64",
            "WOLFOS_VIRTIO_GPU_SCANOUT_RESET_OK reset_to_vga_ack=1",
            "WOLFOS_VIRTIO_GPU_NATIVE_ROLLBACK_OK resource_id=1",
            "WOLFOS_VIRTIO_GPU_TRANSFER2D_OK resource_id=1",
        ):
            with self.subTest(foreign=foreign):
                self.assertFalse(validate_desktop_serial(TEXT + "\n" + foreign))

    def test_display_edid_and_framebuffer_evidence_are_required(self):
        broken = (
            TEXT.replace(DISPLAY, ""),
            TEXT + "\n" + DISPLAY,
            TEXT.replace(DISPLAY, DISPLAY.replace("frames_allocated=773",
                                                  "frames_allocated=9")),
            TEXT.replace(DISPLAY, DISPLAY.replace("width=1280", "width=0")),
            TEXT.replace(EDID, ""),
            TEXT.replace("WOLFOS_FRAMEBUFFER_OK 1024x768", ""),
            TEXT.replace("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK", ""),
            TEXT.replace("WOLFOS_VIRTIO_GPU_SCANOUT_TEST_OK", ""),
            TEXT + "\n" + "WOLFOS_VIRTIO_GPU_SCANOUT_TEST_OK",
        )
        for index, candidate in enumerate(broken):
            with self.subTest(case=index):
                self.assertFalse(validate_desktop_serial(candidate))


class DesktopPixelTests(unittest.TestCase):
    def test_patterns_are_exact_and_distinct(self):
        self.assertEqual(expected_rgb(0, 0), (29, 71, 173))
        self.assertNotEqual(expected_rgb(0, 0), expected_rgb(0, 16))
        self.assertEqual(alt_rgb(0, 0), (244, 0x5A ^ 0x35, 97))
        self.assertNotEqual(alt_rgb(37, 91), expected_rgb(37, 91))
        self.assertEqual(len(expected_bytes()), PIXELS * 3)
        self.assertEqual(len(alt_bytes()), ALT_WIDTH * ALT_HEIGHT * 3)

    def test_desktop_capture_is_verified_pixel_for_pixel(self):
        verify_pixels((WIDTH, HEIGHT, expected_bytes()))
        broken = bytearray(expected_bytes())
        broken[3 * (32 * WIDTH + 17) + 1] ^= 1
        with self.assertRaises(ProofError):
            verify_pixels((WIDTH, HEIGHT, bytes(broken)))
        with self.assertRaises(ProofError):
            verify_pixels((WIDTH, HEIGHT - 1, expected_bytes()))
        # A 1024x384 capture cannot pass as the desktop, and the reverse holds.
        with self.assertRaises(ProofError):
            verify_pixels((ALT_WIDTH, ALT_HEIGHT, alt_bytes()))
        with self.assertRaises(ProofError):
            verify_alt_pixels((WIDTH, HEIGHT, expected_bytes()))

    def test_reduced_capture_is_verified_pixel_for_pixel(self):
        verify_alt_pixels((ALT_WIDTH, ALT_HEIGHT, alt_bytes()))
        broken = bytearray(alt_bytes())
        broken[3 * (192 * ALT_WIDTH + 512) + 2] ^= 1
        with self.assertRaises(ProofError):
            verify_alt_pixels((ALT_WIDTH, ALT_HEIGHT, bytes(broken)))
        # A stale desktop frame must not pass as the reduced scanout.
        stale = bytearray(alt_bytes())
        stale[:3 * ALT_WIDTH] = expected_bytes()[:3 * ALT_WIDTH]
        with self.assertRaises(ProofError):
            verify_alt_pixels((ALT_WIDTH, ALT_HEIGHT, bytes(stale)))


if __name__ == "__main__":
    unittest.main()
