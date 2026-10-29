#!/usr/bin/env python3
"""Adversarial native resize+rollback tests; genuine QEMU is separately mandatory."""
import unittest

from qemu_virtio_gpu_scanout_live_smoke import (
    MARKER,NATIVE_MARKER,PREFIX,ProofError,validate_serial,
    expected_rgb,verify_active,verify_reduced,verify_reexpanded,verify_refused,
)
from test_qemu_virtio_gpu_scanout_live_smoke import (
    CAPTURE1,CAPTURE2,TEXT,image,
)

REDUCED=PREFIX+"reduced"
REEXPANDED=PREFIX+"reexpanded"
REFUSED=PREFIX+"refused"
RESTORED=PREFIX+"restored"
# Matches the offline EDID fixture (modes=1), so the host can cross-check that
# every advertised connector mode was refused.
CATALOG=(
    "WOLFOS_DISPLAY_CATALOG_OK generation=1 entries=3 selectable=2 "
    "device_reported=1 device_width=1920 device_height=1080 "
    "automatic_width=64 automatic_height=64 automatic_refresh=unavailable "
    "automatic_change_required=0 manual_32x32=accepted "
    "manual_32x32_refresh=unavailable "
    "device_reported_mode=rejected:unproven_gpu_timing edid_advertised=1 "
    "edid_refused=1 edid_hz_request=rejected:refresh_not_programmable "
    "plan=some plan_confirm=accepted "
    "plan_wrong_readback=rejected:device_did_not_apply "
    "confirmation_window_ms=15000 gpu_commands_sent=0 used_idx_before=11 "
    "used_idx_after=11 refusal_capture_acks=1 "
    "host_pixels_verified_by_kernel=0"
)
NATIVE_TEXT=TEXT.replace(
    CAPTURE1+"\n",
    CAPTURE1+"\n"+REDUCED+"\n"+REEXPANDED+"\n"+CATALOG+"\n"+REFUSED+"\n"
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
    def test_exact_seven_stage_proof_and_legacy_rejection(self):
        self.assertTrue(validate_serial(NATIVE_TEXT,native_rollback=True))
        self.assertFalse(validate_serial(NATIVE_TEXT))
        self.assertFalse(validate_serial(NATIVE_TEXT,reset_restore=True))
        self.assertFalse(validate_serial(TEXT,native_rollback=True))

    def test_missing_duplicate_swapped_and_fake_markers_fail(self):
        for broken in (
            NATIVE_TEXT.replace(REDUCED+"\n",""),
            NATIVE_TEXT.replace(REEXPANDED+"\n",""),
            NATIVE_TEXT.replace(REFUSED+"\n",""),
            NATIVE_TEXT.replace(RESTORED+"\n",""),
            NATIVE_TEXT+"\n"+REDUCED,
            NATIVE_TEXT.replace(REDUCED+"\n"+REEXPANDED,
                                REEXPANDED+"\n"+REDUCED),
            NATIVE_TEXT.replace(REEXPANDED+"\n"+CATALOG,
                                CATALOG+"\n"+REEXPANDED),
            NATIVE_TEXT.replace(CATALOG+"\n"+REFUSED,REFUSED+"\n"+CATALOG),
            NATIVE_TEXT.replace(NATIVE_MARKER,MARKER),
            NATIVE_TEXT+"\n"+MARKER,
            NATIVE_TEXT+"\nWOLFOS_VIRTIO_GPU_NATIVE_ROLLBACK_FAIL stage=reexpanded",
            NATIVE_TEXT+"\nWOLFOS_DISPLAY_CATALOG_FAIL stage=catalog_device_reported_accepted",
        ):
            with self.subTest(input=broken[:80]):
                self.assertFalse(validate_serial(broken,native_rollback=True))

    def test_catalog_evidence_is_mandatory_and_uniquely_positioned(self):
        # No catalog proof at all: the native rollback alone is not enough.
        self.assertFalse(validate_serial(NATIVE_TEXT.replace(CATALOG+"\n",""),
                                         native_rollback=True))
        self.assertFalse(validate_serial(NATIVE_TEXT.replace(
            CATALOG+"\n",CATALOG+"\n"+CATALOG+"\n"),native_rollback=True))
        # Catalog evidence cannot be claimed by a non-native scenario.
        self.assertFalse(validate_serial(TEXT+"\n"+CATALOG))
        self.assertTrue(validate_serial(NATIVE_TEXT,native_rollback=True))

    def test_catalog_fields_cannot_be_weakened(self):
        for old,new in (
            ("selectable=2","selectable=1"),
            ("selectable=2","selectable=3"),
            ("device_reported=1","device_reported=0"),
            ("automatic_width=64","automatic_width=1280"),
            ("automatic_height=64","automatic_height=800"),
            ("automatic_refresh=unavailable","automatic_refresh=74994"),
            ("manual_32x32_refresh=unavailable","manual_32x32_refresh=60000"),
            ("device_reported_mode=rejected:unproven_gpu_timing",
             "device_reported_mode=accepted"),
            ("edid_refused=1","edid_refused=0"),
            ("edid_advertised=1","edid_advertised=2"),
            ("edid_hz_request=rejected:refresh_not_programmable",
             "edid_hz_request=accepted"),
            ("plan=some","plan=none"),
            ("plan_wrong_readback=rejected:device_did_not_apply",
             "plan_wrong_readback=accepted"),
            ("confirmation_window_ms=15000","confirmation_window_ms=0"),
            ("gpu_commands_sent=0","gpu_commands_sent=1"),
            ("used_idx_before=11","used_idx_before=12"),
            ("used_idx_after=11","used_idx_after=12"),
            ("refusal_capture_acks=1","refusal_capture_acks=0"),
            ("host_pixels_verified_by_kernel=0","host_pixels_verified_by_kernel=1"),
            ("device_width=1920","device_width=64"),
            ("device_height=1080","device_height=64"),
            ("generation=1","generation=0"),
            ("entries=3","entries=17"),
        ):
            with self.subTest(field=old):
                self.assertFalse(validate_serial(
                    NATIVE_TEXT.replace(CATALOG,CATALOG.replace(old,new)),
                    native_rollback=True,
                ))

    def test_fences_completions_and_cleanup_strict(self):
        for old,new in (
            ("used_idx=14","used_idx=10"),
            ("used_len=24","used_len=23"),
            ("fences_verified=12","fences_verified=8"),
            ("notify_writes=14","notify_writes=10"),
            ("native_switch_acks=4","native_switch_acks=3"),
            ("capture_acks=7","capture_acks=6"),
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

    def test_refused_mode_change_must_leave_every_pixel_and_geometry(self):
        active=image()
        # A rejected mode change provably does nothing: identical bytes pass.
        verify_refused(active,active)
        mutated=bytearray(active[2])
        mutated[3*(63*64+63)+1]^=1
        with self.assertRaisesRegex(ProofError,"altered pixel"):
            verify_refused(active,(64,64,bytes(mutated)))
        with self.assertRaisesRegex(ProofError,"resized the display"):
            verify_refused(active,reduced_image())
        with self.assertRaisesRegex(ProofError,"resized the display"):
            verify_refused(active,(1024,768,bytes(1024*768*3)))
        with self.assertRaises(ProofError):
            verify_refused(reduced_image(),active)

if __name__=="__main__":
    unittest.main()
