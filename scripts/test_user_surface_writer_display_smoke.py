#!/usr/bin/env python3
"""Adversarial pixel and serial fixtures; never substitutes for real QEMU."""
import unittest

from elf_launch_evidence import transaction_rows
from user_copy_smoke import PROOFS, WRITER_PROOF
from user_surface_writer_display_smoke import (
    BACKGROUND, DISPLAY_OK, H, PIXELS, PREFIX, STAGES, W, X, Y,
    ProofError, expect_active, validate_serial,
)

WIDTH, HEIGHT = X + W + 5, Y + H + 5
ENTER = (
    "WOLFOS_ELF_RUN_ENTER elf64=1 et_exec=1 pt_load=2 rx=1 rw_nx=2 "
    "bss_zero=1 cr3_new=1 root_slot=1 user_entry=0x401000"
)


def serial_evidence():
    rows = transaction_rows(1, 7)
    lines = [
        "WOLFOS_BOOT_OK", rows[0], rows[1], ENTER,
        *PROOFS[:4], *(PREFIX + stage for stage in STAGES),
        DISPLAY_OK, WRITER_PROOF, rows[2], rows[3], *PROOFS[4:],
    ]
    return "\n".join(lines) + "\n"


class PixelEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.baseline = (WIDTH, HEIGHT, bytes(WIDTH * HEIGHT * 3))
        pixels = bytearray(self.baseline[2])
        for y in range(H):
            for x in range(W):
                offset = 3 * ((Y + y) * WIDTH + X + x)
                pixels[offset:offset + 3] = bytes(
                    PIXELS.get((x, y), BACKGROUND)
                )
        self.active = (WIDTH, HEIGHT, bytes(pixels))

    def test_full_exact_changed_patch_accepted(self):
        expect_active(self.active, self.baseline)

    def test_outside_patch_corruption_rejected(self):
        pixels = bytearray(self.active[2])
        pixels[0] = 1
        with self.assertRaises(ProofError):
            expect_active((WIDTH, HEIGHT, bytes(pixels)), self.baseline)

    def test_changed_patch_channel_rejected(self):
        pixels = bytearray(self.active[2])
        offset = 3 * ((Y + 1) * WIDTH + X + 1)
        pixels[offset + 2] ^= 1
        with self.assertRaises(ProofError):
            expect_active((WIDTH, HEIGHT, bytes(pixels)), self.baseline)

    def test_missing_patch_write_rejected(self):
        pixels = bytearray(self.active[2])
        offset = 3 * (Y * WIDTH + X)
        pixels[offset:offset + 3] = self.baseline[2][offset:offset + 3]
        with self.assertRaises(ProofError):
            expect_active((WIDTH, HEIGHT, bytes(pixels)), self.baseline)

    def test_preexisting_exact_color_is_not_a_change(self):
        baseline = bytearray(self.baseline[2])
        offset = 3 * ((Y + 1) * WIDTH + X + 1)
        baseline[offset:offset + 3] = self.active[2][offset:offset + 3]
        with self.assertRaisesRegex(ProofError, "did not change"):
            expect_active(self.active, (WIDTH, HEIGHT, bytes(baseline)))

    def test_truncated_payload_rejected(self):
        with self.assertRaisesRegex(ProofError, "payload length"):
            expect_active((WIDTH, HEIGHT, self.active[2][:-1]), self.baseline)

    def test_extra_payload_rejected(self):
        with self.assertRaisesRegex(ProofError, "payload length"):
            expect_active((WIDTH, HEIGHT, self.active[2] + b"x"), self.baseline)

    def test_truncated_baseline_rejected(self):
        with self.assertRaisesRegex(ProofError, "payload length"):
            expect_active(self.active, (WIDTH, HEIGHT, self.baseline[2][:-1]))

    def test_wrong_geometry_rejected(self):
        with self.assertRaises(ProofError):
            expect_active((WIDTH + 1, HEIGHT, self.active[2]), self.baseline)

    def test_too_small_geometry_rejected(self):
        with self.assertRaises(ProofError):
            expect_active((X + W - 1, Y + H, self.active[2]), self.baseline)


class SerialEvidenceTests(unittest.TestCase):
    def test_complete_hardware_evidence_accepted(self):
        validate_serial(serial_evidence(), 33)

    def test_debug_exit_must_be_exact(self):
        with self.assertRaises(ProofError):
            validate_serial(serial_evidence(), 0)

    def test_missing_actual_transaction_rejected(self):
        rows = transaction_rows(1, 7)
        with self.assertRaises(ProofError):
            validate_serial(serial_evidence().replace(rows[2] + "\n", ""), 33)

    def test_duplicate_display_ok_rejected(self):
        with self.assertRaises(ProofError):
            validate_serial(serial_evidence() + DISPLAY_OK + "\n", 33)

    def test_reordered_capture_stages_rejected(self):
        output = serial_evidence().replace(
            PREFIX + "baseline", PREFIX + "_temporary"
        ).replace(
            PREFIX + "active", PREFIX + "baseline"
        ).replace(
            PREFIX + "_temporary", PREFIX + "active"
        )
        with self.assertRaises(ProofError):
            validate_serial(output, 33)

    def test_missing_stage_rejected(self):
        with self.assertRaises(ProofError):
            validate_serial(
                serial_evidence().replace(PREFIX + "active" + "\n", ""), 33
            )

    def test_out_of_range_user_cr3_slot_rejected(self):
        with self.assertRaises(ProofError):
            validate_serial(
                serial_evidence().replace("root_slot=1", "root_slot=256"), 33
            )

    def test_guest_panic_rejected_even_with_success_log(self):
        with self.assertRaises(ProofError):
            validate_serial(serial_evidence() + "WOLFOS_PANIC\n", 33)


if __name__ == "__main__":
    unittest.main()
