#!/usr/bin/env python3
"""Adversarial pixel and serial fixtures; never substitutes for real QEMU."""
import unittest

from elf_launch_evidence import transaction_rows
from user_copy_smoke import PROOFS, WRITER_PROOF
from user_surface_writer_display_smoke import (
    BACKGROUND, DISPLAY_OK, H, PIXELS, PREFIX, STAGES, W, X, Y,
    MAX_SERIAL_BYTES, MAX_SERIAL_LINE_BYTES, append_serial_chunk,
    ProofError, expect_active, validate_serial, parse_capture_stage_line,
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


class BoundedSerialChunkTests(unittest.TestCase):
    def test_lines_in_one_chunk(self):
        received = bytearray()
        pending, lines = append_serial_chunk(received, b"", b"a\nb\npartial")
        self.assertEqual(lines, [b"a", b"b"])
        self.assertEqual(pending, b"partial")
        self.assertEqual(received, b"a\nb\npartial")

    def test_line_split_across_chunks(self):
        received = bytearray()
        pending, lines = append_serial_chunk(received, b"", b"base")
        self.assertEqual(lines, [])
        pending, lines = append_serial_chunk(received, pending, b"line\nactive\n")
        self.assertEqual(lines, [b"baseline", b"active"])
        self.assertEqual(pending, b"")

    def test_exact_total_byte_boundary_allowed(self):
        received = bytearray(b"x" * (MAX_SERIAL_BYTES - 2))
        pending, lines = append_serial_chunk(received, b"", b"\nq")
        self.assertEqual(lines, [b""])
        self.assertEqual(pending, b"q")
        self.assertEqual(len(received), MAX_SERIAL_BYTES)

    def test_total_byte_limit_rejected_without_mutation(self):
        received = bytearray(b"x" * MAX_SERIAL_BYTES)
        with self.assertRaisesRegex(ProofError, "bounded size"):
            append_serial_chunk(received, b"", b"X")
        self.assertEqual(len(received), MAX_SERIAL_BYTES)

    def test_overlong_unterminated_line_rejected(self):
        received = bytearray()
        with self.assertRaisesRegex(ProofError, "line"):
            append_serial_chunk(received, b"", b"X" * (MAX_SERIAL_LINE_BYTES + 1))
        self.assertEqual(len(received), 0)

    def test_overlong_terminated_line_rejected(self):
        received = bytearray()
        with self.assertRaisesRegex(ProofError, "line"):
            append_serial_chunk(received, b"", b"X" * (MAX_SERIAL_LINE_BYTES + 1) + b"\n")
        self.assertEqual(len(received), 0)

    def test_byte_limit_with_pending_chunk_rejected(self):
        received = bytearray(b"z" * (MAX_SERIAL_BYTES - 1))
        with self.assertRaisesRegex(ProofError, "bounded size"):
            append_serial_chunk(received, b"abc", b"XY")
        self.assertEqual(len(received), MAX_SERIAL_BYTES - 1)

    def test_fragmented_line_rejected_without_extra_bytes(self):
        received = bytearray()
        pending, lines = append_serial_chunk(received, b"", b"X" * MAX_SERIAL_LINE_BYTES)
        self.assertEqual(lines, [])
        with self.assertRaisesRegex(ProofError, "line"):
            append_serial_chunk(received, pending, b"Y")
        self.assertEqual(len(received), MAX_SERIAL_LINE_BYTES)

    def test_exact_line_boundary_allowed(self):
        received = bytearray()
        pending, lines = append_serial_chunk(received, b"", b"X" * MAX_SERIAL_LINE_BYTES + b"\n")
        self.assertEqual(len(lines[0]), MAX_SERIAL_LINE_BYTES)
        self.assertEqual(pending, b"")


class RawCaptureStageTests(unittest.TestCase):
    def test_normal_baseline(self):
        self.assertEqual(
            parse_capture_stage_line(PREFIX.encode() + b"baseline", "baseline"), "baseline")

    def test_accept_crlf_framing(self):
        self.assertEqual(
            parse_capture_stage_line(PREFIX.encode() + b"active\r", "active"), "active")

    def test_ignore_unrelated_serial_line(self):
        self.assertIsNone(parse_capture_stage_line(b"WOLFOS_BOOT_OK", "baseline"))

    def test_reject_leading_spaces(self):
        with self.assertRaises(ProofError):
            parse_capture_stage_line(b" " + PREFIX.encode() + b"baseline", "baseline")

    def test_reject_trailing_spaces(self):
        with self.assertRaises(ProofError):
            parse_capture_stage_line(PREFIX.encode() + b"baseline ", "baseline")

    def test_reject_out_of_order_stage(self):
        with self.assertRaises(ProofError):
            parse_capture_stage_line(PREFIX.encode() + b"active", "baseline")

    def test_reject_extra_stage(self):
        with self.assertRaises(ProofError):
            parse_capture_stage_line(PREFIX.encode() + b"baseline", None)

    def test_reject_embedded_stage(self):
        with self.assertRaises(ProofError):
            parse_capture_stage_line(b"fake-" + PREFIX.encode() + b"baseline", "baseline")

    def test_reject_non_ascii_suffix(self):
        with self.assertRaises(ProofError):
            parse_capture_stage_line(PREFIX.encode() + b"baseline\xff", "baseline")

    def test_reject_stage_with_extra_tokens(self):
        with self.assertRaises(ProofError):
            parse_capture_stage_line(PREFIX.encode() + b"baseline stage=active", "baseline")


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

    def test_embedded_display_success_rejected(self):
        forged = serial_evidence().replace(
            DISPLAY_OK + "\n", "prefix-" + DISPLAY_OK + "\n"
        )
        with self.assertRaises(ProofError):
            validate_serial(forged, 33)

    def test_embedded_writer_proof_rejected(self):
        forged = serial_evidence().replace(
            WRITER_PROOF + "\n", "prefix-" + WRITER_PROOF + "\n"
        )
        with self.assertRaises(ProofError):
            validate_serial(forged, 33)

    def test_capture_stage_embedded_in_other_line_rejected(self):
        forged = serial_evidence().replace(
            PREFIX + "baseline" + "\n", "prefix-" + PREFIX + "baseline" + "\n"
        )
        with self.assertRaises(ProofError):
            validate_serial(forged, 33)

    def test_unexpected_extra_stage_rejected(self):
        forged = serial_evidence().replace(
            PREFIX + "active" + "\n",
            PREFIX + "unknown" + "\n" + PREFIX + "active" + "\n"
        )
        with self.assertRaises(ProofError):
            validate_serial(forged, 33)

    def test_duplicate_capture_stage_rejected(self):
        forged = serial_evidence().replace(
            PREFIX + "active" + "\n",
            PREFIX + "active" + "\n" + PREFIX + "active" + "\n"
        )
        with self.assertRaises(ProofError):
            validate_serial(forged, 33)

    def test_embedded_boot_marker_rejected(self):
        text = serial_evidence().replace("WOLFOS_BOOT_OK\n", "fake-WOLFOS_BOOT_OK\n")
        with self.assertRaises(ProofError):
            validate_serial(text, 33)

    def test_embedded_usercopy_write_marker_rejected(self):
        text = serial_evidence().replace(PROOFS[3] + "\n", "fake-" + PROOFS[3] + "\n")
        with self.assertRaises(ProofError):
            validate_serial(text, 33)

    def test_extra_content_on_elf_entry_rejected(self):
        text = serial_evidence().replace(ENTER + "\n", ENTER + " extra\n")
        with self.assertRaises(ProofError):
            validate_serial(text, 33)

    def test_embedded_hello_from_wolfos_rejected(self):
        text = serial_evidence().replace(
            "Hello from WolfOS!\n", "fake-Hello from WolfOS!\n"
        )
        with self.assertRaises(ProofError):
            validate_serial(text, 33)

    def test_embedded_usercopy_run_marker_rejected(self):
        text = serial_evidence().replace(PROOFS[-1] + "\n", "fake-" + PROOFS[-1] + "\n")
        with self.assertRaises(ProofError):
            validate_serial(text, 33)

    def test_duplicate_usercopy_id_marker_rejected(self):
        text = serial_evidence() + PROOFS[0] + "\n"
        with self.assertRaises(ProofError):
            validate_serial(text, 33)

    def test_guest_panic_rejected_even_with_success_log(self):
        with self.assertRaises(ProofError):
            validate_serial(serial_evidence() + "WOLFOS_PANIC\n", 33)


if __name__ == "__main__":
    unittest.main()
