#!/usr/bin/env python3
"""Adversarial offline tests for the standalone Ring3 GDT/TR/TSS QEMU gate."""
import unittest

from user_ring_prep_smoke import strict_ring_prep_evidence, strict_boot_evidence

PROOF = (
    "WOLFOS_RING_PREP_OK tr=0x18 user_cs=0x33 user_ds=0x2b "
    "rsp0_aligned=1 rsp0_stack_kib=16 ist_disjoint=1 guards=1 "
    "cpl=0 ring3=0"
)


class RingPrepEvidenceTests(unittest.TestCase):
    def test_boot_marker_exactly_once(self):
        self.assertTrue(strict_boot_evidence("diagnostic\nWOLFOS_BOOT_OK\n"))
        for output in ("", "WOLFOS_BOOT_OK_FAKE", "prefix WOLFOS_BOOT_OK",
                       "WOLFOS_BOOT_OK\nWOLFOS_BOOT_OK",
                       "WOLFOS_BOOT_OK\nprefix WOLFOS_BOOT_OK"):
            with self.subTest(output=output):
                self.assertFalse(strict_boot_evidence(output))

    def test_accepts_one_complete_proof_with_unrelated_output(self):
        self.assertTrue(strict_ring_prep_evidence(
            "WOLFOS_BOOT_OK\n" + PROOF + "\ndiagnostic: unrelated output"))

    def test_rejects_missing_truncated_and_embedded_proofs(self):
        for output in (
            "",
            "WOLFOS_BOOT_OK",
            "WOLFOS_RING_PREP_OK",
            "WOLFOS_RING_PREP_OK tr=0x18 user_cs=0x33",
            "diagnostic: " + PROOF,
            PROOF + " forged=1",
        ):
            with self.subTest(output=output):
                self.assertFalse(strict_ring_prep_evidence(output))

    def test_rejects_duplicate_or_forged_additional_markers(self):
        for extra in (
            PROOF,
            "diagnostic: " + PROOF,
            "WOLFOS_RING_PREP_OK",
            "WOLFOS_RING_PREP_OK_FAKE tr=0x18",
        ):
            with self.subTest(extra=extra):
                self.assertFalse(strict_ring_prep_evidence(PROOF + "\n" + extra))

    def test_rejects_invalid_descriptor_or_stack_metadata(self):
        for before, after in (
            ("tr=0x18", "tr=0x20"),
            ("user_cs=0x33", "user_cs=0x30"),
            ("user_ds=0x2b", "user_ds=0x28"),
            ("user_ds=0x2b", "user_ds=0x33"),
            ("rsp0_aligned=1", "rsp0_aligned=0"),
            ("rsp0_stack_kib=16", "rsp0_stack_kib=8"),
            ("ist_disjoint=1", "ist_disjoint=0"),
            ("guards=1", "guards=0"),
            ("cpl=0", "cpl=3"),
            ("ring3=0", "ring3=1"),
        ):
            with self.subTest(after=after):
                self.assertFalse(strict_ring_prep_evidence(PROOF.replace(before, after)))


if __name__ == "__main__":
    unittest.main()
