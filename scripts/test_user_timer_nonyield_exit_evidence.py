#!/usr/bin/env python3
"""Offline regression tests for strict QEMU Ring3 EXIT evidence validation."""
import unittest

from user_timer_nonyield_smoke import exit_markers_well_formed

EXIT1 = "WOLFOS_RING3_NONYIELD_EXIT pid=1 progress=10 private_cr3=1 rsp0_guarded=1"
EXIT2 = "WOLFOS_RING3_NONYIELD_EXIT pid=2 progress=20 private_cr3=1 rsp0_guarded=1"
SWITCH = "WOLFOS_RING3_NONYIELD_EXIT_SWITCH from=1 to=2 private_cr3=1 tss_rsp0=1 fx_saved=1"


class ExitEvidenceTests(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(exit_markers_well_formed('\n'.join((EXIT1, SWITCH, EXIT2))))

    def test_missing_exit(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, SWITCH))))

    def test_duplicate_exit(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, EXIT1, SWITCH, EXIT2))))

    def test_missing_handoff(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, EXIT2))))

    def test_extra_handoff(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, SWITCH, SWITCH, EXIT2))))

    def test_trailing_forged_data(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, SWITCH + ' forged=1', EXIT2))))

    def test_truncated_exit(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, SWITCH, 'WOLFOS_RING3_NONYIELD_EXIT pid=2'))))


if __name__ == '__main__':
    unittest.main()
