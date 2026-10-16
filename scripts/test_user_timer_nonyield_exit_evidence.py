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

    def test_two_exits_with_same_pid(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, SWITCH, EXIT1))))

    def test_self_handoff(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, SWITCH.replace('to=2', 'to=1'), EXIT2))))

    def test_reverse_direction_is_valid_when_exit_order_reversed(self):
        reverse = SWITCH.replace('from=1 to=2', 'from=2 to=1')
        self.assertTrue(exit_markers_well_formed('\n'.join((EXIT2, reverse, EXIT1))))

    def test_wrong_handoff_direction(self):
        reverse = SWITCH.replace('from=1 to=2', 'from=2 to=1')
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, reverse, EXIT2))))

    def test_handoff_before_first_exit(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((SWITCH, EXIT1, EXIT2))))

    def test_handoff_after_last_exit(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, EXIT2, SWITCH))))

    def test_missing_handoff(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, EXIT2))))

    def test_extra_handoff(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, SWITCH, SWITCH, EXIT2))))

    def test_trailing_forged_data(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, SWITCH + ' forged=1', EXIT2))))

    def test_truncated_exit(self):
        self.assertFalse(exit_markers_well_formed('\n'.join((EXIT1, SWITCH, 'WOLFOS_RING3_NONYIELD_EXIT pid=2'))))


    def test_exit_marker_without_delimiter_is_rejected(self):
        malformed = "WOLFOS_RING3_NONYIELD_EXIT"
        self.assertFalse(exit_markers_well_formed('\n'.join(
            (EXIT1, SWITCH, EXIT2, malformed))))

    def test_exit_marker_tab_delimiter_is_rejected(self):
        malformed = EXIT1.replace("EXIT pid=", "EXIT" + chr(9) + "pid=")
        self.assertFalse(exit_markers_well_formed('\n'.join(
            (EXIT1, SWITCH, EXIT2, malformed))))

    def test_exit_marker_unknown_suffix_is_rejected(self):
        malformed = "WOLFOS_RING3_NONYIELD_EXIT_FORGED pid=1"
        self.assertFalse(exit_markers_well_formed('\n'.join(
            (EXIT1, SWITCH, EXIT2, malformed))))

    def test_handoff_marker_without_delimiter_is_rejected(self):
        malformed = "WOLFOS_RING3_NONYIELD_EXIT_SWITCH"
        self.assertFalse(exit_markers_well_formed('\n'.join(
            (EXIT1, SWITCH, EXIT2, malformed))))

    def test_handoff_marker_tab_delimiter_is_rejected(self):
        malformed = SWITCH.replace("SWITCH from=", "SWITCH" + chr(9) + "from=")
        self.assertFalse(exit_markers_well_formed('\n'.join(
            (EXIT1, SWITCH, EXIT2, malformed))))


if __name__ == '__main__':
    unittest.main()
