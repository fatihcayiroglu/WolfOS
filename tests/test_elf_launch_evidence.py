"""Reject incomplete hardware observations; synthetic rows are parser tests only."""
import unittest

from scripts.elf_launch_evidence import (
    RELAUNCH_STACK_PROOF, transaction_rows, valid_launch_transactions,
)


def transcript(frames=7, pids=(1,)):
    rows = ["WOLFOS_BOOT_OK"]
    for pid in pids:
        rollback, active, blocked, reclaim = transaction_rows(pid, frames)
        rows += [rollback]
        if pid == 2:
            rows += [RELAUNCH_STACK_PROOF]
        rows += [active, "WOLFOS_ELF_RUN_ENTER elf64=1",
                 "GUEST_EXIT_OR_AUTHENTICATED_FAULT", blocked, reclaim,
                 f"WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed={frames} pmm_no_leak=1"]
    return "\n".join(rows)


class ElfLaunchEvidenceTests(unittest.TestCase):
    def test_four_exact_budgets_and_sequential_generations(self):
        for frames in (6, 7, 8, 9):
            for pids in ((1,), (1, 2)):
                self.assertTrue(valid_launch_transactions(transcript(frames, pids), frames, pids))
                self.assertFalse(valid_launch_transactions(transcript(frames, pids), 15 - frames, pids))
        self.assertFalse(valid_launch_transactions(transcript(), 7, (2,)))
        self.assertFalse(valid_launch_transactions(transcript(), 7, ()))

    def test_each_row_is_required_exactly_once_and_undecorated(self):
        output = transcript()
        for row in transaction_rows(1, 7):
            for bad in ("", "prefix " + row, row + " extra=1", row + "\n" + row):
                self.assertFalse(valid_launch_transactions(output.replace(row, bad), 7, (1,)))
        self.assertFalse(valid_launch_transactions(output + "\nWOLFOS_ELF_TX_FORGED_OK", 7, (1,)))

    def test_every_safety_field_and_exact_pid_are_required(self):
        output = transcript()
        fields = ["rejected", "bytes_unchanged", "pid_unpublished", "pmm_no_leak",
                  "transferred_before_cr3", "cpu_reserved", "actual_cr3", "full_bytes",
                  "pcid_off", "bsp_only", "cpu_outstanding", "active_ack_denied",
                  "frames_pinned", "actual_boot_cr3", "cpu_drained", "pid_revoked",
                  "returns_revoked"]
        for field in fields:
            self.assertFalse(valid_launch_transactions(output.replace(field + "=1", field + "=0"), 7, (1,)), field)
        self.assertFalse(valid_launch_transactions(output.replace("failed=0", "failed=1"), 7, (1,)))
        self.assertFalse(valid_launch_transactions(output.replace("pid=1", "pid=2"), 7, (1,)))

    def test_entry_reclamation_cleanup_and_next_generation_are_ordered(self):
        rows = transcript(pids=(1, 2)).splitlines()
        for a, b in [(0, 1), (1, 2), (2, 3), (3, 5), (5, 6), (6, 7), (7, 8)]:
            changed = rows.copy()
            changed[a], changed[b] = changed[b], changed[a]
            self.assertFalse(valid_launch_transactions("\n".join(changed), 7, (1, 2)), (a, b))

    def test_guest_entry_and_exact_cleanup_cannot_be_omitted_or_duplicated(self):
        output = transcript()
        for row in ["WOLFOS_BOOT_OK", "WOLFOS_ELF_RUN_ENTER elf64=1",
                    "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1"]:
            self.assertFalse(valid_launch_transactions(output.replace(row, ""), 7, (1,)))
        for row in ["WOLFOS_ELF_RUN_ENTER elf64=1",
                    "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1"]:
            self.assertFalse(valid_launch_transactions(output + "\n" + row, 7, (1,)))

    def test_relaunch_requires_a_separate_checked_preparation_stack(self):
        output = transcript(pids=(1, 2))
        for bad in ("", "prefix " + RELAUNCH_STACK_PROOF,
                    RELAUNCH_STACK_PROOF + "\n" + RELAUNCH_STACK_PROOF,
                    RELAUNCH_STACK_PROOF.replace("canary=1", "canary=0"),
                    RELAUNCH_STACK_PROOF.replace("rsp0_stack_kib=16", "rsp0_stack_kib=64")):
            self.assertFalse(valid_launch_transactions(output.replace(RELAUNCH_STACK_PROOF, bad), 7, (1, 2)))
        late = output.replace(RELAUNCH_STACK_PROOF, "") + "\n" + RELAUNCH_STACK_PROOF
        self.assertFalse(valid_launch_transactions(late, 7, (1, 2)))
