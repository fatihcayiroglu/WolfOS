#!/usr/bin/env python3
"""Adversarial evidence tests for the isolated four-live Ring3 QEMU gate."""
import unittest

from user_timer_four_live_smoke import (
    ORDERED, evaluate, strict_four_exit_evidence,
    strict_four_hardware_evidence,
)

HARDWARE = (
    "WOLFOS_RING3_FOUR_HARDWARE_OK timer_switches=40 "
    "pid1=10 pid2=10 pid3=10 pid4=10 fair_four_min=8 fair_four_spread=1 "
    "quantum_ticks=2 eligible_irqs=88 voluntary_yields=0 exits=4 "
    "progress_per_pid=16 private_cr3=4 tss_rsp0=4 fx_state=4 executed=4"
)


def exit_row(pid):
    return (f"WOLFOS_RING3_FOUR_EXIT pid={pid} progress=16 "
            "private_cr3=1 rsp0_guarded=1")


def switch_row(src, dst):
    return (f"WOLFOS_RING3_FOUR_EXIT_SWITCH from={src} to={dst} "
            "private_cr3=1 tss_rsp0=1 fx_saved=1")


def complete():
    rows = [
        *ORDERED[:9],
        exit_row(1), switch_row(1, 2),
        exit_row(2), switch_row(2, 3),
        exit_row(3), switch_row(3, 4),
        exit_row(4),
        ORDERED[9], HARDWARE, *ORDERED[10:],
    ]
    # The real descriptor proof carries validated GDT/TR metadata. The
    # fail-closed parser intentionally rejects a bare unadorned stem.
    rows[1] = "WOLFOS_RING_PREP_OK tr=0x18 user_cs=0x33"
    return rows


class FourLiveHardwareEvidenceTests(unittest.TestCase):
    def check(self, rows, code=33):
        return evaluate("\n".join(rows), code)

    def test_accepts_exact_four_live_success(self):
        rows = complete()
        self.assertTrue(self.check(rows))
        self.assertTrue(strict_four_exit_evidence("\n".join(rows)))
        self.assertTrue(strict_four_hardware_evidence("\n".join(rows)))

    def test_lifetime_irq_counts_can_diverge_after_early_exit(self):
        rows = complete()
        unequal = (HARDWARE.replace("timer_switches=40", "timer_switches=3680")
                   .replace("pid1=10 pid2=10 pid3=10 pid4=10",
                            "pid1=894 pid2=926 pid3=930 pid4=930")
                   .replace("fair_four_min=8", "fair_four_min=880")
                   .replace("eligible_irqs=88", "eligible_irqs=7500"))
        rows[rows.index(HARDWARE)] = unequal
        self.assertTrue(self.check(rows),
                        "an EXITED PID cannot keep accruing IRQ decisions")

    def test_exit_code_and_missing_evidence_fail_closed(self):
        rows = complete()
        self.assertFalse(self.check(rows, code=0))
        for target in (ORDERED[3], ORDERED[4], ORDERED[5],
                       ORDERED[8], ORDERED[9], HARDWARE, exit_row(4)):
            self.assertFalse(self.check([r for r in rows if r != target]), target)

    def test_wrong_pid_or_progress_or_exit_order_fails(self):
        for before, after in (
            (exit_row(2), exit_row(1)),
            (exit_row(2), exit_row(2).replace("progress=16", "progress=15")),
            (switch_row(2, 3), switch_row(2, 2)),
            (switch_row(2, 3), switch_row(2, 1)),
            (switch_row(3, 4), switch_row(1, 4)),
        ):
            self.assertFalse(self.check([
                r.replace(before, after) for r in complete()
            ]), after)

    def test_false_hardware_counters_and_claims_fail(self):
        for before, after in (
            ("timer_switches=40", "timer_switches=39"),
            ("pid4=10", "pid4=3"),
            ("pid4=10", "pid4=20"),
            ("fair_four_min=8", "fair_four_min=3"),
            ("fair_four_min=8", "fair_four_min=11"),
            ("fair_four_spread=1", "fair_four_spread=2"),
            ("quantum_ticks=2", "quantum_ticks=1"),
            ("eligible_irqs=88", "eligible_irqs=79"),
            ("eligible_irqs=88", "eligible_irqs=0"),
            ("voluntary_yields=0", "voluntary_yields=1"),
            ("exits=4", "exits=2"),
            ("executed=4", "executed=2"),
            ("private_cr3=4", "private_cr3=2"),
            ("fx_state=4", "fx_state=0"),
        ):
            rows = complete()
            rows[rows.index(HARDWARE)] = HARDWARE.replace(before, after)
            self.assertFalse(self.check(rows), after)

    def test_embedded_duplicate_truncated_and_extra_exit_fail(self):
        rows = complete()
        for extra in (
            "prefix: " + exit_row(1),
            "prefix: " + switch_row(1, 2),
            "prefix: " + HARDWARE,
            HARDWARE,
            exit_row(1),
            switch_row(3, 4),
            "WOLFOS_RING3_FOUR_EXIT pid=3",
        ):
            self.assertFalse(self.check(rows + [extra]), extra)

    def test_no_forged_p3_preflight_or_failure_evidence(self):
        rows = complete()
        for extra in (
            "diagnostic: " + ORDERED[5],
            "WOLFOS_RING3_YIELD_ERROR cannot_switch",
            "WOLFOS_RING3_NONYIELD_HARDWARE_OK timer_switches=40",
            "WOLFOS_PANIC",
        ):
            self.assertFalse(self.check(rows + [extra]), extra)


if __name__ == "__main__":
    unittest.main()
