#!/usr/bin/env python3
"""Fail-closed physical QEMU evidence for genuine Ring3 WAIT→SIGNAL→IRET.

Two separate ELF64 CPL3 processes, distinct PMM-backed CR3 and guarded RSP0,
and real FXSAVE64/FXRSTOR64 cross-task handoffs. The WAIT is a genuine INT80
trap, SIGNAL is a second process's genuine INT80, and PID1 returns to the
original saved WAIT IRET frame before EXIT. This IF=0 test never claims an IRQ.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

START = (
    "WOLFOS_RING3_YIELD_START_OK separate_native_elf=2 live_user_roots=2 "
    "guarded_kernel_rsp0=2 fx_images=2 owned_frames=25"
)
HARDWARE = (
    "WOLFOS_RING3_EVENT_HARDWARE_OK user_wait=1 rejected_signal=1 "
    "trusted_signal=1 resumed_wait=1 exits=2 traps=5 timer_switches=0 real_int80_iret=1 "
    "independent_cr3=2 rsp0=2 fx=2"
)
CLEANUP = (
    "WOLFOS_RING3_EVENT_CLEANUP_OK frames_freed=25 wait_ticket_drained=1 "
    "fx_wiped=2 tss_restored=1 cr3_restored=1 pmm_no_leak=1"
)
RESUME = (
    "WOLFOS_RING3_EVENT_RESUME_OK pid=1 wait_return=0 saved_gprs=1 "
    "fx_state=1 real_iret=1"
)
REJECTED = (
    "WOLFOS_RING3_EVENT_REJECTED_OK wrong_event=78 pid1_still_blocked=1 "
    "queue_unchanged=1 saved_iret=1 no_fake_irq=1"
)
TRAPS = [
    f"WOLFOS_RING3_EVENT_TRAP pid={pid} kind={kind} count=1 "
    "cr3_private=1 rsp0_guarded=1"
    for pid, kind in [(1, "wait"), (2, "signal_rejected"), (2, "signal"),
                      (1, "exit"), (2, "exit")]
]
SWITCHES = [
    f"WOLFOS_RING3_EVENT_SWITCH from={a} to={b} "
    "private_cr3=1 tss_rsp0=1 fx_saved=1"
    for a, b in [(1, 2), (2, 1), (1, 2)]
]
FAILURES = (
    "WOLFOS_RING3_YIELD_ERROR", "WOLFOS_PANIC", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_UD", "WOLFOS_EXCEPTION_DF",
)
DISALLOWED = (
    "WOLFOS_RING3_TIMER_HARDWARE_OK", "WOLFOS_RING3_FOUR_HARDWARE_OK",
    "WOLFOS_RING3_TIMER_ARMED_OK", "WOLFOS_RING3_IRQ_READY_OK",
    "WOLFOS_RING3_YIELD_HARDWARE_OK",  # cannot mislabel WAIT as 8 yields
)


def evaluate(output: str, code: int) -> bool:
    if code != 33 or any(marker in output for marker in FAILURES + DISALLOWED):
        return False
    rows = output.splitlines()
    expected_order = [
        "WOLFOS_BOOT_OK",
        START,
        TRAPS[0], SWITCHES[0], TRAPS[1], REJECTED, TRAPS[2],
        SWITCHES[1], TRAPS[3], RESUME, SWITCHES[2], TRAPS[4], HARDWARE,
        CLEANUP,
    ]
    # Full-line, once-only evidence: no substring, duplicate or reordering
    # may pass. In particular, PID1 must resume and genuinely EXIT before
    # the signaller PID2 can finish its own interrupted syscall.
    # The hardware sequence legitimately switches PID1→PID2 twice: once
    # at WAIT, again after PID1 exits. Demand the EXACT expected multiplicity
    # of every marker, then match each occurrence in order. A simple count=1
    # check would incorrectly reject this genuine three-handoff sequence.
    from collections import Counter
    expected_counts = Counter(expected_order)
    # Reject forged, truncated, embedded or suffixed evidence even when a
    # genuine complete record exists. Count-only validation misses these
    # extra lines because it counts exact strings, not marker stems.
    marker_stems = {line.split(" ", 1)[0] for line in expected_order}
    if any(
        any(stem in row for stem in marker_stems)
        and row not in expected_counts
        for row in rows
    ):
        return False
    for line, required in expected_counts.items():
        if rows.count(line) != required:
            return False
    after = 0
    for line in expected_order:
        try:
            index = rows.index(line, after)
        except ValueError:
            return False
        after = index + 1
    traps = [row for row in rows if row.startswith("WOLFOS_RING3_EVENT_TRAP ")]
    switches = [row for row in rows if row.startswith("WOLFOS_RING3_EVENT_SWITCH ")]
    return traps == TRAPS and switches == SWITCHES


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_event_wait_smoke.py KERNEL_ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ring3-event-wait-") as temp:
        log = Path(temp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-boot", "d", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-serial", f"file:{log}", "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=70, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: actual Ring3 WAIT/SIGNAL/RESUME QEMU timeout")
            if log.exists():
                print(log.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 unavailable")
            return 2
        output = log.read_text(errors="replace") if log.exists() else ""
        print(output)
        if not evaluate(output, proc.returncode):
            print("FAIL: missing/forged real CPL3 WAIT/SIGNAL/IRET, FX or cleanup"
                  f" proof (exit={proc.returncode})")
            print(proc.stderr.decode(errors="replace"))
            return 1
        print("PASS: two actual CPL3 ELFs, wrong CPL3 SIGNAL rejected without wake, "
              "then WAIT→trusted SIGNAL→original saved "
              "IRET, three private-CR3/RSP0/FX handoffs, two exits and "
              "exact zero-leak PMM teardown; no timer IRQ credited")
        return 0


if __name__ == "__main__":
    sys.exit(main())
