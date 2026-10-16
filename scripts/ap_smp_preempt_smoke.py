#!/usr/bin/env python3
"""Proof of three independent two-worker local timer preemptive AP schedulers.

No producer-supplied outcome is trusted: a valid QEMU boot plus detailed
aggregate IRQ/EOI/switch and per-AP lifecycle markers are mandatory.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


AGGREGATE_PATTERN = (
            r"WOLFOS_AP_SMP_PREEMPT_OK cpus=(\d+) aps=(\d+) tasks_per_ap=(\d+) "
            r"switches=(\d+) task0_irqs=(\d+) task1_irqs=(\d+) "
            r"ticks=(\d+) eois=(\d+) work=(\d+) invalid=(\d+) "
            r"xmm_bad=(\d+) spurious=(\d+) wrong_ipi=(\d+) offline=(\d+) "
            r"bsp_if=(\d+) migrated=(\d+) deferred=(\d+) nested_aps=(\d+) guard_depth=(\d+)"
        )


def unique_aggregate_proof(output: str):
    """Return one complete AP aggregate record, never a substring or duplicate."""
    matches = []
    for line in output.splitlines():
        # Any appearance of the success token must be a complete, valid record.
        # Reject malformed duplicates even when another record is genuine.
        if "WOLFOS_AP_SMP_PREEMPT_OK" not in line:
            continue
        match = re.fullmatch(AGGREGATE_PATTERN, line)
        if match is None:
            return None
        matches.append(match)
    return matches[0] if len(matches) == 1 else None


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: ap_smp_preempt_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ap-smp-preempt-") as tmp:
        logfile = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", "4", "-vga", "std", "-cdrom",
            str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{logfile}",
            "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            process = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: AP SMP preemption QEMU smoke timed out")
            if logfile.exists():
                print(logfile.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 is unavailable")
            return 1

        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if sum(line.startswith("WOLFOS_SMP_APS_OK total=4 ") for line in output.splitlines()) != 1:
            print("FAIL: prerequisite 4-vCPU SMP/CPU context tests not complete")
            return 1
        proof = unique_aggregate_proof(output)
        if proof is None:
            print("FAIL: expected exactly one full-line AP SMP proof")
            return 1
        (cpus, aps, tasks, switches, a, b, ticks, eois,
         work, invalid, xmm_bad, spurious, wrong_ipi,
         offline, bsp_if, migrated, deferred, nested_aps,
         guard_depth) = map(int, proof.groups())
        if (cpus != 4 or aps != 3 or tasks != 2 or switches < 30
            or a < 15 or b < 15 or a + b != switches
            or ticks < switches or ticks != eois or work == 0
            or invalid or xmm_bad or spurious or wrong_ipi
            or offline != 3 or bsp_if != 0 or migrated != 0
            or deferred < 12 or nested_aps != 3 or guard_depth != 0
            or ticks < switches + deferred):
            print(f"FAIL: invalid independent per-AP IRQ/task/x87-SSE evidence: {proof.groups()}")
            return 1

        if "WOLFOS_AP_LOCAL_TIMER_OK" in output or "WOLFOS_AP_IPI_OK" in output:
            print("FAIL: wrong flavor claims unrelated directed-IPI or no-preempt timer proof")
            return 1
        for error in (
            "WOLFOS_AP_SMP_PREEMPT_ERROR", "WOLFOS_AP_SMP_PREEMPT_TEST_FAILED",
            "WOLFOS_AP_IPI_ERROR", "WOLFOS_PANIC",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
            "WOLFOS_EXCEPTION_DF",
        ):
            if error in output:
                print(f"FAIL: {error} observed")
                return 1
        if "WOLFOS_BOOT_OK" not in output or process.returncode != 33:
            print(f"FAIL: kernel did not exit cleanly; return={process.returncode}")
            print(process.stderr.decode(errors="replace"))
            return 1
        print(
            f"PASS: 3 independent APs with 2 private kernel tasks each; "
            f"{switches} real timer-IRQ involuntary task switches, "
            f"{ticks} AP-local IRQs/{eois} EOIs, {deferred} deferrals across "
            "nested critical sections, no x87/SSE corruption, "
            "all APs parked IF=0, BSP remained unpreempted"
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
