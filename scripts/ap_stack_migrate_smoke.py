#!/usr/bin/env python3
"""Require ONE saved kernel RSP/FX image to genuinely resume across APs.

This is a cooperative suspend-at-ABI-boundary proof, not IRQ-time migration.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: ap_stack_migrate_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ap-stack-migrate-") as tmp:
        logfile = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", "4", "-vga", "std", "-cdrom",
            str(Path(sys.argv[1]).resolve()), "-boot", "d",
            "-serial", f"file:{logfile}", "-display", "none",
            "-no-reboot", "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: real suspended-RSP cross-AP migration timed out")
            if logfile.exists():
                print(logfile.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 missing")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if "WOLFOS_SMP_APS_OK total=4 " not in output:
            print("FAIL: prerequisite SMP stack / context proof missing")
            return 1
        proof = re.search(
            r"WOLFOS_AP_STACK_MIGRATE_OK cpus=(\d+) aps=(\d+) "
            r"starts=(\d+) resumes=(\d+) cross_ap_resumes=(\d+) "
            r"transfers=(\d+) quanta=(\d+) sent=(\d+) received=(\d+) "
            r"eois=(\d+) claims=(\d+) finished=(\d+) stale_denied=(\d+) "
            r"fx_checked=(\d+) canary=(\d+) irq_preempted=(\d+) "
            r"stack_copied=(\d+) invalid=(\d+) spurious=(\d+) "
            r"offline=(\d+) bsp_if=(\d+)",
            output,
        )
        if proof is None:
            print("FAIL: missing hardware-proven identical task stack, RSP and SSE restoration")
            return 1
        got = tuple(map(int, proof.groups()))
        expected = (
            4, 3, 1, 12, 11, 11, 12,
            12, 12, 12, 12, 12, 11, 12,
            1, 0, 0, 0, 0, 3, 0,
        )
        if got != expected:
            print(f"FAIL: unexpected suspended task/FX/IRQ evidence {got}, wanted {expected}")
            return 1
        for marker in (
            "WOLFOS_AP_STACK_MIGRATE_ERROR",
            "WOLFOS_AP_STACK_MIGRATE_TEST_FAILED",
            "WOLFOS_AP_IPI_ERROR", "WOLFOS_EXCEPTION_GP",
            "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_DF", "WOLFOS_PANIC",
        ):
            if marker in output:
                print(f"FAIL: {marker} observed")
                return 1
        if "WOLFOS_BOOT_OK" not in output or result.returncode != 33:
            print(f"FAIL: QEMU did not exit cleanly code={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print(
            "PASS: same Rust kernel task entry and 16-KiB stack resumed "
            "12 times across 3 APs with 11 real cross-core saved-RSP/FX "
            "continuations, 12 directed IPIs + local EOIs, 0 double-running "
            "or invalid stack canaries. Cooperative quiescence only."
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
