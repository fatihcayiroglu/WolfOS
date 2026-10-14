#!/usr/bin/env python3
"""Require a quiesced logical continuation to change owners across real AP IPIs.

This explicitly does NOT establish migration of a saved RSP / kernel stack.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: ap_handoff_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ap-handoff-") as tmp:
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
            run = subprocess.run(cmd, capture_output=True, timeout=50, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: Quiesced cross-CPU logical task handoff timed out")
            if logfile.exists():
                print(logfile.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 missing")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if "WOLFOS_SMP_APS_OK total=4 " not in output:
            print("FAIL: prior per-CPU context and stack proof missing")
            return 1
        evidence = re.search(
            r"WOLFOS_AP_HANDOFF_OK cpus=(\d+) aps=(\d+) logical_tasks=(\d+) "
            r"epochs=(\d+) migrations=(\d+) quiesced=(\d+) sent=(\d+) "
            r"received=(\d+) eois=(\d+) claimed=(\d+) executed=(\d+) "
            r"retired=(\d+) stale_denied=(\d+) idle=(\d+) offline=(\d+) "
            r"invalid=(\d+) spurious=(\d+) stack_migrated=(\d+) bsp_if=(\d+)",
            output,
        )
        if evidence is None:
            print("FAIL: no quiesced AP-owned task continuation + real IPI proof")
            return 1
        got = tuple(map(int, evidence.groups()))
        required = (
            4, 3, 1, 12, 11, 12, 12,
            12, 12, 12, 12, 1, 11, 3, 3, 0, 0, 0, 0,
        )
        if got != required:
            print(f"FAIL: invalid quiescence/lease/IPI/EOI state {got}; expected {required}")
            return 1
        for error in (
            "WOLFOS_AP_HANDOFF_ERROR",
            "WOLFOS_AP_HANDOFF_TEST_FAILED",
            "WOLFOS_AP_IPI_ERROR", "WOLFOS_PANIC",
            "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_GP",
            "WOLFOS_EXCEPTION_DF",
        ):
            if error in output:
                print(f"FAIL: unexpected kernel failure: {error}")
                return 1
        if "WOLFOS_BOOT_OK" not in output or run.returncode != 33:
            print(f"FAIL: QEMU boot did not complete exit={run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print(
            "PASS: 4 CPUs, one quiesced logical task and 11 atomic owner handoffs "
            "across 3 APs; 12 checked continuation steps / directed IPI / "
            "local EOI, 11 stale-owner rejections; no suspended stack migrated"
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
