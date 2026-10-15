#!/usr/bin/env python3
"""BSP QEMU preflight of PID-bound user trap snapshots and private stack plans.

There are NO actual user switches in this smoke. Existing genuine Ring3
tests are separately mandatory and prove the hardware path independently.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

PROOFS = [
    "WOLFOS_BOOT_OK",
    "WOLFOS_USER_CONTEXT_READY_OK pids=2 frames=14 independent_rsp0=2 stored_gprs=15",
    "WOLFOS_USER_CONTEXT_PLAN_OK alternations=64 frames_independent=1 active_user_cr3_denied=1 actual_switches=0",
    "WOLFOS_USER_CONTEXT_CLEANUP_OK released=14 no_pmm_leak=1 boot_cr3_intact=1 users_executed=0",
]
FORBIDDEN = [
    "WOLFOS_USER_CONTEXT_ERROR", "WOLFOS_PANIC", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_DF", "WOLFOS_EXCEPTION_UD",
]

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_context_smoke.py path/to/ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-user-context-") as tmp:
        log = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{log}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: user context planning QEMU timed out")
            if log.exists(): print(log.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU missing")
            return 2
        output = log.read_text(errors="replace") if log.exists() else ""
        print(output)
        positions = [output.find(marker) for marker in PROOFS]
        if any(p < 0 for p in positions) or positions != sorted(positions):
            print("FAIL: context proof markers absent or out of order")
            return 1
        if any(output.count(marker) != 1 for marker in PROOFS):
            print("FAIL: duplicate context markers")
            return 1
        if any(marker in output for marker in FORBIDDEN):
            print("FAIL: kernel fault or context accounting failure")
            return 1
        if run.returncode != 33:
            print("FAIL: expected debug-exit 33, got", run.returncode)
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: two private 7-frame PMM roots, disjoint kernel RSP0 and 64 verified frame plans (no actual CPL3 handoff)")
        return 0

if __name__ == "__main__":
    sys.exit(main())
