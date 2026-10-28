#!/usr/bin/env python3
"""QEMU real PMM-backed kernel stack leases, NOT a live stack switch."""
from pathlib import Path
import subprocess
import sys
import tempfile

MARKERS = [
    "WOLFOS_BOOT_OK",
    "WOLFOS_KSTACK_LEASE_READY_OK pids=2 real_pmm_frames=22 stack_pages=8 independent_rsp0=2 redzone=canary",
    "WOLFOS_KSTACK_LEASE_PLAN_OK alternations=64 cpl3_switches=0 root_aliases=0",
    "WOLFOS_KSTACK_LEASE_CLEANUP_OK frames_freed=22 pmm_leak=0 boot_cr3_restored=1 guard_page=0 user_tasks_switched=0",
]
BAD = [
    "WOLFOS_KSTACK_LEASE_ERROR", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_DF", "WOLFOS_PANIC",
]
def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: kernel_stack_lease_smoke.py path/to/ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-kstack-") as tmp:
        serial = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{serial}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: kernel stack lease QEMU timed out")
            if serial.exists(): print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU unavailable")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        positions = [output.find(marker) for marker in MARKERS]
        if any(x < 0 for x in positions) or positions != sorted(positions):
            print("FAIL: missing or out-of-order lease proofs")
            return 1
        if any(output.count(marker) != 1 for marker in MARKERS):
            print("FAIL: duplicate stack proof")
            return 1
        if any(b in output for b in BAD):
            print("FAIL: fault or rejected lease")
            return 1
        if run.returncode != 33:
            print("FAIL: QEMU debug exit expected 33, got", run.returncode)
            return 1
        print("PASS: 2 actual 16KiB PMM-backed contiguous HHDM stack leases and exact 22-frame cleanup; no real task switch")
        return 0

if __name__ == "__main__":
    sys.exit(main())
