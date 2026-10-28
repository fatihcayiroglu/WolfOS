#!/usr/bin/env python3
"""Fail closed unless hardware IPIs wake CPU-owned remote job mailboxes."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: ap_remote_work_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ap-remote-work-") as tmp:
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
            print("FAIL: CPU-owned remote mailbox QEMU hardware run timed out")
            if logfile.exists():
                print(logfile.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 not found")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if "WOLFOS_SMP_APS_OK total=4 " not in output:
            print("FAIL: prior AP stack/context/independent boot work missing")
            return 1
        match = re.search(
            r"WOLFOS_REMOTE_WORK_OK cpus=(\d+) aps=(\d+) per_ap=(\d+) "
            r"published=(\d+) sent=(\d+) claims=(\d+) completed=(\d+) "
            r"retired=(\d+) received=(\d+) eois=(\d+) idle=(\d+) "
            r"offline=(\d+) wrong_owner=(\d+) duplicates=(\d+) "
            r"invalid=(\d+) spurious=(\d+) migrated=(\d+) bsp_if=(\d+)",
            output,
        )
        if match is None:
            print("FAIL: missing BSP-to-AP real IPI remote work ownership proof")
            return 1
        got = tuple(map(int, match.groups()))
        expected = (4, 3, 4, 12, 12, 12, 12, 12, 12, 12, 3, 3, 0, 0, 0, 0, 0, 0)
        if got != expected:
            print(f"FAIL: invalid CPU-owned AP job/IRQ/EOI evidence: {got}, wanted {expected}")
            return 1
        for error in (
            "WOLFOS_REMOTE_WORK_ERROR", "WOLFOS_REMOTE_WORK_TEST_FAILED",
            "WOLFOS_AP_IPI_ERROR", "WOLFOS_EXCEPTION_GP",
            "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_DF", "WOLFOS_PANIC",
        ):
            if error in output:
                print(f"FAIL: kernel emitted {error}")
                return 1
        if "WOLFOS_BOOT_OK" not in output or run.returncode != 33:
            print(f"FAIL: kernel did not exit successfully code={run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print(
            "PASS: 4 CPUs, BSP published 12 new jobs to 3 CPU-owned slots, "
            "12 directed real xAPIC IPIs, 12 claims + 12 after-IRQ AP executions, "
            "12 independently checked results/retirements, 12 AP-local EOIs, "
            "0 ownership/duplicate errors, all APs safely parked IF=0"
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
