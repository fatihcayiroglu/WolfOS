#!/usr/bin/env python3
"""Require genuine AP-local periodic xAPIC hardware IRQs (not BSP IPIs)."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: ap_local_timer_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ap-local-timer-") as tmp:
        serial = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", "4", "-vga", "std",
            "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{serial}",
            "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=50, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: AP-local xAPIC timer smoke timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 missing")
            return 1
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        if "WOLFOS_SMP_APS_OK total=4 " not in output:
            print("FAIL: prerequisite AP boot / private stack and CPU work evidence missing")
            return 1
        pattern = (
            r"WOLFOS_AP_LOCAL_TIMER_OK cpus=(\d+) aps=(\d+) min_per_ap=(\d+) "
            r"ticks=(\d+) eois=(\d+) progress_irqs=(\d+) work=(\d+) "
            r"ready=(\d+) offline=(\d+) invalid=(\d+) spurious=(\d+) "
            r"unexpected_ipi=(\d+) vector=(\d+) bsp_if=(\d+)"
        )
        match = re.search(pattern, output)
        if match is None:
            print("FAIL: AP-local periodic hardware IRQ proof missing")
            return 1
        (cpus, aps, per_ap, ticks, eois, progress, work, ready, offline,
         invalid, spurious, unexpected_ipi, vector, bsp_if) = map(int, match.groups())
        if (cpus != 4 or aps != 3 or per_ap != 4 or ticks < 12
            or eois != ticks or progress < 9 or work <= 0
            or ready != 3 or offline != 3 or invalid != 0
            or spurious != 0 or unexpected_ipi != 0
            or vector != 0xe2 or bsp_if != 0):
            print(f"FAIL: mismatched per-AP hardware timer evidence: {match.groups()}")
            return 1
        if "WOLFOS_AP_IPI_OK" in output:
            print("FAIL: AP local timer flavor unexpectedly used BSP-directed IPIs")
            return 1
        for error in (
            "WOLFOS_AP_LOCAL_TIMER_ERROR",
            "WOLFOS_AP_LOCAL_TIMER_TEST_FAILED",
            "WOLFOS_AP_IPI_ERROR",
            "WOLFOS_EXCEPTION_GP",
            "WOLFOS_EXCEPTION_PF",
            "WOLFOS_EXCEPTION_DF",
            "WOLFOS_PANIC",
        ):
            if error in output:
                print(f"FAIL: kernel emitted {error}")
                return 1
        if "WOLFOS_BOOT_OK" not in output or run.returncode != 33:
            print(f"FAIL: expected successful QEMU shutdown; exit={run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print(
            f"PASS: three secondary CPUs each handled >=4 own periodic APIC timer "
            f"IRQs; delivered={ticks}, EOIs={eois}, post-IRQ work observed, "
            "all APs parked with IF=0"
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
