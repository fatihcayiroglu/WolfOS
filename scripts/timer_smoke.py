#!/usr/bin/env python3
"""Hardware timer IRQ0 delivery test, isolated single-vCPU QEMU."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: timer_smoke.py out/wolfos-timer.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-timer-") as tmp:
        serial = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", "1", "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{serial}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=45, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: hardware timer QEMU test timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU missing")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        match = re.search(r"WOLFOS_TIMER_IRQ_OK vector=(\d+) hz=(\d+) ticks=(\d+)", output)
        if not match:
            print("FAIL: expected PIT interrupt milestone missing")
            print(run.stderr.decode(errors="replace"))
            return 1
        vector, hz, ticks = map(int, match.groups())
        if (vector, hz) != (32, 100) or ticks < 8:
            print(f"FAIL: timer configuration/ticks invalid {(vector, hz, ticks)}")
            return 1
        tasks = re.search(
            r"WOLFOS_TIMER_TASKS_OK threads=(\d+) dispatches=(\d+) switches=(\d+) stack_kib=(\d+) gated_by_irq=(\d+) preemptive=(\d+)",
            output,
        )
        if tasks is None or tuple(map(int, tasks.groups())) != (2, 6, 12, 16, 1, 0):
            print("FAIL: two real saved Rust contexts did not dispatch on later hardware ticks")
            return 1
        if run.returncode != 33 or "WOLFOS_BOOT_OK" not in output:
            print(f"FAIL: kernel did not finish; QEMU exit={run.returncode}")
            return 1
        if "WOLFOS_TIMER_ERROR" in output or "WOLFOS_EXCEPTION_GP" in output:
            print("FAIL: timer caused fatal exception")
            return 1
        print("PASS: PIT IRQ0 tick-gated two cooperative Rust contexts; preemption is NOT claimed")
        return 0

if __name__ == "__main__":
    sys.exit(main())
