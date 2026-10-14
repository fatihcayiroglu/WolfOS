#!/usr/bin/env python3
"""Require real xAPIC BSP periodic IRQ+EOI delivery in isolated one-vCPU QEMU."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: apic_timer_smoke.py out/wolfos-apic-timer.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-apic-timer-") as tmp:
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
            print("FAIL: APIC timer QEMU test timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU missing")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        if "WOLFOS_APIC_TIMER_BEGIN vector=224" not in output:
            print("FAIL: APIC timer hardware start marker missing")
            print(run.stderr.decode(errors="replace"))
            return 1
        match = re.search(
            r"WOLFOS_APIC_TIMER_IRQ_OK vector=(\d+) ticks=(\d+) eoi=(\d+) spurious=(\d+) preemptive=(\d+)",
            output,
        )
        if match is None:
            print("FAIL: APIC timer hardware completion marker missing")
            print(run.stderr.decode(errors="replace"))
            return 1
        vector, ticks, eoi, spurious, preemptive = map(int, match.groups())
        if vector != 224 or ticks < 4 or eoi != ticks or preemptive != 0:
            print(f"FAIL: invalid delivery/EOI evidence: {match.groups()}")
            return 1
        if "WOLFOS_BOOT_OK" not in output or run.returncode != 33:
            print(f"FAIL: boot did not finish successfully: exit={run.returncode}")
            return 1
        if any(s in output for s in (
            "WOLFOS_APIC_TIMER_ERROR", "WOLFOS_APIC_TIMER_TEST_FAILED",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF", "WOLFOS_PANIC",
        )):
            print("FAIL: fatal APIC-related kernel diagnostic")
            return 1
        print(
            f"PASS: xAPIC periodic IRQs={ticks}, EOIs={eoi}, spurious={spurious}; "
            "no scheduling or preemption asserted"
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
