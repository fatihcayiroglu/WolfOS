#!/usr/bin/env python3
"""Exercise real BSP-local xAPIC timer IRQ and EOI in 1- and 4-vCPU QEMU."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def exercise(iso: Path, cpus: int) -> bool:
    with tempfile.TemporaryDirectory(prefix=f"wolfos-apic-timer-{cpus}cpu-") as tmp:
        serial = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", str(cpus), "-vga", "std", "-cdrom", str(iso.resolve()),
            "-boot", "d", "-serial", f"file:{serial}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=45, check=False)
        except subprocess.TimeoutExpired:
            print(f"FAIL: APIC timer QEMU test timed out ({cpus} CPUs)")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return False
        except FileNotFoundError:
            print("FAIL: QEMU missing")
            return False
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(f"=== xAPIC hardware smoke ({cpus} CPUs) ===")
        print(output)
        if f"WOLFOS_SMP_APS_OK total={cpus} " not in output:
            print(f"FAIL: {cpus}-CPU SMP completion marker missing")
            print(run.stderr.decode(errors="replace"))
            return False
        if "WOLFOS_APIC_TIMER_BEGIN vector=224" not in output:
            print("FAIL: APIC timer hardware start marker missing")
            print(run.stderr.decode(errors="replace"))
            return False
        match = re.search(
            r"WOLFOS_APIC_TIMER_IRQ_OK vector=(\d+) ticks=(\d+) eoi=(\d+) spurious=(\d+) preemptive=(\d+)",
            output,
        )
        if match is None:
            print("FAIL: APIC timer hardware completion marker missing")
            print(run.stderr.decode(errors="replace"))
            return False
        vector, ticks, eoi, spurious, preemptive = map(int, match.groups())
        if vector != 224 or ticks < 4 or eoi != ticks or preemptive != 0:
            print(f"FAIL: invalid delivery/EOI evidence: {match.groups()}")
            return False
        if "WOLFOS_BOOT_OK" not in output or run.returncode != 33:
            print(f"FAIL: boot did not finish successfully: exit={run.returncode}")
            return False
        if any(s in output for s in (
            "WOLFOS_APIC_TIMER_ERROR", "WOLFOS_APIC_TIMER_TEST_FAILED",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF", "WOLFOS_PANIC",
        )):
            print("FAIL: fatal APIC-related kernel diagnostic")
            return False
        print(
            f"PASS: {cpus} CPUs; BSP xAPIC IRQs={ticks}, EOIs={eoi}, "
            f"spurious={spurious}; no preemption asserted"
        )
        return True


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: apic_timer_smoke.py out/wolfos-apic-timer.iso")
        return 2
    iso = Path(sys.argv[1])
    for cpus in (1, 4):
        if not exercise(iso, cpus):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
