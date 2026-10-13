#!/usr/bin/env python3
"""Boot four QEMU vCPUs and verify ACPI MADT topology, not CPU scheduling."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

EXPECTED_CPUS = 4

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: topology_smoke.py out/wolfos-smoke.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-topology-") as temp:
        log = Path(temp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", "4,sockets=1,cores=4,threads=1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{log}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=45, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: 4-vCPU topology QEMU boot timed out")
            if log.exists():
                print(log.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU missing")
            return 2
        output = log.read_text(errors="replace") if log.exists() else ""
        print(output)
        match = re.search(r"WOLFOS_ACPI_MADT_OK enabled_cpus=(\d+) lapic=(\d+) x2apic=(\d+)", output)
        if not match:
            print("FAIL: missing ACPI MADT summary")
            return 1
        total, lapic, x2apic = map(int, match.groups())
        if (total, lapic+x2apic) != (EXPECTED_CPUS, EXPECTED_CPUS):
            print(f"FAIL: expected four enabled CPUs, MADT reported {total}")
            return 1
        if "WOLFOS_BOOT_OK" not in output or run.returncode != 33:
            print(f"FAIL: kernel not fully booted, QEMU exit={run.returncode}")
            return 1
        print("PASS: ACPI MADT discovered 4 enabled logical CPUs; SMP startup NOT tested")
        return 0

if __name__ == "__main__":
    sys.exit(main())
