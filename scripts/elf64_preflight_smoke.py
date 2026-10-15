#!/usr/bin/env python3
"""P2 ELF64 preflight integration smoke: kernel validates, never executes."""
from pathlib import Path
import subprocess
import sys
import tempfile

MARKER = (
    "WOLFOS_ELF64_PREFLIGHT_OK entry=0x401100 loads=1 pages=1 "
    "wx_rejected=1 truncated_rejected=1 kernel_entry_rejected=1 "
    "executed=0 ring3=0"
)

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: elf64_preflight_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-elf64-") as tmp:
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
            print("FAIL: ELF64 preflight QEMU did not complete")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 is missing")
            return 1
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        if MARKER not in output or "WOLFOS_BOOT_OK" not in output:
            print("FAIL: incomplete P2 preflight proof or previous kernel boot")
            return 1
        for bad in (
            "WOLFOS_ELF64_PREFLIGHT_ERROR", "WOLFOS_ELF64_PREFLIGHT_TEST_FAILED",
            "WOLFOS_PANIC", "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
            "WOLFOS_EXCEPTION_DF",
        ):
            if bad in output:
                print(f"FAIL: kernel emitted {bad}")
                return 1
        if run.returncode != 33:
            print(f"FAIL: expected clean QEMU debug-exit 33, got {run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: boot-time ET_EXEC plan, strict rejection, no Ring 3 execution")
        return 0

if __name__ == "__main__":
    sys.exit(main())
