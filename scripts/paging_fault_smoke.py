#!/usr/bin/env python3
"""QEMU: map/unmap a page, then fault on the unmapped virtual address."""
from pathlib import Path
import subprocess
import sys
import tempfile

MARKERS = (
    "WOLFOS_GDT_OK",
    "WOLFOS_IDT_OK",
    "WOLFOS_PMM_DYNAMIC_OK",
    "WOLFOS_PAGING_MAP_OK",
    "WOLFOS_PAGING_UNMAP_OK",
    "WOLFOS_PAGING_FAULT_TEST_BEGIN",
    "WOLFOS_EXCEPTION_PF vector=14",
    "WOLFOS_PAGING_FAULT_OK",
)

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: paging_fault_smoke.py out/wolfos-paging-fault.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-paging-fault-") as tmp:
        log = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{log}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=45, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: paging QEMU test timed out")
            if log.exists():
                print(log.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU missing")
            return 2
        output = log.read_text(errors="replace") if log.exists() else ""
        print(output)
        missing = [mark for mark in MARKERS if mark not in output]
        if missing or run.returncode != 33:
            print(f"FAIL: missing={missing}; qemu_return={run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        if "WOLFOS_PAGING_FAULT_TEST_FAILED" in output:
            print("FAIL: page fault did not trigger")
            return 1
        print("PASS: map/read/write/unmap and deliberate #PF on unmapped page")
        return 0

if __name__ == "__main__":
    sys.exit(main())
