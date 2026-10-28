#!/usr/bin/env python3
"""In QEMU, inject #UD with UD2 and require the Rust IDT handler to run."""
from pathlib import Path
import subprocess
import sys
import tempfile

MARKERS = (
    "WOLFOS: Rust kernel entered",
    "WOLFOS_GDT_OK",
    "WOLFOS_IDT_OK",
    "WOLFOS_EXCEPTION_BP vector=3",
    "WOLFOS_BREAKPOINT_RETURN_OK",
    "WOLFOS_EXCEPTION_TEST_BEGIN vector=6",
    "WOLFOS_EXCEPTION_UD vector=6",
)

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: exception_smoke.py out/wolfos-exception.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-exceptions-") as tmp:
        log = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-cdrom", str(Path(sys.argv[1]).resolve()), "-boot", "d",
            "-serial", f"file:{log}", "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=45, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: exception test timed out (possible triple fault / lockup)")
            if log.exists():
                print(log.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU is missing")
            return 2
        output = log.read_text(errors="replace") if log.exists() else ""
        print(output)
        missing = [marker for marker in MARKERS if marker not in output]
        if missing or run.returncode != 33:
            print(f"FAIL: missing={missing}, QEMU exit={run.returncode}, expected=33")
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: #BP returned through IRETQ, #UD dispatched through WolfOS IDT")
        return 0

if __name__ == "__main__":
    sys.exit(main())
