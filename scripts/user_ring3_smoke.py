#!/usr/bin/env python3
"""First WolfOS *actual hardware* CPL3 -> kernel -> CPL3 -> kernel proof.

Hardcoded two-trap user payload only, boot CR3, NO process isolation yet.
A successful first INT80 alone is NOT enough: insist on two distinct traps,
second user-side nonce, real TSS.RSP0 stack switch and QEMU exit=33.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ENTRY = re.compile(
    r"WOLFOS_RING3_ENTER root_slot=(\d+) user_pages=3 rx=1 rw_nx=2 "
    r"rsp0=1 nxe=1 if=0"
)
FIRST = "WOLFOS_RING3_INT80_FIRST from_cpl=3 kernel_cpl=0 rsp0_switch=1 nonce=0x11"
SECOND = "WOLFOS_RING3_INT80_SECOND from_cpl=3 kernel_cpl=0 rsp0_switch=1 nonce=0x22"
SUCCESS = (
    "WOLFOS_RING3_OK cpl3_executed=1 kernel_entries=2 "
    "user_iret_return=1 rsp0_switch=1 user_rw=1 user_rx=1 nxe=1 processes=0"
)

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_ring3_smoke.py path/to/wolfos-user-ring3.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-real-ring3-") as tmp:
        serial = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", "1", "-vga", "std",
            "-cdrom", str(Path(sys.argv[1]).resolve()), "-boot", "d",
            "-serial", f"file:{serial}", "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: hardware CPL3->CPL0 roundtrip timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 missing")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        entry = ENTRY.search(output)
        if not entry or not 1 <= int(entry.group(1)) <= 255:
            print("FAIL: no verified lower-half user root and NXE admission")
            return 1
        ordered = [output.find(token) for token in (
            "WOLFOS_BOOT_OK", ENTRY.pattern.split(" root_slot=")[0],
            FIRST, SECOND, SUCCESS
        )]
        # Re-express the ENTRY check with the actual match offset: no
        # substring assumptions about regex syntax.
        ordered[1] = entry.start()
        if any(index < 0 for index in ordered) or ordered != sorted(ordered):
            print("FAIL: missing or out-of-order actual user/kernel transitions")
            return 1
        for marker in (FIRST, SECOND, SUCCESS):
            if output.count(marker) != 1:
                print(f"FAIL: marker missing or duplicated: {marker}")
                return 1
        for bad in (
            "WOLFOS_RING3_ERROR", "WOLFOS_RING_PREP_ERROR",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
            "WOLFOS_EXCEPTION_DF", "WOLFOS_EXCEPTION_UD", "WOLFOS_PANIC",
        ):
            if bad in output:
                print(f"FAIL: kernel fault or failed preflight: {bad}")
                return 1
        if run.returncode != 33:
            print(f"FAIL: expected clean QEMU debug exit code 33; got {run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: two REAL CPL3 INT0x80 entries with intervening IRETQ user return; no process isolation")
        return 0

if __name__ == "__main__":
    sys.exit(main())
