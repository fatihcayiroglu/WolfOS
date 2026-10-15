#!/usr/bin/env python3
"""Actual independent sanitized CR3 and CPU-enforced CPL3 kernel-read denial.

All markers come from *hardware* QEMU execution. This is not a general
process loader; the user code is a fixed trusted test payload.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ENTER = re.compile(
    r"WOLFOS_USER_ISOLATION_ENTER cr3_new=1 cr3_distinct=1 "
    r"high_supervisor=1 user_pages=3 rx=1 rw_nx=2 root_slot=(\d+) nxe=1"
)
FIRST = "WOLFOS_USER_ISOLATION_INT80_FIRST cpl3=1 cpl0=1 rsp0=1 nonce=0x11"
SECOND = "WOLFOS_USER_ISOLATION_INT80_SECOND cpl3=1 cpl0=1 rsp0=1 nonce=0x22"
PF = "WOLFOS_USER_ISOLATION_PF_OK present=1 user=1 read=1 kernel_supervisor=1 cr3_new=1 rsp0=1"
OK = (
    "WOLFOS_USER_ISOLATION_OK cpl3=1 int80=2 iretq_returns=2 "
    "denied_kernel_read=1 sanitized_cr3=1 processes=0"
)

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_ring3_isolation_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-protected-cr3-") as tmp:
        serial = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{serial}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: distinct CR3 CPL3/#PF QEMU test timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 missing")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        entry = ENTER.search(output)
        if not entry or not (1 <= int(entry.group(1)) <= 255):
            print("FAIL: no verified distinct sanitized CR3 entry")
            return 1
        stages = [
            output.find("WOLFOS_BOOT_OK"), entry.start(),
            output.find(FIRST), output.find(SECOND),
            output.find(PF), output.find(OK),
        ]
        if any(p < 0 for p in stages) or stages != sorted(stages):
            print("FAIL: missing/out-of-order Ring3 INT80 IRETQ and privilege #PF")
            return 1
        for marker in [FIRST, SECOND, PF, OK]:
            if output.count(marker) != 1:
                print("FAIL: missing or duplicate unique proof marker " + marker)
                return 1
        for bad in [
            "WOLFOS_USER_ISOLATION_ERROR", "WOLFOS_RING_PREP_ERROR",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
            "WOLFOS_EXCEPTION_DF", "WOLFOS_EXCEPTION_UD", "WOLFOS_PANIC",
        ]:
            if bad in output:
                print("FAIL: unexpected kernel fault or preflight error: " + bad)
                return 1
        if result.returncode != 33:
            print(f"FAIL: expected debug-exit code 33, got {result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: active distinct sanitized CR3; CPL3->INT80->IRETQ twice; CPU denied CPL3 kernel read with #PF")
        return 0

if __name__ == "__main__":
    sys.exit(main())
