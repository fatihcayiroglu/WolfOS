#!/usr/bin/env python3
"""Actual independently linked ELF64 -> hardware CPL3 -> WolfOS PUTC -> EXIT.

Fail-closed QEMU admission: real ELF64 loader and BSS, supervisor-only new
CR3, genuine serial message from USER CODE via 19 INT80 calls, two register
result returns, EXIT(0), restored boot CR3, all seven PMM frames reclaimed.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ENTER = re.compile(
    r"WOLFOS_ELF_RUN_ENTER elf64=1 et_exec=1 pt_load=2 rx=1 rw_nx=2 "
    r"bss_zero=1 cr3_new=1 root_slot=(\d+) user_entry=0x401000"
)
MARKERS = (
    "WOLFOS_ELF_ID_OK cpl3=1 return_rax=0x574f4c46",
    "WOLFOS_ELF_ADD_OK cpl3=1 return_rax=42",
    "Hello from WolfOS!\n",
    "WOLFOS_ELF_HELLO_OK bytes=19 syscall_iretq=19",
    "WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=22",
    "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1",
    "WOLFOS_ELF_RUN_OK linked_elf=1 hardware_cpl3=1 user_console=1 "
    "int80_calls=22 exit=0 resources_released=1 real_process_manager=0",
)

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_elf_run_smoke.py path/to/wolfos-user-elf-run.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-real-elf-run-") as tmp:
        serial = Path(tmp) / "serial.log"
        command = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{serial}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(command, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: real ELF64 hardware CPL3 or cleanup timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 unavailable")
            return 2
        # Path.read_text() uses universal newline conversion: COM1 CRLF is
        # correctly presented as LF. Still insist on ONE complete line.
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        entry = ENTER.search(output)
        if not entry or not 1 <= int(entry.group(1)) <= 255:
            print("FAIL: genuine ELF64 independent sanitized CR3 entry missing")
            return 1
        positions = [output.find("WOLFOS_BOOT_OK"), entry.start()]
        positions += [output.find(m) for m in MARKERS]
        if any(i < 0 for i in positions) or positions != sorted(positions):
            print("FAIL: ELF64 ELF/PT_LOAD/IRet/Hello/Exit/CR3 cleanup order wrong")
            return 1
        for marker in MARKERS:
            if output.count(marker) != 1:
                print("FAIL: missing/duplicate native ELF proof: " + marker)
                return 1
        for bad in [
            "WOLFOS_ELF_RUN_ERROR", "WOLFOS_RING_PREP_ERROR",
            "WOLFOS_PANIC", "WOLFOS_EXCEPTION_PF",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_UD",
            "WOLFOS_EXCEPTION_DF",
        ]:
            if bad in output:
                print("FAIL: ELF kernel trap rejected: " + bad)
                return 1
        if result.returncode != 33:
            print(f"FAIL: expected clean QEMU debug-exit 33, got {result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: linked ELF64 -> validated RX+RW/BSS -> real CPL3 Hello -> EXIT -> CR3 restore + 7 PMM free")
        return 0

if __name__ == "__main__":
    sys.exit(main())
