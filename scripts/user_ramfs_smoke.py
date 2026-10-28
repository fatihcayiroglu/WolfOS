#!/usr/bin/env python3
"""QEMU: real native ELF image loaded FROM WolfOS RAMFS and run in CPL3.

Require strict file-backed chain and all the existing user-mode, BSS,
ELF64, INT80, CR3-switch, resource-reap and leak-free proof markers.
This does NOT attest persistence, VFS, arbitrary dynamic ELF or file syscalls.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

if __package__:
    from .elf_launch_evidence import valid_launch_transactions
else:
    from elf_launch_evidence import valid_launch_transactions


READY = re.compile(
    r"WOLFOS_RAMFS_READY slots=2 capacity=32768 "
    r"elf_path=/bin/hello\.elf elf_bytes=(\d+) "
    r"sealed=1 reopen=1 path_denial=1 stale_denial=1"
)
ENTER = re.compile(
    r"WOLFOS_ELF_RUN_ENTER elf64=1 et_exec=1 pt_load=2 "
    r"rx=1 rw_nx=2 bss_zero=1 cr3_new=1 root_slot=(\d+) user_entry=0x401000"
)
MARKERS = [
    "WOLFOS_ELF_ID_OK cpl3=1 return_rax=0x574f4c46",
    "WOLFOS_ELF_ADD_OK cpl3=1 return_rax=42",
    "Hello from WolfOS!\n",
    "WOLFOS_ELF_HELLO_OK bytes=19 syscall_iretq=19",
    "WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=22",
    "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1",
    "WOLFOS_ELF_RUN_OK linked_elf=1 hardware_cpl3=1 user_console=1 "
    "int80_calls=22 exit=0 resources_released=1 real_process_manager=0",
    "WOLFOS_RAMFS_EXEC_OK staged_elf=1 file_backed_loader=1 cpl3=1 "
    "hello=1 exited=1 pmm_no_leak=1 persistent=0",
]

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_ramfs_smoke.py path/to/wolfos-user-ramfs.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ramfs-") as tmp:
        log = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{log}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: native RamFS ELF user loader QEMU timed out")
            if log.exists(): print(log.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU unavailable")
            return 2
        output = log.read_text(errors="replace") if log.exists() else ""
        print(output)
        if not valid_launch_transactions(output, 7, (1,)):
            print("FAIL: counted launch rollback, CPU ownership or terminal retirement evidence missing")
            return 1
        ready = READY.search(output)
        entry = ENTER.search(output)
        if ready is None or entry is None:
            print("FAIL: RamFS staging or real ELF64 execution marker absent")
            return 1
        if not (64 <= int(ready.group(1)) <= 32768
                and 1 <= int(entry.group(1)) <= 255):
            print("FAIL: invalid staged ELF size or user CR3 slot")
            return 1
        positions = [output.find("WOLFOS_BOOT_OK"), ready.start(), entry.start()]
        positions.extend(output.find(marker) for marker in MARKERS)
        if any(p < 0 for p in positions) or positions != sorted(positions):
            print("FAIL: incomplete or out-of-order actual file-backed ELF run")
            return 1
        if output.count("WOLFOS_RAMFS_READY ") != 1:
            print("FAIL: duplicate RamFS preparation")
            return 1
        for marker in MARKERS:
            if output.count(marker) != 1:
                print("FAIL: missing/duplicate milestone: " + marker)
                return 1
        for bad in (
            "WOLFOS_RAMFS_ERROR", "WOLFOS_ELF_RUN_ERROR",
            "WOLFOS_RING_PREP_ERROR", "WOLFOS_EXCEPTION_PF",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_UD",
            "WOLFOS_EXCEPTION_DF", "WOLFOS_PANIC",
        ):
            if bad in output:
                print("FAIL: fail-closed kernel error: " + bad)
                return 1
        if result.returncode != 33:
            print(f"FAIL: expected QEMU debug-exit code 33, got {result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: WolfOS RamFS /bin/hello.elf -> strict ELF loader -> CPL3 Hello -> EXIT -> CR3 and PMM restored")
        return 0

if __name__ == "__main__":
    sys.exit(main())
