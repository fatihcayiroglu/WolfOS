#!/usr/bin/env python3
"""First original WolfOS VFS mount/owner-FD acceptance test in QEMU.

Requires strict root and /tmp mount routing, stale/foreign descriptor denial,
sealing of the file-backed native ELF, actual CPL3 execution, 22 INT80
syscalls, Hello, EXIT(0), boot CR3 restoration and zero PMM leaks.
No user-mode open/read syscall or persistent storage is claimed.
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
    r"WOLFOS_VFS_READY root_mount=1 tmp_mount=1 owner_fds=1 stale_fds=1 "
    r"busy_unlink=1 sealed_elf=1 path_denial=1 elf_bytes=(\d+) cap=32768"
)
ENTER = re.compile(
    r"WOLFOS_ELF_RUN_ENTER elf64=1 et_exec=1 pt_load=2 rx=1 rw_nx=2 "
    r"bss_zero=1 cr3_new=1 root_slot=(\d+) user_entry=0x401000"
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
    "WOLFOS_VFS_EXEC_OK file_backed_elf=1 hardware_cpl3=1 root_tmp=2 "
    "owner_fd=1 sealed=1 exited=1 pmm_no_leak=1 persistent=0",
]

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_vfs_smoke.py path/to/wolfos-user-vfs.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-vfs-") as tmp:
        serial = Path(tmp) / "serial.log"
        command = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{serial}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(command, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: VFS mount/FD and CPL3 app timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 unavailable")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        if not valid_launch_transactions(output, 7, (1,)):
            print("FAIL: counted launch rollback, CPU ownership or terminal retirement evidence missing")
            return 1
        ready, entry = READY.search(output), ENTER.search(output)
        if ready is None or entry is None:
            print("FAIL: missing verified VFS mount/FD or ELF execution")
            return 1
        if not 64 <= int(ready.group(1)) <= 32768 or not 1 <= int(entry.group(1)) <= 255:
            print("FAIL: invalid real ELF length or distinct user PML4 slot")
            return 1
        locations = [output.find("WOLFOS_BOOT_OK"), ready.start(), entry.start()]
        locations += [output.find(marker) for marker in MARKERS]
        if any(i < 0 for i in locations) or locations != sorted(locations):
            print("FAIL: missing/out-of-order mount, independent ELF, CPL3, EXIT or cleanup")
            return 1
        if output.count("WOLFOS_VFS_READY ") != 1:
            print("FAIL: duplicate mount preparation")
            return 1
        for marker in MARKERS:
            if output.count(marker) != 1:
                print("FAIL: proof marker missing or repeated: " + marker)
                return 1
        for bad in (
            "WOLFOS_VFS_ERROR", "WOLFOS_ELF_RUN_ERROR",
            "WOLFOS_RING_PREP_ERROR", "WOLFOS_EXCEPTION_PF",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_UD",
            "WOLFOS_EXCEPTION_DF", "WOLFOS_PANIC",
        ):
            if bad in output:
                print("FAIL: fail-closed kernel reported " + bad)
                return 1
        if run.returncode != 33:
            print(f"FAIL: expected clean hardware QEMU debug-exit 33; got {run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: VFS root/tmp isolation + PID-owned FDs + real file-backed Ring3 ELF + PMM cleanup")
        return 0

if __name__ == "__main__":
    sys.exit(main())
