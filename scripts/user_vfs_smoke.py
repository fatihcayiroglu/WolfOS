#!/usr/bin/env python3
"""WolfOS VFS: file-descriptor-backed REAL native ELF64 CPL3 integration.

Checks genuine kernel serial traces, full ELF64 process launch, 22 INT80
calls, restored kernel CR3 and zero leaked PMM frames. Explicitly no
user-visible VFS syscalls, persistent storage or production app loader.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

VFS = re.compile(
    r"WOLFOS_VFS_READY files=1 open_fds=1 slot_generation=1 sealed_elf=1 "
    r"open_close=1 cursor=1 config_io=1 stale_fd_denied=1 elf_bytes=(\d+)"
)
ELF = re.compile(
    r"WOLFOS_ELF_RUN_ENTER elf64=1 et_exec=1 pt_load=2 rx=1 "
    r"rw_nx=2 bss_zero=1 cr3_new=1 root_slot=(\d+) user_entry=0x401000"
)
REQUIRED = [
    "WOLFOS_ELF_ID_OK cpl3=1 return_rax=0x574f4c46",
    "WOLFOS_ELF_ADD_OK cpl3=1 return_rax=42",
    "Hello from WolfOS!\n",
    "WOLFOS_ELF_HELLO_OK bytes=19 syscall_iretq=19",
    "WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=22",
    "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1",
    "WOLFOS_ELF_RUN_OK linked_elf=1 hardware_cpl3=1 user_console=1 "
    "int80_calls=22 exit=0 resources_released=1 real_process_manager=0",
    "WOLFOS_VFS_EXEC_OK descriptor_source=1 sealed=1 cpl3=1 hello=1 "
    "exit=0 cr3_restored=1 all_frames_freed=1 user_file_syscalls=0",
]
def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_vfs_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-vfs-") as temp:
        serial = Path(temp) / "serial.log"
        args = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{serial}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(args, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: VFS descriptor-backed ELF loader QEMU timed out")
            if serial.exists(): print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 not installed")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        vfs = VFS.search(output)
        elf = ELF.search(output)
        if not vfs or not elf:
            print("FAIL: VFS admission or separately mapped ELF entry missing")
            return 1
        if not (64 <= int(vfs.group(1)) <= 32768
                and 1 <= int(elf.group(1)) <= 255):
            print("FAIL: invalid ELF length or CR3 root slot")
            return 1
        positions = [output.find("WOLFOS_BOOT_OK"), vfs.start(), elf.start()]
        positions += [output.find(m) for m in REQUIRED]
        if any(p < 0 for p in positions) or positions != sorted(positions):
            print("FAIL: real FD->ELF->CPL3->exit->reap flow not ordered")
            return 1
        if output.count("WOLFOS_VFS_READY ") != 1:
            print("FAIL: VFS initialized more than once")
            return 1
        for marker in REQUIRED:
            if output.count(marker) != 1:
                print("FAIL: missing or duplicate proof: " + marker)
                return 1
        for bad in [
            "WOLFOS_VFS_ERROR", "WOLFOS_ELF_RUN_ERROR",
            "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_GP",
            "WOLFOS_EXCEPTION_UD", "WOLFOS_EXCEPTION_DF",
            "WOLFOS_RING_PREP_ERROR", "WOLFOS_PANIC",
        ]:
            if bad in output:
                print("FAIL: invalid access/kernel fault: " + bad)
                return 1
        if run.returncode != 33:
            print(f"FAIL: expected QEMU debug exit 33, got {run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: VFS FD-backed real ELF64, hardware CPL3, 22 INT80, successful exit and PMM cleanup")
        return 0
if __name__ == "__main__":
    sys.exit(main())
