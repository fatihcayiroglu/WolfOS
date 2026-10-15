#!/usr/bin/env python3
"""WolfOS hardware CPL3 SYS_FILE_OPEN/READ/CLOSE and safe user-buffer admission.

A separately linked ELF executes exactly 27 real INT80 calls, copies
8 bytes from original PID-scoped VFS into RW+NX user .bss, verifies bytes
IN USER MODE and rejects attempted RX-code and kernel-address accesses
with -EFAULT. Validates CR3 reversion, PMM ownership and no file leaks.
Single-BSP, fixed trusted fixture; NOT general POSIX or pointer handling.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ENTRY = re.compile(
    r"WOLFOS_ELF_RUN_ENTER elf64=1 et_exec=1 pt_load=2 rx=1 "
    r"rw_nx=2 bss_zero=1 cr3_new=1 root_slot=(\d+) user_entry=0x401000"
)
MARKERS = [
    "WOLFOS_ELF_ID_OK cpl3=1 return_rax=0x574f4c46",
    "WOLFOS_ELF_ADD_OK cpl3=1 return_rax=42",
    "Hello from WolfOS!\n",
    "WOLFOS_ELF_HELLO_OK bytes=19 syscall_iretq=19",
    "WOLFOS_FILE_OPEN_OK cpl3=1 pid=1 path_from_user=1 fd_owned=1",
    "WOLFOS_FILE_READ_OK cpl3=1 bytes=8 copied_to_bss=1 cursor=8",
    "WOLFOS_FILE_EFAULT_RX_OK denied_write_to_user_code=1 cursor_unchanged=1",
    "WOLFOS_FILE_CLOSE_OK pid=1 descriptor_released=1",
    "WOLFOS_FILE_EFAULT_KERNEL_OK denied_kernel_pointer=1",
    "WOLFOS_FILE_IO_DONE calls=5 read_bytes=8 efault_denials=2 opened=1 closed=1 leaked_fd=0",
    "WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=27",
    "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1",
    "WOLFOS_ELF_RUN_OK linked_elf=1 hardware_cpl3=1 user_console=1 "
    "int80_calls=27 exit=0 resources_released=1 real_process_manager=0",
]

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_file_io_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-real-file-syscalls-") as tmp:
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
            print("FAIL: user-VFS hardware file syscall sequence timed out")
            if serial.exists(): print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU unavailable")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        entry = ENTRY.search(output)
        ready = output.find("WOLFOS_FILE_IO_READY root_tmp=2 sealed=1 pid_scoped=1")
        if entry is None or ready < 0 or not 1 <= int(entry.group(1)) <= 255:
            print("FAIL: private user CR3 or sealed PID-scoped VFS not ready")
            return 1
        positions = [output.find("WOLFOS_BOOT_OK"), ready, entry.start()]
        positions.extend(output.find(m) for m in MARKERS)
        if any(i < 0 for i in positions) or positions != sorted(positions):
            print("FAIL: actual user file syscall/reap order violated")
            return 1
        for marker in MARKERS:
            if output.count(marker) != 1:
                print("FAIL: absent/duplicate marker: " + marker)
                return 1
        for bad in [
            "WOLFOS_FILE_IO_ERROR", "WOLFOS_ELF_RUN_ERROR",
            "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_GP",
            "WOLFOS_EXCEPTION_UD", "WOLFOS_EXCEPTION_DF",
            "WOLFOS_RING_PREP_ERROR", "WOLFOS_PANIC",
        ]:
            if bad in output:
                print("FAIL: fail-closed user pointer / syscall violation: " + bad)
                return 1
        if result.returncode != 33:
            print(f"FAIL: clean QEMU debug exit expected 33, got {result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: 27 Ring3 INT80s, PID-owned VFS open/read/close, 2 -EFAULT, user .bss verified, 7 PMM frames recovered")
        return 0

if __name__ == "__main__":
    sys.exit(main())
