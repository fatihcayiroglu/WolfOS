#!/usr/bin/env python3
"""Actual CPL3 ELF OPEN_RO(6)/READ(7)/CLOSE(8) with checked user pointers."""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ENTER = re.compile(
    r"WOLFOS_ELF_RUN_ENTER elf64=1 et_exec=1 pt_load=2 rx=1 rw_nx=2 "
    r"bss_zero=1 cr3_new=1 root_slot=(\d+) user_entry=0x401000"
)
PROOFS = [
    "WOLFOS_FILE_IO_READY tmp_mount=1 sealed_files=2 pid_owner=1",
    "WOLFOS_ELF_ID_OK cpl3=1 return_rax=0x574f4c46",
    "WOLFOS_ELF_ADD_OK cpl3=1 return_rax=42",
    "WOLFOS_SHIELD_FILE_DENIED_OK pid=1 fd_open=0 policy_default_deny=1",
    "WOLFOS_SHIELD_FILE_GRANT_OK pid=1 handles=0",
    "WOLFOS_FILE_IO_BAD_OPEN_OK supervisor_denied=1",
    "WOLFOS_SHIELD_PRIVATE_OPEN_DENIED_OK pid=1 fd_open=0",
    "WOLFOS_FILE_IO_OPEN_OK path_user_rx=1 fd=256",
    "WOLFOS_FILE_IO_BAD_READ_OK rx_write_denied=1 cursor_rollback=1",
    "WOLFOS_FILE_IO_READ_OK bytes=8 user_stack=1 payload=FILE_OK",
    "WOLFOS_SHIELD_FILE_REVOKE_OK pid=1 handles=1",
    "WOLFOS_SHIELD_READ_DENIED_OK pid=1 retained_fd=1",
    "WOLFOS_SHIELD_PRIVATE_SCOPE_OK pid=1 handles=1",
    "WOLFOS_SHIELD_WRONG_SCOPE_READ_DENIED_OK pid=1 fd_kept=1",
    "WOLFOS_SHIELD_SCOPE_RESTORED_OK pid=1 handles=1",
    "WOLFOS_FILE_IO_EOF_OK read=0",
    "WOLFOS_FILE_IO_CLOSE_OK released=1",
    "WOLFOS_FILE_IO_STALE_OK ebadf=1",
    "WOLFOS_SHIELD_RETIRED_OK pid=1 grants=0 stale_denied=1",
    "WOLFOS_FILE_IO_FDS_OK open=0 stale_denied=1 pid_cleanup=1",
    "WOLFOS_FILE_IO_EXIT_OK code=0 cpl3=1 calls=14",
    "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1",
    "WOLFOS_FILE_IO_RUN_OK linked_elf=1 hardware_cpl3=1 "
    "real_file_syscalls=3 int80_calls=14 exit=0 resources_released=1 "
    "persistent=0 production=0",
]

def main():
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_file_io_smoke.py path/to/wolfos-user-file-io.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-file-io-") as tmp:
        log = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{log}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: genuine CPL3 file IO timed out")
            if log.exists():
                print(log.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU unavailable")
            return 2
        output = log.read_text(errors="replace") if log.exists() else ""
        print(output)
        enter = ENTER.search(output)
        if not enter or not 1 <= int(enter.group(1)) <= 255:
            print("FAIL: no real sanitized CPL3 entry")
            return 1
        locations = [output.find("WOLFOS_BOOT_OK"), enter.start()]
        locations += [output.find(p) for p in PROOFS]
        # READY runs before ENTER, so check READY independently first.
        if output.find(PROOFS[0]) < 0 or output.find(PROOFS[0]) >= enter.start():
            print("FAIL: VFS staging not before CPL3 entry")
            return 1
        positions = [output.find("WOLFOS_BOOT_OK"), enter.start()]
        positions += [output.find(p) for p in PROOFS[1:]]
        if any(p < 0 for p in positions) or positions != sorted(positions):
            print("FAIL: missing/out-of-order user file I/O proof")
            return 1
        if any(output.count(p) != 1 for p in PROOFS):
            print("FAIL: duplicate/missing file I/O marker")
            return 1
        for forbidden in [
            "WOLFOS_FILE_IO_ERROR", "WOLFOS_ELF_RUN_ERROR",
            "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_GP",
            "WOLFOS_EXCEPTION_UD", "WOLFOS_EXCEPTION_DF",
            "WOLFOS_PANIC", "WOLFOS_ELF_HELLO_OK",
        ]:
            if forbidden in output:
                print("FAIL: fault or legacy console path: " + forbidden)
                return 1
        if run.returncode != 33:
            print("FAIL: QEMU debug-exit expected 33, got", run.returncode)
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: genuine CPL3 Shield exact-path deny/grant/revoke/re-scope/retire, checked file syscalls and seven-frame cleanup")
        return 0

if __name__ == "__main__":
    sys.exit(main())
