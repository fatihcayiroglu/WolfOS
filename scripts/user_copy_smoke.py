#!/usr/bin/env python3
"""Real user-pointer INT80 WRITE using verified owned four-level CR3 walk.

The ELF guest passes RIP-relative user TEXT pointer (RDI) and 19-byte length
(RSI) to syscall 5, not 19 scalar PUTC calls. The kernel validates user PTE
and owned physical leaf frames before reading. Negative supervisor and RX
writes, RW stack copied to/from, then EXIT(0), clean CR3 and PMM restore.
No actual generic POSIX write nor concurrent/untrusted app loading yet.
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


ENTER = re.compile(
    r"WOLFOS_ELF_RUN_ENTER elf64=1 et_exec=1 pt_load=2 rx=1 rw_nx=2 "
    r"bss_zero=1 cr3_new=1 root_slot=(\d+) user_entry=0x401000"
)
PROOFS = [
    "WOLFOS_ELF_ID_OK cpl3=1 return_rax=0x574f4c46",
    "WOLFOS_ELF_ADD_OK cpl3=1 return_rax=42",
    "Hello from WolfOS!\n",
    "WOLFOS_USERCOPY_WRITE_OK guest_pointer=1 user_cr3_walk=4 copied=19 "
    "kernel_denied=1 rx_write_denied=1 stack_copy_roundtrip=1",
    "WOLFOS_USERCOPY_EXIT_OK code=0 cpl3=1 calls=4",
    "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1",
    "WOLFOS_USERCOPY_RUN_OK linked_elf=1 hardware_cpl3=1 real_user_pointer=1 "
    "int80_calls=4 exit=0 resources_released=1 production_user_copy=0",
]

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_copy_smoke.py path/to/wolfos-user-copy.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-usercopy-") as tmp:
        log = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{log}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: real user pointer syscall timed out")
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
        enter = ENTER.search(output)
        if not enter or not 1 <= int(enter.group(1)) <= 255:
            print("FAIL: missing actual hardware Ring3 sanitized CR3 entry")
            return 1
        loc = [output.find("WOLFOS_BOOT_OK"), enter.start()]
        loc += [output.find(x) for x in PROOFS]
        if any(p < 0 for p in loc) or loc != sorted(loc):
            print("FAIL: user ELF pointer/deny/roundtrip/exit/reap order invalid")
            return 1
        for marker in PROOFS:
            if output.count(marker) != 1:
                print("FAIL: missing or duplicate proof: " + marker)
                return 1
        for bad in [
            "WOLFOS_ELF_RUN_ERROR", "WOLFOS_PANIC",
            "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_GP",
            "WOLFOS_EXCEPTION_UD", "WOLFOS_EXCEPTION_DF",
            "WOLFOS_RING_PREP_ERROR", "WOLFOS_ELF_HELLO_OK",
        ]:
            if bad in output:
                print("FAIL: privileged fault or stale PUTC program: " + bad)
                return 1
        if run.returncode != 33:
            print("FAIL: expected QEMU debug-exit 33, got", run.returncode)
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: genuine ELF passes user pointer -> checked CR3 PTE walk -> WRITE -> EXIT -> 7 PMM frame cleanup")
        return 0

if __name__ == "__main__":
    sys.exit(main())
