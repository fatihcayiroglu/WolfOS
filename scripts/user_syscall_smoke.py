#!/usr/bin/env python3
"""P2 register-based INT80 syscall ABI under a separate sanitized active CR3.

Proof requires all four actual register returns (ID, ENOSYS, checked ADD,
EINVAL) and fifth SYS_EXIT_ZERO, while old QEMU and host tests remain active.
No arbitrary user pointers or ELF applications are accepted by the kernel.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ENTER = re.compile(
    r"WOLFOS_SYSCALL_ENTER cr3_new=1 cr3_distinct=1 high_supervisor=1 "
    r"user_pages=3 rx=1 rw_nx=2 root_slot=(\d+) nxe=1 abi=int80"
)
RETURNS = [
    "WOLFOS_SYSCALL_RETURN stage=1 rax=0x574f4c46 saved_gpr=1 cpl3=1 kernel_cpl=0",
    "WOLFOS_SYSCALL_RETURN stage=2 rax=0xffffffffffffffda saved_gpr=1 cpl3=1 kernel_cpl=0",
    "WOLFOS_SYSCALL_RETURN stage=3 rax=0x2a saved_gpr=1 cpl3=1 kernel_cpl=0",
    "WOLFOS_SYSCALL_RETURN stage=4 rax=0xffffffffffffffea saved_gpr=1 cpl3=1 kernel_cpl=0",
]
EXIT = "WOLFOS_SYSCALL_EXIT_OK stage=5 code=0 returned_to_user=4"
SUCCESS = (
    "WOLFOS_SYSCALL_OK cr3_distinct=1 cpl3=1 call_count=5 "
    "results_checked=4 enosys=1 einval=1 gprs_preserved=1 exit_zero=1 processes=0"
)

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_syscall_smoke.py path/to/wolfos-user-syscall.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-syscall-") as tmp:
        serial = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{serial}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: real register-based INT80 QEMU test timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 missing")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        entry = ENTER.search(output)
        if not entry or not 1 <= int(entry.group(1)) <= 255:
            print("FAIL: independent sanitized CR3 entry was not observed")
            return 1
        ordered_markers = RETURNS + [EXIT, SUCCESS]
        positions = [output.find("WOLFOS_BOOT_OK"), entry.start()]
        positions += [output.find(marker) for marker in ordered_markers]
        if any(position < 0 for position in positions) or positions != sorted(positions):
            print("FAIL: missing or out-of-order actual user syscall/IRETQ evidence")
            return 1
        for marker in ordered_markers:
            if output.count(marker) != 1:
                print(f"FAIL: missing or duplicated proof marker: {marker}")
                return 1
        for bad in (
            "WOLFOS_SYSCALL_ERROR", "WOLFOS_RING_PREP_ERROR",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
            "WOLFOS_EXCEPTION_DF", "WOLFOS_EXCEPTION_UD",
            "WOLFOS_PANIC",
        ):
            if bad in output:
                print(f"FAIL: unexpected CPL fault or fail-closed error: {bad}")
                return 1
        if run.returncode != 33:
            print(f"FAIL: QEMU must exit via 0xf4 with code 33, got {run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: 5 real saved-GPR INT80 syscalls under new CR3, four checked IRETQ/RAX returns and kernel EXIT")

if __name__ == "__main__":
    sys.exit(main())
