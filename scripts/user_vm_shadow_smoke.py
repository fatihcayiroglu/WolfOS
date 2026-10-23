#!/usr/bin/env python3
"""WolfOS P2 shadow-root proof: real PMM x86-64 tables, CR3 stays unchanged."""
from pathlib import Path
import subprocess
import sys
import tempfile

MARKER = (
    "WOLFOS_USER_ROOT_OK roots=2 pages=2 user=1 rx=1 rw_nx=1 "
    "high_half_empty=1 frames_freed=10 cr3_unchanged=1 ring3=0"
)

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_vm_shadow_smoke.py path/to/wolfos-user-vm-shadow.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-user-vm-") as tmp:
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
            print("FAIL: user shadow-root QEMU smoke timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU missing")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        multi_marker = (
            "WOLFOS_USER_MULTI_OK roots=1 pages=4 rx=2 rw_nx=2 "
            "elf_segments=2 bss_zero=1 atomic_page_copy=1 elf_pte_contract=1 byte_audit=1 tamper_rejected=4 stack_zero=1 ready_image_gate=1 hhdm_backing=1 staged_admission=1 kernel_supervisor=1 high_half_copied=1 "
            "kernel_anchor=1 hhdm_anchor=1 freed=8 "
            "cr3_unchanged=1 ring3=0"
        )
        if MARKER not in output or multi_marker not in output or "WOLFOS_BOOT_OK" not in output:
            print("FAIL: missing independently verified user page-table root or normal boot")
            return 1
        for bad in (
            "WOLFOS_USER_ROOT_ERROR", "WOLFOS_USER_ROOT_TEST_FAILED",
            "WOLFOS_USER_MULTI_ERROR", "WOLFOS_USER_MULTI_TEST_FAILED",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
            "WOLFOS_EXCEPTION_DF", "WOLFOS_PANIC",
        ):
            if bad in output:
                print("FAIL: " + bad)
                return 1
        if run.returncode != 33:
            print(f"FAIL: expected clean debug-exit 33, got {run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: two independent roots plus one mixed four-leaf ELF/stack root, no CR3 load")
        return 0

if __name__ == "__main__":
    sys.exit(main())
