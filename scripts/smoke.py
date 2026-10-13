#!/usr/bin/env python3
"""Boot a VM ISO and assert observable early kernel milestones."""
from __future__ import annotations
import pathlib
import subprocess
import sys
import tempfile

MARKERS = (
    "WOLFOS: Rust kernel entered",
    "WOLFOS_LIMINE_OK",
    "WOLFOS_CPU_OK",
    "WOLFOS_GDT_OK",
    "WOLFOS_IDT_OK",
    "WOLFOS_EXCEPTION_BP vector=3",
    "WOLFOS_BREAKPOINT_RETURN_OK",
    "WOLFOS_MEMMAP_OK",
    "WOLFOS_PMM_OK",
    "WOLFOS_PMM_TEST_OK iterations=10000 unique=128",
    "WOLFOS_PMM_DYNAMIC_OK",
    "WOLFOS_GPU_DETECTED",
    "WOLFOS_PCI_OK",
    "WOLFOS_PCI_TEST_OK",
    "WOLFOS_ACPI_RSDP_OK",
    "WOLFOS_ACPI_ROOT_OK",
    "WOLFOS_ACPI_MADT_OK",
    "WOLFOS_PAGING_MAP_OK",
    "WOLFOS_PAGING_UNMAP_OK",
    "WOLFOS_FRAMEBUFFER_OK",
    "WOLFOS_SMP_APS_OK total=1",
    "WOLFOS_SMP_AP_IDT_OK total=1 ap_idts=0 ap_bp_returns=0",
    "WOLFOS_SMP_PERCPU_OK total=1 ap_tables=0",
    "WOLFOS_BOOT_OK",
)

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: smoke.py path/to/wolfos-smoke.iso")
        return 2
    iso = pathlib.Path(sys.argv[1]).resolve()
    if not iso.is_file():
        print(f"ERROR: ISO not found: {iso}")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-smoke-") as tmp:
        log = pathlib.Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-vga", "std",
            "-cdrom", str(iso), "-boot", "d",
            "-serial", f"file:{log}", "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: QEMU did not reach smoke-exit in 45 seconds")
            if log.exists():
                print(log.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 missing")
            return 2
        output = log.read_text(errors="replace") if log.exists() else ""
        print(output)
        missing = [marker for marker in MARKERS if marker not in output]
        if missing:
            print(f"FAIL: missing boot markers: {missing}")
            print(run.stderr.decode(errors="replace"))
            return 1
        if run.returncode != 33:
            print(f"FAIL: expected QEMU debug-exit 33, got {run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: WolfOS kernel booted, read memory map, and accessed framebuffer")
        return 0

if __name__ == "__main__":
    sys.exit(main())
