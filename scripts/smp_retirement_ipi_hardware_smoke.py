#!/usr/bin/env python3
"""Fail-closed QEMU evidence of owner-bound CPL0 retirement via 3 real AP IPIs.

The marker may be produced only after all three APs have executed CR3 flush,
acknowledged the owning retirement round, issued local APIC EOIs and parked.
Does NOT represent multicore Ring3 execution or generalized TLB shootdown.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

PROOF = (
    "WOLFOS_SMP_RETIRE_IPI_OK cpus=4 ring3=0 owner_bound=1 "
    "ipis=3 eois=3 local_cr3_flush_acks=4 withheld_last_flush=1 "
    "premature_reclaim=0 frames_freed=1 pmm_no_leak=1 offline=3"
)
FAILURES = (
    "WOLFOS_SMP_RETIRE_ERROR", "WOLFOS_SMP_RETIRE_TEST_FAILED",
    "WOLFOS_AP_IPI_ERROR", "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_DF", "WOLFOS_EXCEPTION_UD", "WOLFOS_PANIC",
)


def validate(output: str, code: int) -> bool:
    rows = output.splitlines()
    if code != 33 or rows.count("WOLFOS_BOOT_OK") != 1:
        return False
    if rows.count(PROOF) != 1 or rows.index(PROOF) >= rows.index("WOLFOS_BOOT_OK"):
        return False
    if any("WOLFOS_SMP_RETIRE_IPI_OK" in row and row != PROOF for row in rows):
        return False
    if "WOLFOS_SMP_APS_OK total=4 " not in output:
        return False
    if any(bad in output for bad in FAILURES):
        return False
    # Reject a legacy CPL0 test accidentally misrepresented as hardware IPI.
    if "WOLFOS_SMP_RETIRE_OK " in output or "WOLFOS_ACTIVE_SPACE_OWNERSHIP_OK " in output:
        return False
    return True


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: smp_retirement_ipi_hardware_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-owner-ipi-") as directory:
        logfile = Path(directory) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "4",
            "-cdrom", str(Path(sys.argv[1]).resolve()), "-boot", "d",
            "-serial", f"file:{logfile}", "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print(f"FAIL: owner-bound four-vCPU IPI QEMU: {exc}")
            print(logfile.read_text(errors="replace") if logfile.exists() else "")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if not validate(output, result.returncode):
            print(f"FAIL: owner-bound real IPI retirement proof (exit={result.returncode})")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: owner-bound CPL0 retirement; three target AP IRQs, "
              "three local CR3 reloads and EOIs, withheld final AP, "
              "zero early frame release; not multicore Ring3")
    return 0


if __name__ == "__main__":
    sys.exit(main())
