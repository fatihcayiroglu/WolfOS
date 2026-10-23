#!/usr/bin/env python3
"""BSP-only retirement gate with genuine CR3 loads; not an SMP shootdown."""
from pathlib import Path
import subprocess
import sys
import tempfile

PROOF = (
    "WOLFOS_ADDRESS_SPACE_RETIRE_OK bsp_only=1 private_cr3_loads=2 late_load_rejected=1 "
    "active_rejected=1 reentry_rejected=1 stale_ack_rejected=1 "
    "supervisor_restored=1 frames_freed=1 pmm_no_leak=1 ring3=0"
)


def evaluate(output: str, returncode: int) -> bool:
    rows = output.splitlines()
    proofs = [row for row in rows if "WOLFOS_ADDRESS_SPACE_RETIRE_OK" in row]
    if returncode != 33 or proofs != [PROOF] or rows.count("WOLFOS_BOOT_OK") != 1:
        return False
    if any(bad in output for bad in (
        "WOLFOS_ADDRESS_SPACE_RETIRE_ERROR", "WOLFOS_ADDRESS_SPACE_RETIRE_TEST_FAILED",
        "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_UD",
        "WOLFOS_EXCEPTION_DF", "WOLFOS_PANIC",
    )):
        return False
    return rows.index(PROOF) < rows.index("WOLFOS_BOOT_OK")


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: address_space_retirement_smoke.py KERNEL_ISO")
        return 2
    for cpus in (1, 4):
        with tempfile.TemporaryDirectory(prefix="wolfos-retirement-") as tmp:
            log = Path(tmp) / "serial.log"
            cmd = [
                "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", str(cpus),
                "-cdrom", str(Path(sys.argv[1]).resolve()), "-boot", "d",
                "-serial", f"file:{log}", "-display", "none", "-no-reboot",
                "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            ]
            try:
                run = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
            except (subprocess.TimeoutExpired, FileNotFoundError) as error:
                print(f"FAIL: retirement QEMU run ({cpus} vCPUs): {error}")
                print(log.read_text(errors="replace") if log.exists() else "")
                return 1
            output = log.read_text(errors="replace") if log.exists() else ""
            print(output)
            if not evaluate(output, run.returncode):
                print(f"FAIL: BSP retirement CR3 proof ({cpus} vCPUs, exit={run.returncode})")
                print(run.stderr.decode(errors="replace"))
                return 1
            print(f"PASS: BSP private CR3 blocks retirement until restored, zero PMM leak ({cpus} vCPUs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
