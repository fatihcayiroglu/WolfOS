#!/usr/bin/env python3
"""BSP or four-CPU CR3 retirement evidence; neither mode is an IPI shootdown."""
from pathlib import Path
import subprocess
import sys
import tempfile

PROOF = (
    "WOLFOS_ADDRESS_SPACE_RETIRE_OK bsp_only=1 private_cr3_loads=2 late_load_rejected=1 "
    "active_rejected=1 reentry_rejected=1 stale_ack_rejected=1 "
    "supervisor_restored=1 frames_freed=1 pmm_no_leak=1 ring3=0"
)
SMP_PROOF = (
    "WOLFOS_SMP_RETIRE_OK cpus=4 real_cr3_loads=4 per_cpu_restored=4 "
    "bsp_alone_rejected=1 last_ap_rejected=1 frames_freed=1 "
    "pmm_no_leak=1 ring3=0 ipi_shootdown=0"
)
OWNERSHIP_PROOF = (
    "WOLFOS_ACTIVE_SPACE_OWNERSHIP_OK staged_transfer=1 active_drop_retained=1 "
    "cpus=4 last_ap_pinned=1 drop_probe_freed=1 retired_owner_freed=1 "
    "pmm_no_leak=1 ring3=0 ipi_shootdown=0"
)


def evaluate(output: str, returncode: int, *, smp: bool = False) -> bool:
    rows = output.splitlines()
    proof = SMP_PROOF if smp else PROOF
    proofs = [row for row in rows if proof.split()[0] in row]
    if returncode != 33 or proofs != [proof] or rows.count("WOLFOS_BOOT_OK") != 1:
        return False
    if smp:
        ownership = [row for row in rows if OWNERSHIP_PROOF.split()[0] in row]
        if ownership != [OWNERSHIP_PROOF] or rows.index(OWNERSHIP_PROOF) >= rows.index(proof):
            return False
    if any(bad in output for bad in (
        "WOLFOS_ADDRESS_SPACE_RETIRE_ERROR", "WOLFOS_ADDRESS_SPACE_RETIRE_TEST_FAILED",
        "WOLFOS_SMP_RETIRE_ERROR", "WOLFOS_SMP_RETIRE_TEST_FAILED",
        "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_UD",
        "WOLFOS_EXCEPTION_DF", "WOLFOS_PANIC",
    )):
        return False
    return rows.index(proof) < rows.index("WOLFOS_BOOT_OK")


def main() -> int:
    if (len(sys.argv) not in (2, 3) or not Path(sys.argv[1]).is_file()
            or (len(sys.argv) == 3 and sys.argv[2] != "--smp")):
        print("Usage: address_space_retirement_smoke.py KERNEL_ISO [--smp]")
        return 2
    smp = len(sys.argv) == 3
    for cpus in ((4,) if smp else (1, 4)):
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
            if not evaluate(output, run.returncode, smp=smp):
                print(f"FAIL: retirement CR3 proof ({cpus} vCPUs, exit={run.returncode})")
                print(run.stderr.decode(errors="replace"))
                return 1
            description = ("active Drop pins frames, all CPU departures required, last AP withheld, zero PMM leak"
                           if smp else "BSP private CR3 blocks retirement until restored, zero PMM leak")
            print(f"PASS: {description} ({cpus} vCPUs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
