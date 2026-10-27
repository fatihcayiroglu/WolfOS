#!/usr/bin/env python3
"""Fail-closed QEMU negative witness: a missing remote IPI must PIN live ELF frames.

Exactly two APs physically flush/EOI; the third AP remains online without
an IPI. The owner must refuse retirement and the QEMU must exit WITHOUT
PMM free/cleanup. This is an intentionally terminal isolated test flavor.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from user_elf_smp_ipi_retire_smoke import ACTIVATION

EXIT = "WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=22"
BLOCKED = (
    "WOLFOS_ELF_TX_RETIRE_BLOCKED_OK pid=1 cpu_outstanding=1 "
    "active_ack_denied=1 frames_pinned=1"
)
PROOF = (
    "WOLFOS_ELF_SMP_IPI_MISSING_ACK_OK pid=1 cpus=4 real_cpl3_bsp=1 "
    "ap_cpl0_root_borrowers=3 remote_ipis_sent=2 remote_eois=2 "
    "last_ipi_sent=0 pending_mask_one=1 owner_refused=1 frames_pinned=7 "
    "premature_free=0 last_ap_online=1"
)
FORBIDDEN = (
    "WOLFOS_ELF_SMP_IPI_REAP_OK", "WOLFOS_ELF_TX_TLB_SMP_OK",
    "WOLFOS_ELF_CLEANUP_OK", "WOLFOS_ELF_SMP_IPI_ERROR",
    "WOLFOS_ELF_ERROR", "WOLFOS_PANIC",
    "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_DF", "WOLFOS_USER_ELF_TEST_FAILED",
    "WOLFOS_SMP_TEST_FAILED",
)


def validate(output: str, code: int) -> bool:
    rows = output.splitlines()
    required = ("WOLFOS_BOOT_OK", ACTIVATION, EXIT, BLOCKED, PROOF)
    if code != 33 or any(rows.count(line) != 1 for line in required):
        return False
    if not (rows.index(required[0]) < rows.index(required[1])
            < rows.index(required[2]) < rows.index(required[3])
            < rows.index(required[4])):
        return False
    ap_rows = [row for row in rows if row.startswith("WOLFOS_SMP_APS_OK ")]
    if len(ap_rows) != 1 or re.fullmatch(
        r"WOLFOS_SMP_APS_OK total=4 bsp_lapic=[0-9]+ ap_acks=3", ap_rows[0]
    ) is None:
        return False
    for expected in required[1:]:
        prefix = expected.split()[0]
        if any(row.startswith(prefix + " ") and row != expected for row in rows):
            return False
    if any(token in output for token in FORBIDDEN):
        return False
    return True


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_elf_smp_ipi_missing_ack_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-elf-ipi-missing-ack-") as directory:
        logfile = Path(directory) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "4",
            "-cdrom", str(Path(sys.argv[1]).resolve()), "-boot", "d",
            "-serial", f"file:{logfile}", "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=65, check=False)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print(f"FAIL: incomplete IPI must pin frames: {exc}")
            print(logfile.read_text(errors="replace") if logfile.exists() else "")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if not validate(output, result.returncode):
            print(f"FAIL: missing remote IPI not proved fail-closed, exit={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: real ELF CPL3 EXIT and four-CPU owner; two AP hardware "
              "IPI/CR3/EOIs; absent last IPI pins all seven PMM frames. "
              "No owner retirement and no frame free were allowed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
