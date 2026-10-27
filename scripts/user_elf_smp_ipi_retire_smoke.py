#!/usr/bin/env python3
"""Exact QEMU proof: BSP real ELF Ring3, 3 CPL0 APs borrow same owned root.

No AP executes Ring3. Fail closed on absent AP/EOI, late flush or false-green.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

PROOF = (
    "WOLFOS_ELF_SMP_IPI_REAP_OK cpus=4 real_cpl3_bsp=1 "
    "ap_cpl0_root_borrowers=3 owner_bound=1 remote_ipis=3 eois=3 "
    "remote_cr3_flushes=3 bsp_cr3_flush=1 last_ap_withheld=1 "
    "premature_free=0 frames_freed=7 pmm_no_leak=1 offline=3"
)
ACTIVATION = (
    "WOLFOS_ELF_TX_ACTIVE_SMP_OK pid=1 frames=7 cpl3_bsp=1 "
    "ap_root_users=3 owner_reserved=4 local_cr3_observed=4"
)
TLB = (
    "WOLFOS_ELF_TX_TLB_SMP_OK pid=1 cpus=4 real_cpl3_bsp=1 "
    "remote_cr3_reload_ipis=3 withheld_last=1 frames_pinned=1"
)
FAILURES = (
    "WOLFOS_ELF_SMP_IPI_ERROR", "WOLFOS_ELF_ERROR", "WOLFOS_PANIC",
    "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_DF",
    "WOLFOS_USER_ELF_TEST_FAILED", "WOLFOS_SMP_TEST_FAILED",
)


def validate(output: str, code: int) -> bool:
    rows = output.splitlines()
    if code != 33 or rows.count("WOLFOS_BOOT_OK") != 1:
        return False
    for marker in (ACTIVATION, TLB, PROOF):
        if rows.count(marker) != 1:
            return False
        if any(marker.split()[0] in row and row != marker for row in rows):
            return False
    if not (rows.index("WOLFOS_BOOT_OK") < rows.index(ACTIVATION)
            < rows.index(TLB) < rows.index(PROOF)):
        return False
    if ("WOLFOS_SMP_APS_OK total=4 " not in output
            or rows.count("WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=22") != 1
            or rows.count("WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1") != 1):
        return False
    if any(bad in output for bad in FAILURES):
        return False
    return True


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_elf_smp_ipi_retire_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-elf-real-owner-") as directory:
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
            print(f"FAIL: real ELF owner / AP IPI test: {exc}")
            print(logfile.read_text(errors="replace") if logfile.exists() else "")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if not validate(output, result.returncode):
            print(f"FAIL: real ELF + AP owner-bound hardware retirement, exit={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: real BSP CPL3 ELF and four-CPU shared owner; AP-owned CPL0 "
              "real private-root loads, remote hardware IPI CR3 invalidations, "
              "EOIs and exact frame reclamation. AP Ring3 execution NOT claimed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
