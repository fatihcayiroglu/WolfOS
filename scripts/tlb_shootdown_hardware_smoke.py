#!/usr/bin/env python3
"""Require three four-vCPU TLB rounds including one withheld final IPI."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

PROOF = re.compile(
    r"^WOLFOS_TLB_SHOOTDOWN_HW_OK cpus=(\d+) aps=(\d+) rounds=(\d+) "
    r"sends=(\d+) invlpg=(\d+) acks=(\d+) eois=(\d+) bad=(\d+) "
    r"spurious=(\d+) offline=(\d+) epoch=(\d+) pending=(\d+) "
    r"withheld=(\d+) blocked=(\d+) pcid=(\d+) freed=(\d+) "
    r"remaps=(\d+) probe_invlpg=(\d+) probe_reads=(\d+)$",
    re.MULTILINE,
)
EXPECTED = (4, 3, 3, 9, 9, 9, 9, 0, 0, 3, 3, 0, 1, 1, 0, 0, 2, 9, 9)
FAILURES = (
    "WOLFOS_TLB_SHOOTDOWN_HW_ERROR",
    "WOLFOS_TLB_SHOOTDOWN_HW_TEST_FAILED",
    "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_DF",
    "WOLFOS_PANIC",
)


def validate(output: str, code: int) -> bool:
    matches = PROOF.findall(output)
    if len(matches) != 1 or tuple(map(int, matches[0])) != EXPECTED:
        print("FAIL: missing or inconsistent recipient-local INVLPG proof")
        return False
    if "WOLFOS_SMP_APS_OK total=4 " not in output:
        print("FAIL: real four-vCPU SMP startup evidence is missing")
        return False
    if any(marker in output for marker in FAILURES):
        print("FAIL: kernel reported fault or TLB smoke failure")
        return False
    if output.count("WOLFOS_TLB_SHOOTDOWN_HW_OK") != 1:
        print("FAIL: duplicated hardware evidence")
        return False
    if "WOLFOS_BOOT_OK" not in output or code != 33:
        print(f"FAIL: QEMU did not reach successful boot exit (code={code})")
        return False
    return True


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: tlb_shootdown_hardware_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-tlb-invlpg-") as tmp:
        logfile = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "4",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{logfile}", "-display", "none",
            "-no-reboot", "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, check=False, timeout=45)
        except subprocess.TimeoutExpired:
            print("FAIL: four-CPU real TLB invalidation proof timed out")
            if logfile.exists():
                print(logfile.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 not installed")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if not validate(output, result.returncode):
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: 4 genuine CPUs, 3 epochs, 9 hardware IPIs, "
              "9 recipient-local INVLPG instructions and serialized acks; "
              "withheld last IPI left barrier pending, blocked a new epoch, "
              "then recovered; zero early reclamation; 2 real PTE remaps and "
              "9 recipient-local probe invalidations/verified marker reads")
        return 0


if __name__ == "__main__":
    sys.exit(main())
