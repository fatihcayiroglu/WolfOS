#!/usr/bin/env python3
"""Require real directed BSP-to-three-AP xAPIC IPIs and recipient-side EOIs."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: ap_ipi_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ap-ipi-") as tmp:
        logfile = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", "4", "-vga", "std", "-cdrom",
            str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{logfile}",
            "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=45, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: BSP->AP fixed IPI QEMU run timed out")
            if logfile.exists():
                print(logfile.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 not found")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if "WOLFOS_SMP_APS_OK total=4 " not in output:
            print("FAIL: all three APs did not complete prior independent kernel tests")
            return 1
        proof = re.search(
            r"WOLFOS_AP_IPI_OK cpus=(\d+) aps=(\d+) per_ap=(\d+) sends=(\d+) "
            r"received=(\d+) eois=(\d+) bad=(\d+) spurious=(\d+) "
            r"offline=(\d+) vector=(\d+) bsp_if=(\d+)",
            output,
        )
        if proof is None:
            print("FAIL: no genuine per-AP directed IPI/EOI evidence")
            return 1
        got = tuple(map(int, proof.groups()))
        if got != (4, 3, 3, 9, 9, 9, 0, 0, 3, 225, 0):
            print(f"FAIL: invalid directed IPI evidence {got}")
            return 1
        for error in ("WOLFOS_AP_IPI_ERROR", "WOLFOS_AP_IPI_TEST_FAILED",
                      "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
                      "WOLFOS_EXCEPTION_DF", "WOLFOS_PANIC"):
            if error in output:
                print(f"FAIL: kernel emitted {error}")
                return 1
        if "WOLFOS_BOOT_OK" not in output or run.returncode != 33:
            print(f"FAIL: kernel did not finish boot exit={run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: 4 CPUs, 3 recipient APs, 9 directed IPIs, 9 AP-local EOIs, "
              "all APs parked with IF=0")
        return 0


if __name__ == "__main__":
    sys.exit(main())
