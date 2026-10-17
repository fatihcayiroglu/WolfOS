#!/usr/bin/env python3
"""P2 QEMU: read actual x86-64 TR and TSS.RSP0 with isolated user GDTs.

DOES NOT enter Ring 3, execute an ELF, or change CR3. All legacy P0/P1
and P2 regression tests are separately required by GitHub Actions.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

PROOF = re.compile(
    r"WOLFOS_RING_PREP_OK tr=0x([0-9a-f]+) user_cs=0x([0-9a-f]+) "
    r"user_ds=0x([0-9a-f]+) rsp0_aligned=1 rsp0_stack_kib=16 "
    r"ist_disjoint=1 guards=1 cpl=0 ring3=0"
)

def strict_ring_prep_evidence(output: str) -> bool:
    """Require one complete GDT/TR/TSS proof, rejecting embedded or extra records."""
    rows = [row for row in output.splitlines()
            if "WOLFOS_RING_PREP_OK" in row]
    if len(rows) != 1:
        return False
    match = PROOF.fullmatch(rows[0])
    if match is None:
        return False
    tr, cs, ds = (int(value, 16) for value in match.groups())
    return tr == 0x18 and cs & 7 == 3 and ds & 7 == 3 and cs != ds


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_ring_prep_smoke.py path/to/wolfos-user-ring-prep.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ring-prep-") as tmp:
        serial = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", "1", "-vga", "std",
            "-cdrom", str(Path(sys.argv[1]).resolve()), "-boot", "d",
            "-serial", f"file:{serial}", "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: Ring3 preflight QEMU timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 missing")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        if not strict_ring_prep_evidence(output) or "WOLFOS_BOOT_OK" not in output:
            print("FAIL: missing, forged, duplicated or invalid GDT/TSS/TR proof or regular kernel boot")
            return 1
        for bad in (
            "WOLFOS_RING_PREP_ERROR", "WOLFOS_RING_PREP_TEST_FAILED",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_DF",
            "WOLFOS_PANIC",
        ):
            if bad in output:
                print(f"FAIL: unexpected failure marker {bad}")
                return 1
        if run.returncode != 33:
            print(f"FAIL: expected clean QEMU exit code 33; got {run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: loaded TR, user RPL3 descriptors, guarded TSS.RSP0; still CPL0")

if __name__ == "__main__":
    sys.exit(main())
