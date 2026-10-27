#!/usr/bin/env python3
"""Strict real AP CPL3/INT80/IRETQ four-vCPU hardware evidence.

This proof uses a fixed trusted guest under shared BOOT CR3: it does not
assert an ELF scheduler, private address-space isolation or PMM retirement.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

PROOF_RE = re.compile(
    r"WOLFOS_AP_RING3_OK cpus=4 target_index=([0-3]) "
    r"bsp_lapic=([0-9]+) ap_lapic=([0-9]+) ap_cpl3=1 "
    r"int80=2 iret_to_cpl3=1 private_tss_rsp0=1 actual_tr=1 "
    r"rw_nx=2 rx=1 frames_pinned=6"
)
AP_RE = re.compile(r"WOLFOS_SMP_APS_OK total=4 bsp_lapic=([0-9]+) ap_acks=3")
FORBIDDEN = (
    "WOLFOS_AP_RING3_ERROR", "WOLFOS_AP_RING3_TEST_FAILED",
    "WOLFOS_PANIC", "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_DF", "WOLFOS_SMP_TEST_FAILED",
    "WOLFOS_RING3_ERROR", "WOLFOS_USER_ELF_TEST_FAILED",
)


def validate(output: str, exit_code: int) -> bool:
    rows = output.splitlines()
    if exit_code != 33 or rows.count("WOLFOS_BOOT_OK") != 1:
        return False
    ap_rows = [row for row in rows if row.startswith("WOLFOS_SMP_APS_OK ")]
    proof_rows = [row for row in rows if row.startswith("WOLFOS_AP_RING3_OK ")]
    if len(ap_rows) != 1 or len(proof_rows) != 1:
        return False
    boot = AP_RE.fullmatch(ap_rows[0])
    proof = PROOF_RE.fullmatch(proof_rows[0])
    if boot is None or proof is None:
        return False
    target, bsp_id, ap_id = map(int, proof.groups())
    if ap_id == bsp_id or int(boot.group(1)) != bsp_id:
        return False
    if not (rows.index(ap_rows[0]) < rows.index("WOLFOS_BOOT_OK")
            < rows.index(proof_rows[0])):
        return False
    return not any(token in output for token in FORBIDDEN)


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: ap_ring3_hardware_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ap-real-ring3-") as directory:
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
            print(f"FAIL: AP real Ring3 QEMU gate: {exc}")
            print(logfile.read_text(errors="replace") if logfile.exists() else "")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if not validate(output, result.returncode):
            print(f"FAIL: AP Ring3 user/ISR hardware evidence, exit={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: one REAL secondary CPU executes fixed CPL3 code, "
              "INT80 twice through its own GDT/TSS.RSP0, IRETQ once; "
              "six PMM frames intentionally remain pinned. "
              "No AP ELF scheduler or private root is claimed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
