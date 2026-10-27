#!/usr/bin/env python3
"""Strict exact-line evidence for genuine non-BSP CPL3 under a private PML4.

The marker originates from the guest after checking the real AP CR3 in BOTH
CPL3-originated INT80 traps and restoring boot CR3 before parking. No production ELF
scheduler, concurrent process isolation, reclaim or untrusted user code.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

AP_RE = re.compile(r"WOLFOS_SMP_APS_OK total=4 bsp_lapic=([0-9]+) ap_acks=3")
PROOF_RE = re.compile(
    r"WOLFOS_AP_RING3_ELF_OK cpus=4 target_index=([0-3]) "
    r"bsp_lapic=([0-9]+) ap_lapic=([0-9]+) ap_cpl3=1 "
    r"linked_elf=1 et_exec=1 pt_load=2 derived_pages=1 "
    r"int80=2 iret_to_cpl3=1 private_tss_rsp0=1 actual_tr=1 "
    r"ap_private_cr3=1 bsp_boot_cr3=1 kernel_supervisor_pml4=1 "
    r"boot_user_slot_empty=1 ap_restored_boot_cr3=1 "
    r"rx=1 rw_nx=2 frames_pinned=7"
)
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
    ap_rows = [r for r in rows if r.startswith("WOLFOS_SMP_APS_OK ")]
    proof_rows = [r for r in rows if r.startswith("WOLFOS_AP_RING3_ELF_OK ")]
    if len(ap_rows) != 1 or len(proof_rows) != 1:
        return False
    ap = AP_RE.fullmatch(ap_rows[0])
    proof = PROOF_RE.fullmatch(proof_rows[0])
    if ap is None or proof is None:
        return False
    target, bsp_id, ap_id = map(int, proof.groups())
    if target > 3 or ap_id == bsp_id or int(ap.group(1)) != bsp_id:
        return False
    if not (rows.index(ap_rows[0]) < rows.index("WOLFOS_BOOT_OK")
            < rows.index(proof_rows[0])):
        return False
    return not any(token in output for token in FORBIDDEN)


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: ap_ring3_elf_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ap-private-cr3-") as d:
        logfile = Path(d) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "4",
            "-cdrom", str(Path(sys.argv[1]).resolve()), "-boot", "d",
            "-serial", f"file:{logfile}", "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=65, check=False)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print(f"FAIL: AP native ELF hardware QEMU gate: {exc}")
            print(logfile.read_text(errors="replace") if logfile.exists() else "")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if not validate(output, result.returncode):
            print(f"FAIL: AP native ELF evidence, QEMU exit={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: real AP CPL3 independently linked ELF64 executed twice on private PML4/CR3, "
              "restored boot CR3, BSP boot user slot stayed empty; "
              "seven owned frames pinned. No production AP ELF scheduler or reclaim.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
