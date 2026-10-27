#!/usr/bin/env python3
"""Strict hardware evidence: AP CPL3 ELF plus two genuine CPL0 AP root borrowers.

The target AP executes linked ELF in CPL3; the two other non-BSP CPUs must
each load the SAME private user PML4 in CPL0 and restore supervisor CR3.
BSP frees the seven PMM frames only after all three hardware departures.
This is not a general scheduler, directed IPI shootdown or PCID proof.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

AP_RE = re.compile(r"WOLFOS_SMP_APS_OK total=4 bsp_lapic=([0-9]+) ap_acks=3")
PROOF_RE = re.compile(
    r"WOLFOS_AP_RING3_ELF_MULTI_REAP_OK cpus=4 target_index=([0-3]) "
    r"bsp_lapic=([0-9]+) ap_lapic=([0-9]+) "
    r"linked_elf=1 et_exec=1 pt_load=2 ap_cpl3=1 int80=2 "
    r"iret_to_cpl3=1 ap_private_cr3=1 ap_restored_boot_cr3=1 "
    r"cpl0_borrowers=2 borrower_cr3_entered=2 borrower_cr3_departed=2 "
    r"all_user_cr3_departed=1 cr3_flushes=3 bsp_boot_cr3=1 "
    r"root_exclusive_after_departure=1 high_half_supervisor=1 "
    r"boot_user_slot_empty=1 scrubbed=7 frames_freed=7 "
    r"pmm_no_leak=1 stale_root_revoked=1 double_free_denied=1"
)
FORBIDDEN = (
    "WOLFOS_AP_RING3_ERROR", "WOLFOS_AP_RING3_TEST_FAILED",
    "WOLFOS_AP_RING3_RECLAIM_FAIL",
    "WOLFOS_PANIC", "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_DF", "WOLFOS_SMP_TEST_FAILED",
    "WOLFOS_RING3_ERROR", "WOLFOS_USER_ELF_TEST_FAILED",
)


def validate(output: str, exit_code: int) -> bool:
    rows = output.splitlines()
    if exit_code != 33 or rows.count("WOLFOS_BOOT_OK") != 1:
        return False
    ap_rows = [r for r in rows if r.startswith("WOLFOS_SMP_APS_OK ")]
    proof_rows = [r for r in rows if r.startswith("WOLFOS_AP_RING3_ELF_MULTI_REAP_OK ")]
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
        print("Usage: ap_ring3_elf_multi_owner_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ap-elf-multi-owner-") as d:
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
            print(f"FAIL: AP ELF multi-owner QEMU gate: {exc}")
            print(logfile.read_text(errors="replace") if logfile.exists() else "")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if not validate(output, result.returncode):
            print(f"FAIL: AP ELF multi-owner evidence, QEMU exit={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: genuine AP CPL3 ELF, two CPL0 private-root borrowers, "
              "all three local CR3 departures; seven frames scrubbed/reclaimed. "
              "No directed IPI or generic shootdown claimed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
