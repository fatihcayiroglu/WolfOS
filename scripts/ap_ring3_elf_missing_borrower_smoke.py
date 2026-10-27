#!/usr/bin/env python3
"""Fail-closed QEMU proof: one real AP withholds private CR3 departure.

One AP executes linked ELF in CPL3, two other APs really enter private CR3
in CPL0. The highest-indexed borrower is deliberately parked with that CR3
active. BSP must refuse the normal seven-page PMM reclamation path.
This isolated test exits QEMU WITHOUT freeing those seven live frames.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

AP_RE = re.compile(r"WOLFOS_SMP_APS_OK total=4 bsp_lapic=([0-9]+) ap_acks=3")
REJECTION = "WOLFOS_AP_RING3_RECLAIM_FAIL stage=borrowers_still_live"
PROOF_RE = re.compile(
    r"WOLFOS_AP_RING3_ELF_MISSING_BORROWER_OK cpus=4 target_index=([0-3]) "
    r"bsp_lapic=([0-9]+) ap_lapic=([0-9]+) "
    r"linked_elf=1 et_exec=1 pt_load=2 ap_cpl3=1 int80=2 "
    r"iret_to_cpl3=1 ap_private_cr3=1 ap_restored_boot_cr3=1 "
    r"cpl0_borrowers=2 borrower_cr3_entered=2 borrower_cr3_departed=1 "
    r"borrower_held_private_cr3=1 all_user_cr3_departed=0 "
    r"reclaim_refused=1 frames_pinned=7 frames_freed=0 "
    r"pmm_held_lease=1 bsp_boot_cr3=1"
)
FORBIDDEN = (
    "WOLFOS_AP_RING3_ERROR", "WOLFOS_AP_RING3_TEST_FAILED",
    "WOLFOS_AP_RING3_ELF_MULTI_REAP_OK", "WOLFOS_AP_RING3_ELF_REAP_OK",
    "WOLFOS_PANIC", "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_DF", "WOLFOS_SMP_TEST_FAILED",
    "WOLFOS_RING3_ERROR", "WOLFOS_USER_ELF_TEST_FAILED",
)

def validate(output: str, exit_code: int) -> bool:
    rows = output.splitlines()
    if exit_code != 33 or rows.count("WOLFOS_BOOT_OK") != 1:
        return False
    ap_rows = [row for row in rows if row.startswith("WOLFOS_SMP_APS_OK ")]
    reject_rows = [row for row in rows
                   if row.startswith("WOLFOS_AP_RING3_RECLAIM_FAIL ")]
    proof_rows = [row for row in rows
                  if row.startswith("WOLFOS_AP_RING3_ELF_MISSING_BORROWER_OK ")]
    if len(ap_rows) != 1 or len(reject_rows) != 1 or len(proof_rows) != 1:
        return False
    if reject_rows[0] != REJECTION:
        return False
    ap = AP_RE.fullmatch(ap_rows[0])
    proof = PROOF_RE.fullmatch(proof_rows[0])
    if ap is None or proof is None:
        return False
    target, bsp_id, ap_id = map(int, proof.groups())
    if target == 0 or ap_id == bsp_id or int(ap.group(1)) != bsp_id:
        return False
    if not (rows.index(ap_rows[0]) < rows.index("WOLFOS_BOOT_OK")
            < rows.index(REJECTION) < rows.index(proof_rows[0])):
        return False
    return not any(token in output for token in FORBIDDEN)

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: ap_ring3_elf_missing_borrower_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ap-elf-held-cr3-") as d:
        logfile = Path(d) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "4",
            "-cdrom", str(Path(sys.argv[1]).resolve()), "-boot", "d",
            "-serial", f"file:{logfile}", "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True,
                                    timeout=65, check=False)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print(f"FAIL: AP ELF withheld-borrower QEMU gate: {exc}")
            print(logfile.read_text(errors="replace") if logfile.exists() else "")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if not validate(output, result.returncode):
            print(f"FAIL: AP ELF live borrower was not safely denied, QEMU exit={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: real borrower stayed on private CR3, seven-frame reclaim "
              "refused by the normal gate; no PMM frame freed. "
              "Not a general scheduler or shootdown claim.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
