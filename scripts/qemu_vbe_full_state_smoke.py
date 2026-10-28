#!/usr/bin/env python3
"""Real QEMU VBE register snapshot: virtual plane, bank and panning intact.

Runs only the opt-in full-state smoke ISO. The two ENABLE writes happen in
the separately verified transaction; this validator checks unchanged state.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from qemu_stdvga_dispi_smoke import PROOF
from qemu_vbe_enable_tx_smoke import validate as validate_transaction

REGS = re.compile(
    r"WOLFOS_QEMU_VBE_FULL_(BEFORE|AFTER) bank=(\d+) "
    r"virtw=(\d+) virth=(\d+) xoff=(\d+) yoff=(\d+) "
    r"selector_restored=1 data_writes=0"
)
SUCCESS = (
    "WOLFOS_QEMU_VBE_FULL_STATE_OK snapshots_equal=1 bank_zero=1 pan_zero=1 "
    "virtual_plane_bounded=1 tx_writes=2 native_accel=0"
)
FORBIDDEN = (
    "WOLFOS_QEMU_VBE_FULL_FAIL", "WOLFOS_QEMU_VBE_FULL_TEST_FAILED",
    "WOLFOS_PANIC", "WOLFOS_GPU_DRIVER_LOADED",
)

def validate(output: str, exit_code: int) -> bool:
    if not validate_transaction(output, exit_code):
        return False
    if any(token in output for token in FORBIDDEN):
        return False
    rows = output.splitlines()
    captures = [(i, REGS.fullmatch(row)) for i, row in enumerate(rows)
                if row.startswith("WOLFOS_QEMU_VBE_FULL_BEFORE ")
                or row.startswith("WOLFOS_QEMU_VBE_FULL_AFTER ")]
    results = [i for i, row in enumerate(rows) if row.startswith("WOLFOS_QEMU_VBE_FULL_STATE_OK")]
    proof = [(i, PROOF.fullmatch(row)) for i, row in enumerate(rows)
             if row.startswith("WOLFOS_QEMU_DISPI_PROBE_OK ")]
    attest = [i for i, row in enumerate(rows)
              if row.startswith("WOLFOS_QEMU_DISPLAY_ATTEST_OK ")]
    tx = [i for i, row in enumerate(rows)
          if row.startswith("WOLFOS_QEMU_VBE_ENABLE_TX_OK ")]
    fb = [i for i, row in enumerate(rows) if row.startswith("WOLFOS_FB_TEXT_OK ")]
    if (len(captures) != 2 or len(results) != 1 or len(proof) != 1
            or len(attest) != 1 or len(tx) != 1 or len(fb) != 1
            or rows[results[0]] != SUCCESS):
        return False
    if captures[0][1] is None or captures[1][1] is None or proof[0][1] is None:
        return False
    if captures[0][1].group(1) != "BEFORE" or captures[1][1].group(1) != "AFTER":
        return False
    if not (proof[0][0] < attest[0] < captures[0][0] < tx[0]
            < captures[1][0] < results[0] < fb[0] < rows.index("WOLFOS_BOOT_OK")):
        return False
    before, after = captures[0][1].groups()[1:], captures[1][1].groups()[1:]
    if before != after:
        return False
    bank, virtw, virth, xoff, yoff = map(int, before)
    _, xres, yres, bpp, enabled, vram = proof[0][1].groups()
    xres, yres, bpp, enabled, vram = map(int, (xres, yres, bpp, enabled, vram))
    if (bank != 0 or xoff != 0 or yoff != 0 or not(enabled & 1)
            or bpp != 32 or virtw < xres or virth < yres
            or virtw * virth * 4 > vram * 65536):
        return False
    return True

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: qemu_vbe_full_state_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-qemu-vbe-full-") as d:
        logfile = Path(d) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{logfile}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=65, check=False)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print(f"FAIL: QEMU VBE full-state observation: {exc}")
            print(logfile.read_text(errors="replace") if logfile.exists() else "")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if not validate(output, result.returncode):
            print(f"FAIL: QEMU VBE full-state before/after data, exit={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: real QEMU full VBE virtual-plane/bank/pan registers "
              "unchanged across two ENABLE writes; index restored.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
