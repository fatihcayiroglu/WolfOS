#!/usr/bin/env python3
"""Hardware-only QEMU stdvga ENABLE temporary NOCLEARMEM transaction proof.

No production boots, physical GPU access or real disks. The enabled scanout
must survive two exact writes (0x0041 -> 0x00c1 -> 0x0041), including a pixel.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from qemu_stdvga_dispi_smoke import validate as validate_readonly

TRANSACTION = (
    "WOLFOS_QEMU_VBE_ENABLE_TX_OK pci=1234:1111 initial=0041 "
    "temporary=00c1 restored=0041 writes=2 selector_restored=1 "
    "geometry_preserved=1 pixel_preserved=1 native_accel=0"
)
FORBIDDEN = (
    "WOLFOS_QEMU_VBE_ENABLE_TX_FAIL",
    "WOLFOS_QEMU_VBE_ENABLE_TX_TEST_FAILED",
    "WOLFOS_PANIC", "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_DF", "WOLFOS_GPU_DRIVER_LOADED",
)

def validate(output: str, exit_code: int) -> bool:
    if not validate_readonly(output, exit_code):
        return False
    rows = output.splitlines()
    tx_rows = [(index, row) for index, row in enumerate(rows)
               if row.startswith("WOLFOS_QEMU_VBE_ENABLE_TX_")]
    if len(tx_rows) != 1 or tx_rows[0][1] != TRANSACTION:
        return False
    if any(token in output for token in FORBIDDEN):
        return False
    attest = [index for index, row in enumerate(rows)
              if row.startswith("WOLFOS_QEMU_DISPLAY_ATTEST_OK ")]
    text = [index for index, row in enumerate(rows)
            if row.startswith("WOLFOS_FB_TEXT_OK ")]
    probe = [index for index, row in enumerate(rows)
             if row.startswith("WOLFOS_QEMU_DISPI_PROBE_OK ")]
    if len(attest) != 1 or len(text) != 1 or len(probe) != 1:
        return False
    if not (probe[0] < attest[0] < tx_rows[0][0] < text[0] < rows.index("WOLFOS_BOOT_OK")):
        return False
    return True

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: qemu_vbe_enable_tx_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-qemu-vbe-enable-tx-") as d:
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
            print(f"FAIL: isolated VGA enable transaction: {exc}")
            print(logfile.read_text(errors="replace") if logfile.exists() else "")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if not validate(output, result.returncode):
            print(f"FAIL: QEMU VBE enable toggle or restored pixel evidence, exit={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: real QEMU VBE ENABLE control register writes, restored "
              "scanout/index and verified framebuffer pixel.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
