#!/usr/bin/env python3
"""First real QEMU-only VBE 1280x800 -> 1024x768 -> 1280x800 rollback.

No physical adapter is addressed. The selected QEMU mode transaction is
opt-in and follows strict PCI/Limine/ENABLE/full-plane preflight evidence.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from qemu_vbe_full_state_smoke import validate as validate_full

MARKER = (
    "WOLFOS_QEMU_VBE_MODE_ROLLBACK_OK from=1280x800 to=1024x768 "
    "restored=1280x800 writes=11 temporary_enable=00c1 "
    "restored_enable=0041 selector_restored=1 full_state_restored=1 "
    "pixel_preserved=1 native_accel=0"
)
FAILED = (
    "WOLFOS_QEMU_VBE_MODE_ROLLBACK_FAIL",
    "WOLFOS_QEMU_VBE_MODE_ROLLBACK_TEST_FAILED",
    "WOLFOS_GPU_DRIVER_LOADED",
    "WOLFOS_PANIC",
)

def validate(output: str, exit_code: int) -> bool:
    if not validate_full(output, exit_code):
        return False
    if any(flag in output for flag in FAILED):
        return False
    rows = output.splitlines()
    found = [(n, line) for n, line in enumerate(rows)
             if line.startswith("WOLFOS_QEMU_VBE_MODE_ROLLBACK_OK")]
    if len(found) != 1 or found[0][1] != MARKER:
        return False
    indexed = {}
    tokens = {
        "probe": "WOLFOS_QEMU_DISPI_PROBE_OK ",
        "before": "WOLFOS_QEMU_VBE_FULL_BEFORE ",
        "enable_tx": "WOLFOS_QEMU_VBE_ENABLE_TX_OK ",
        "after": "WOLFOS_QEMU_VBE_FULL_AFTER ",
        "full": "WOLFOS_QEMU_VBE_FULL_STATE_OK ",
        "fb": "WOLFOS_FB_TEXT_OK ",
        "boot": "WOLFOS_BOOT_OK",
    }
    for key, token in tokens.items():
        places = [n for n, line in enumerate(rows)
                  if (line == token if key == "boot" else line.startswith(token))]
        if len(places) != 1:
            return False
        indexed[key] = places[0]
    idx = found[0][0]
    return (
        indexed["probe"] < indexed["before"] < indexed["enable_tx"]
        < indexed["after"] < indexed["full"] < idx
        < indexed["fb"] < indexed["boot"]
    )

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: qemu_vbe_mode_rollback_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-qemu-vbe-mode-rollback-") as d:
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
            print(f"FAIL: QEMU transient real resolution switch: {exc}")
            if logfile.exists():
                print(logfile.read_text(errors="replace"))
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if not validate(output, result.returncode):
            print(f"FAIL: QEMU 1280x800 -> 1024x768 -> 1280x800 evidence, exit={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: real QEMU VBE 1280x800 -> 1024x768 -> 1280x800, "
              "11 DATA writes, selector/virtual state and pixel restored; native accel=0.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
