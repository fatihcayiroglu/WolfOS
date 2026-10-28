#!/usr/bin/env python3
"""Strict physical QEMU stdvga Bochs VBE indexed-port observation.

The kernel may write only VBE INDEX 0x1ce and must restore its selector.
This is not a native accelerated GPU driver or display-mode configuration.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

GPU = re.compile(
    r"WOLFOS_GPU_DETECTED vendor=1234 device=1111 bus=[0-9a-f]{2} slot=[0-9a-f]{2}"
)
PROOF = re.compile(
    r"WOLFOS_QEMU_DISPI_PROBE_OK pci=1234:1111 "
    r"id=([0-9a-f]{4}) xres=(\d+) yres=(\d+) bpp=(\d+) "
    r"enabled=(\d+) vram64k=(\d+) "
    r"selector_restored=1 mode_writes=0 native_accel=0"
)
FORBIDDEN = (
    "WOLFOS_QEMU_DISPI_PROBE_FAIL", "WOLFOS_QEMU_DISPI_TEST_FAILED",
    "WOLFOS_PANIC", "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_DF", "WOLFOS_GPU_DRIVER_LOADED",
    "native_accel=1", "mode_writes=1",
)

def validate(output: str, exit_code: int) -> bool:
    rows = output.splitlines()
    if exit_code != 33 or rows.count("WOLFOS_BOOT_OK") != 1:
        return False
    gpu = [i for i, s in enumerate(rows) if GPU.fullmatch(s)]
    proofs = [(i, PROOF.fullmatch(s)) for i, s in enumerate(rows)
              if s.startswith("WOLFOS_QEMU_DISPI_PROBE_OK ")]
    pci_ok = [i for i, s in enumerate(rows) if s == "WOLFOS_PCI_TEST_OK"]
    if len(gpu) != 1 or len(proofs) != 1 or len(pci_ok) != 1:
        return False
    index, evidence = proofs[0]
    if evidence is None or any(token in output for token in FORBIDDEN):
        return False
    if not (gpu[0] < pci_ok[0] < index < rows.index("WOLFOS_BOOT_OK")):
        return False
    ident, xres, yres, bpp, enabled, vram64k = evidence.groups()
    if not (0xb0c0 <= int(ident, 16) <= 0xb0c5):
        return False
    xres, yres, bpp, enabled, vram64k = map(int, (xres, yres, bpp, enabled, vram64k))
    if vram64k == 0 or vram64k > 65535:
        return False
    if enabled & 1:
        if not (0 < xres <= 8192 and 0 < yres <= 8192):
            return False
        bpp_bytes = {4: 1, 8: 1, 15: 2, 16: 2, 24: 3, 32: 4}.get(bpp)
        if bpp_bytes is None or xres * yres * bpp_bytes > vram64k * 65536:
            return False
    return True

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: qemu_stdvga_dispi_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-qemu-dispi-") as d:
        logfile = Path(d) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std",
            "-cdrom", str(Path(sys.argv[1]).resolve()), "-boot", "d",
            "-serial", f"file:{logfile}", "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True,
                                    timeout=65, check=False)
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            print(f"FAIL: QEMU standard VGA Bochs VBE port proof: {exc}")
            print(logfile.read_text(errors="replace") if logfile.exists() else "")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if not validate(output, result.returncode):
            print(f"FAIL: stdvga DISPI evidence, QEMU exit={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: real QEMU VGA Bochs VBE indexed port reads, "
              "selector restored; no mode writes or GPU acceleration claimed.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
