#!/usr/bin/env python3
"""Require genuine QEMU virtio-vga PCI capability proof, not a host mock.

No GPU config writes, BAR mapping or DMA. ISO is read-only virtual CDROM.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

GPU = re.compile(
    r"WOLFOS_GPU_DETECTED vendor=1af4 device=1050 bus=[0-9a-f]{2} slot=[0-9a-f]{2}"
)
POLICY = (
    "WOLFOS_GPU_DRIVER_POLICY vendor=1af4 device=1050 "
    "family=virtio native=none cfg_write=0"
)
CAPS = re.compile(
    r"WOLFOS_VIRTIO_GPU_PCI_CAPS_OK vendor=1af4 device=1050 "
    r"common=([0-5]) notify=([0-5]) isr=([0-5]) device=([0-5]) "
    r"multiplier=([1-9]\d*) cap_reads=64 cfg_writes=0 dma=0 accel=0"
)
FORBIDDEN = (
    "WOLFOS_VIRTIO_GPU_PCI_CAPS_FAIL",
    "WOLFOS_VIRTIO_GPU_PCI_TEST_FAILED",
    "WOLFOS_GPU_DRIVER_LOADED", "WOLFOS_PANIC",
    "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_DF",
    "cfg_writes=1", "dma=1", "accel=1", "native_accel=1",
    "driver_loaded=1", "WOLFOS_PCI_TEST_FAILED",
)


def validate(output: str, exit_code: int) -> bool:
    rows = output.splitlines()
    if exit_code != 33 or rows.count("WOLFOS_BOOT_OK") != 1:
        return False
    if any(word in output for word in FORBIDDEN):
        return False
    gpu = [i for i, row in enumerate(rows) if GPU.fullmatch(row)]
    policy = [i for i, row in enumerate(rows) if row == POLICY]
    caps = [(i, CAPS.fullmatch(row)) for i, row in enumerate(rows)
            if row.startswith("WOLFOS_VIRTIO_GPU_PCI_CAPS_OK ")]
    pci = [i for i, row in enumerate(rows) if row == "WOLFOS_PCI_TEST_OK"]
    proof = [i for i, row in enumerate(rows)
             if row == "WOLFOS_VIRTIO_GPU_PCI_TEST_OK"]
    fb = [i for i, row in enumerate(rows)
          if row.startswith("WOLFOS_FRAMEBUFFER_OK ")]
    if (len(gpu), len(policy), len(caps), len(pci), len(proof), len(fb)) != (1,1,1,1,1,1):
        return False
    if caps[0][1] is None:
        return False
    if not (gpu[0] < policy[0] < caps[0][0] < pci[0] < proof[0]
            < fb[0] < rows.index("WOLFOS_BOOT_OK")):
        return False
    # Capability BAR indices and nonzero notification multiplier are
    # validated by the genuine kernel parser. No driver binding claimed.
    return True


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: qemu_virtio_gpu_pci_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-virtio-gpu-pci-") as directory:
        serial_log = Path(directory) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "none", "-device", "virtio-vga",
            "-cdrom", str(Path(sys.argv[1]).resolve()), "-boot", "d",
            "-serial", f"file:{serial_log}", "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True,
                                    timeout=90, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            print(f"FAIL: real QEMU virtio-vga PCI discovery: {exc}")
            print(serial_log.read_text(errors="replace") if serial_log.exists() else "")
            return 1
        output = serial_log.read_text(errors="replace") if serial_log.exists() else ""
        print(output)
        if not validate(output, result.returncode):
            print(f"FAIL: no trustworthy virtio-vga PCI capability proof; exit={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: genuine QEMU virtio-vga 1af4:1050 PCI capabilities "
              "read-only; no DMA/MMIO, driver load or physical GPU touched.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
