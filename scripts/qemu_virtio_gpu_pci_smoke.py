#!/usr/bin/env python3
"""Require genuine QEMU virtio-vga PCI capability proof, not a host mock.

The ordinary PCI modes are read-only. --size requires a QEMU-only, bounded,
fully restored BAR-size probe. --mmio additionally proves one volatile
read-only common-config MMIO mapping, and --device adds GPU-specific
scanout/capset reads. --preflight adds GPU feature-bank and controlq\ncapacity readback. All pages unmap before boot. No DMA, configured queues,
physical GPU, disk, or driver binding.
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
BARS = re.compile(
    r"WOLFOS_VIRTIO_GPU_BARS_OK common=(io|mem32|mem64) "
    r"notify=(io|mem32|mem64) isr=(io|mem32|mem64) "
    r"device=(io|mem32|mem64) cfg_writes=0 bar_probe_writes=0 mmio=0 dma=0"
)
SIZE = re.compile(
    r"WOLFOS_VIRTIO_GPU_BAR_SIZE_OK kind=(io|mem32|mem64) "
    r"bytes=([1-9][0-9]*) common_offset=([0-9]+) common_length=([1-9][0-9]*) "
    r"command_writes=2 bar_writes=(2|4) restored=1 decode_stopped=1 mmio=0 dma=0"
)
MMIO = re.compile(
    r"WOLFOS_VIRTIO_GPU_COMMON_MMIO_OK queues=([1-9][0-9]*) "
    r"status=([0-9]+) generation=([0-9]+) "
    r"ro=1 uc=1 pages=1 writes=0 dma=0"
)
DEVICE = re.compile(
    r"WOLFOS_VIRTIO_GPU_DEVICE_MMIO_OK scanouts=([1-9][0-9]*) "
    r"capsets=([0-9]+) events=([0-9]+) "
    r"ro=1 uc=1 pages=1 writes=0 dma=0"
)
PREFLIGHT = re.compile(
    r"WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_OK feature_select=0 "
    r"features=([0-9]+) edid=([01]) queue_select=0 queue_size=([1-9][0-9]*) "
    r"queue_enabled=0 status=0 ro=1 uc=1 pages=1 writes=0 dma=0"
)
FORBIDDEN = (
    "WOLFOS_VIRTIO_GPU_PCI_CAPS_FAIL",
    "WOLFOS_VIRTIO_GPU_BARS_FAIL", "bar_probe_writes=1", "mmio=1",
    "WOLFOS_VIRTIO_GPU_BAR_SIZE_FAIL",
    "WOLFOS_VIRTIO_GPU_BAR_SIZE_TEST_FAILED",
    "WOLFOS_VIRTIO_GPU_COMMON_MMIO_FAIL",
    "WOLFOS_VIRTIO_GPU_COMMON_MMIO_TEST_FAILED",
    "WOLFOS_VIRTIO_GPU_DEVICE_MMIO_FAIL",
    "WOLFOS_VIRTIO_GPU_DEVICE_MMIO_TEST_FAILED",
    "WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_FAIL",
    "WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_TEST_FAILED",
    "WOLFOS_VIRTIO_GPU_PCI_TEST_FAILED",
    "WOLFOS_GPU_DRIVER_LOADED", "WOLFOS_PANIC",
    "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_DF",
    "cfg_writes=1", "dma=1", "accel=1", "native_accel=1",
    "driver_loaded=1", "WOLFOS_PCI_TEST_FAILED",
)


def validate(output: str, exit_code: int, require_bars: bool = False,
             require_size: bool = False, require_mmio: bool = False,
             require_device: bool = False,
             require_preflight: bool = False) -> bool:
    require_device = require_device or require_preflight
    require_mmio = require_mmio or require_device
    require_size = require_size or require_mmio
    require_bars = require_bars or require_size
    rows = output.splitlines()
    if exit_code != 33 or rows.count("WOLFOS_BOOT_OK") != 1:
        return False
    if any(word in output for word in FORBIDDEN):
        return False
    gpu = [i for i, row in enumerate(rows) if GPU.fullmatch(row)]
    policy = [i for i, row in enumerate(rows) if row == POLICY]
    caps = [(i, CAPS.fullmatch(row)) for i, row in enumerate(rows)
            if row.startswith("WOLFOS_VIRTIO_GPU_PCI_CAPS_OK ")]
    bars = [(i, BARS.fullmatch(row)) for i, row in enumerate(rows)
            if row.startswith("WOLFOS_VIRTIO_GPU_BARS_OK ")]
    size = [(i, SIZE.fullmatch(row)) for i, row in enumerate(rows)
            if row.startswith("WOLFOS_VIRTIO_GPU_BAR_SIZE_OK ")]
    size_test = [i for i, row in enumerate(rows)
                 if row == "WOLFOS_VIRTIO_GPU_BAR_SIZE_TEST_OK"]
    mmio = [(i, MMIO.fullmatch(row)) for i, row in enumerate(rows)
            if row.startswith("WOLFOS_VIRTIO_GPU_COMMON_MMIO_OK ")]
    mmio_test = [i for i, row in enumerate(rows)
                 if row == "WOLFOS_VIRTIO_GPU_COMMON_MMIO_TEST_OK"]
    device = [(i, DEVICE.fullmatch(row)) for i, row in enumerate(rows)
              if row.startswith("WOLFOS_VIRTIO_GPU_DEVICE_MMIO_OK ")]
    device_test = [i for i, row in enumerate(rows)
                   if row == "WOLFOS_VIRTIO_GPU_DEVICE_MMIO_TEST_OK"]
    preflight = [(i, PREFLIGHT.fullmatch(row)) for i, row in enumerate(rows)
                 if row.startswith("WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_OK ")]
    preflight_test = [i for i, row in enumerate(rows)
                      if row == "WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_TEST_OK"]
    pci = [i for i, row in enumerate(rows) if row == "WOLFOS_PCI_TEST_OK"]
    proof = [i for i, row in enumerate(rows)
             if row == "WOLFOS_VIRTIO_GPU_PCI_TEST_OK"]
    fb = [i for i, row in enumerate(rows)
          if row.startswith("WOLFOS_FRAMEBUFFER_OK ")]
    if (len(gpu), len(policy), len(caps), len(pci), len(proof), len(fb)) != (1,1,1,1,1,1):
        return False
    if caps[0][1] is None:
        return False
    if require_bars and (len(bars) != 1 or bars[0][1] is None):
        return False
    if not require_bars and bars:
        return False
    if require_size and (len(size) != 1 or size[0][1] is None or len(size_test) != 1):
        return False
    if not require_size and (size or size_test):
        return False
    if require_mmio and (len(mmio) != 1 or mmio[0][1] is None or len(mmio_test) != 1):
        return False
    if not require_mmio and (mmio or mmio_test):
        return False
    if require_device and (len(device) != 1 or device[0][1] is None or len(device_test) != 1):
        return False
    if not require_device and (device or device_test):
        return False
    if require_preflight and (len(preflight) != 1 or preflight[0][1] is None
                             or len(preflight_test) != 1):
        return False
    if not require_preflight and (preflight or preflight_test):
        return False
    if not (gpu[0] < policy[0] < caps[0][0] < pci[0] < proof[0]
            < fb[0] < rows.index("WOLFOS_BOOT_OK")):
        return False
    if require_bars and not (caps[0][0] < bars[0][0] < pci[0]):
        return False
    if require_size:
        if not (bars[0][0] < size[0][0] < pci[0] < proof[0]
                < size_test[0] < fb[0]):
            return False
        parsed = size[0][1]
        kind, bytes_txt, offset_txt, length_txt, bar_writes = parsed.groups()
        bytes_count, offset, length = int(bytes_txt), int(offset_txt), int(length_txt)
        if (bytes_count & (bytes_count - 1)) != 0 or offset + length > bytes_count:
            return False
        if (kind == "mem64") != (bar_writes == "4"):
            return False
        if require_mmio:
            if kind == "io" or not (size_test[0] < mmio[0][0]
                                    < mmio_test[0] < fb[0]):
                return False
            queues, status, generation = map(int, mmio[0][1].groups())
            if not (1 <= queues <= 256 and 0 <= status <= 255
                    and status & ~0xcf == 0 and 0 <= generation <= 255):
                return False
            if length < 56:
                return False
            if require_device:
                if not (mmio_test[0] < device[0][0] < device_test[0] < fb[0]):
                    return False
                scanouts, capsets, events = map(int, device[0][1].groups())
                if not (1 <= scanouts <= 16 and
                        0 <= capsets <= 0xffffffff and events in (0, 1)):
                    return False
                if require_preflight:
                    if not (device_test[0] < preflight[0][0]
                            < preflight_test[0] < fb[0]):
                        return False
                    feature_bits, edid_bit, queue_size = map(
                        int, preflight[0][1].groups())
                    if not (0 <= feature_bits <= 0xffffffff and
                            int(bool(feature_bits & 2)) == edid_bit and
                            1 <= queue_size <= 32768):
                        return False
    # Capability BAR indices and nonzero notification multiplier are
    # validated by the genuine kernel parser. No driver binding claimed.
    return True


def main() -> int:
    if (len(sys.argv) not in (2, 3) or
            (len(sys.argv) == 3 and sys.argv[2] not in ("--bars", "--size", "--mmio", "--device", "--preflight")) or
            not Path(sys.argv[1]).is_file()):
        print("Usage: qemu_virtio_gpu_pci_smoke.py ISO [--bars|--size|--mmio|--device|--preflight]")
        return 2
    require_preflight = len(sys.argv) == 3 and sys.argv[2] == "--preflight"
    require_device = len(sys.argv) == 3 and sys.argv[2] in ("--device", "--preflight")
    require_mmio = len(sys.argv) == 3 and sys.argv[2] in ("--mmio", "--device", "--preflight")
    require_size = len(sys.argv) == 3 and sys.argv[2] in ("--size", "--mmio", "--device", "--preflight")
    require_bars = len(sys.argv) == 3
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
        if not validate(output, result.returncode,
                        require_bars=require_bars, require_size=require_size,
                        require_mmio=require_mmio,
                        require_device=require_device,
                        require_preflight=require_preflight):
            print(f"FAIL: no trustworthy virtio-vga PCI capability proof; exit={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        if require_preflight:
            print("PASS: genuine QEMU VirtIO common feature bank 0 and "
                  "control queue capacity inspected without MMIO writes or DMA.")
        elif require_device:
            print("PASS: genuine QEMU VirtIO GPU scanout/capset counts from "
                  "device-config RO page; restored, no DMA/physical GPU.")
        elif require_mmio:
            print("PASS: genuine QEMU virtio-vga one-page, non-cached RO common "
                  "register reads; mapping removed; no DMA or physical device.")
        elif require_size:
            print("PASS: genuine QEMU virtio-vga BAR-size probe with decode "
                  "disabled, command/BARs restored, no MMIO/DMA or physical device.")
        else:
            print("PASS: genuine QEMU virtio-vga 1af4:1050 PCI capabilities "
                  "read-only; no DMA/MMIO, driver load or physical GPU touched.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
