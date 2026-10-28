#!/usr/bin/env python3
"""Require *genuine* QEMU VirtIO GPU GET_DISPLAY_INFO + GET_EDID responses.
No physical GPU, no disks, no synthetic response injected by this script.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from qemu_virtio_gpu_pci_smoke import validate as validate_gpu

EDID = re.compile(
    r"WOLFOS_VIRTIO_GPU_EDID_LIVE_OK scanout=0 edid_size=([0-9]+) "
    r"modes=([0-9]+) preferred_width=([0-9]+) preferred_height=([0-9]+) "
    r"refresh_millihz=([0-9]+) used_idx=2 used_head=0 used_len=1056 "
    r"fence_verified=1 negotiated_edid=1 notify_writes=2 driver_ok=15 "
    r"reset=0 queue_disabled=1 frames_allocated=5 frames_released=5 "
    r"pmm_leak=0 qemu_only=1"
)
TEST_OK = "WOLFOS_VIRTIO_GPU_EDID_LIVE_TEST_OK"

def validate_edid_marker(output: str) -> bool:
    lines = output.splitlines()
    if any("WOLFOS_VIRTIO_GPU_EDID_LIVE_FAIL" in line for line in lines):
        return False
    matches = [(i, EDID.fullmatch(line)) for i, line in enumerate(lines)
               if line.startswith("WOLFOS_VIRTIO_GPU_EDID_LIVE_OK ")]
    if len(matches) != 1 or matches[0][1] is None:
        return False
    if lines.count(TEST_OK) != 1:
        return False
    index, match = matches[0]
    size, count, width, height, mhz = map(int, match.groups())
    if size < 128 or size > 1024 or size % 128 != 0:
        return False
    if not 1 <= count <= 16 or not 1 <= width <= 8192 or not 1 <= height <= 8192:
        return False
    if not 1000 <= mhz <= 1_000_000:
        return False
    # Prior command must genuinely complete first, and both proofs must
    # precede the kernel's test acknowledgements.
    display_indices = [i for i,line in enumerate(lines)
                       if line.startswith("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK ")]
    display_ok_indices = [i for i,line in enumerate(lines)
                          if line == "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK"]
    test_index = lines.index(TEST_OK)
    return (len(display_indices) == len(display_ok_indices) == 1
            and display_indices[0] < index < display_ok_indices[0] < test_index)

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: qemu_virtio_gpu_edid_live_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-virtio-gpu-edid-") as work:
        serial = Path(work) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "none", "-device", "virtio-vga",
            "-cdrom", str(Path(sys.argv[1]).resolve()), "-boot", "d",
            "-serial", f"file:{serial}", "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(cmd,capture_output=True,timeout=90,check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            print(f"FAIL: genuine QEMU GET_EDID run: {error}")
            print(serial.read_text(errors="replace") if serial.exists() else "")
            return 1
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        if not validate_gpu(output,result.returncode,require_display_info=True):
            print("FAIL: prerequisite real QEMU GPU/GET_DISPLAY_INFO proof missing")
            return 1
        if not validate_edid_marker(output):
            print("FAIL: strict second GET_EDID DMA/EDID/reset proof missing")
            return 1
        print("PASS: two real QEMU GPU responses, EDID timings validated, reset-before-free")
        return 0

if __name__=="__main__":
    sys.exit(main())
