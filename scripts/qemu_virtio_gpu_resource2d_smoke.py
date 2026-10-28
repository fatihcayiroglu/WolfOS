#!/usr/bin/env python3
"""Require real QEMU VirtIO-GPU CREATE_2D + UNREF after real GET_EDID.
Host-only 64x64 resource: no physical device/disk, backing or scanout writes.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from qemu_virtio_gpu_pci_smoke import validate as validate_gpu
from qemu_virtio_gpu_edid_live_smoke import validate_edid_marker

RESOURCE = re.compile(
    r"WOLFOS_VIRTIO_GPU_RESOURCE2D_OK resource_id=1 format=2 width=64 height=64 "
    r"create_type=257 unref_type=258 response_type=4352 used_idx=4 "
    r"used_head=0 used_len=24 fences_verified=2 notify_writes=4 "
    r"scanout_writes=0 attach_backing=0 reset=0 queue_disabled=1 "
    r"frames_allocated=5 frames_released=5 pmm_leak=0 qemu_only=1"
)
TEST_OK = "WOLFOS_VIRTIO_GPU_RESOURCE2D_TEST_OK"

def validate_resource_marker(output: str) -> bool:
    lines = output.splitlines()
    if any("WOLFOS_VIRTIO_GPU_RESOURCE2D_FAIL" in line for line in lines):
        return False
    if not validate_edid_marker(output):
        return False
    found = [(i, RESOURCE.fullmatch(line)) for i,line in enumerate(lines)
             if line.startswith("WOLFOS_VIRTIO_GPU_RESOURCE2D_OK ")]
    if len(found) != 1 or found[0][1] is None or lines.count(TEST_OK) != 1:
        return False
    resource_index=found[0][0]
    edid=[i for i,line in enumerate(lines)
          if line.startswith("WOLFOS_VIRTIO_GPU_EDID_LIVE_OK ")]
    display_acks=[i for i,line in enumerate(lines)
                  if line=="WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK"]
    edid_acks=[i for i,line in enumerate(lines)
               if line=="WOLFOS_VIRTIO_GPU_EDID_LIVE_TEST_OK"]
    return (len(edid)==len(display_acks)==len(edid_acks)==1
            and edid[0]<resource_index<display_acks[0]<edid_acks[0]
            <lines.index(TEST_OK))

def main() -> int:
    if len(sys.argv)!=2 or not Path(sys.argv[1]).is_file():
        print("Usage: qemu_virtio_gpu_resource2d_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-virtio-gpu-resource2d-") as work:
        serial=Path(work)/"serial.log"
        cmd=[
            "qemu-system-x86_64","-M","q35","-m","512M","-smp","1",
            "-vga","none","-device","virtio-vga",
            "-cdrom",str(Path(sys.argv[1]).resolve()),"-boot","d",
            "-serial",f"file:{serial}","-display","none","-no-reboot",
            "-device","isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            proc=subprocess.run(cmd,capture_output=True,timeout=90,check=False)
        except (FileNotFoundError,subprocess.TimeoutExpired) as error:
            print(f"FAIL: genuine QEMU 2D resource transaction: {error}")
            print(serial.read_text(errors="replace") if serial.exists() else "")
            return 1
        output=serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        if not validate_gpu(output,proc.returncode,require_display_info=True):
            print("FAIL: prerequisite genuine GPU transport/GET_DISPLAY_INFO proof")
            return 1
        if not validate_resource_marker(output):
            print("FAIL: real QEMU CREATE_2D + UNREF completion/reset proof")
            return 1
        print("PASS: real QEMU 2D create/unref, two fenced OK_NODATA completions, reset-before-free")
        return 0

if __name__=="__main__":
    sys.exit(main())
