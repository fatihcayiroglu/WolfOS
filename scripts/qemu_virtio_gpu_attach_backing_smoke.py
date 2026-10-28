#!/usr/bin/env python3
"""QEMU-only real VirtIO GPU four-page ATTACH/DETACH and UNREF proof."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from qemu_virtio_gpu_pci_smoke import validate as validate_gpu, DISPLAY_INFO_NINE
from qemu_virtio_gpu_edid_live_smoke import validate_edid_marker

BACKING = re.compile(
    r"WOLFOS_VIRTIO_GPU_ATTACH_BACKING_OK resource_id=1 format=2 width=64 height=64 "
    r"create_type=257 attach_type=262 detach_type=263 unref_type=258 "
    r"response_type=4352 used_idx=6 used_head=0 used_len=24 "
    r"fences_verified=4 notify_writes=6 backing_entries=4 backing_bytes=16384 "
    r"pages_zeroed=4 attach_ack=1 detach_ack=1 unref_ack=1 "
    r"transfer_writes=0 scanout_writes=0 reset=0 queue_disabled=1 "
    r"frames_allocated=9 frames_released=9 pmm_leak=0 qemu_only=1"
)
TEST_OK = "WOLFOS_VIRTIO_GPU_ATTACH_BACKING_TEST_OK"

def validate_backing_marker(output: str) -> bool:
    rows = output.splitlines()
    if any("WOLFOS_VIRTIO_GPU_RESOURCE2D_FAIL" in row
           or "WOLFOS_VIRTIO_GPU_ATTACH_BACKING_FAIL" in row
           or "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL" in row
           for row in rows):
        return False
    if not validate_edid_marker(output, frame_count=9):
        return False
    display = [DISPLAY_INFO_NINE.fullmatch(row) for row in rows
               if row.startswith("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK ")]
    if len(display)!=1 or display[0] is None:
        return False
    found = [(i, BACKING.fullmatch(row)) for i,row in enumerate(rows)
             if row.startswith("WOLFOS_VIRTIO_GPU_ATTACH_BACKING_OK ")]
    if len(found)!=1 or found[0][1] is None or rows.count(TEST_OK)!=1:
        return False
    if any(row.startswith("WOLFOS_VIRTIO_GPU_RESOURCE2D_OK ")
           or row=="WOLFOS_VIRTIO_GPU_RESOURCE2D_TEST_OK" for row in rows):
        return False
    edid = [i for i,row in enumerate(rows)
            if row.startswith("WOLFOS_VIRTIO_GPU_EDID_LIVE_OK ")]
    display_ack = [i for i,row in enumerate(rows)
                   if row=="WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK"]
    edid_ack = [i for i,row in enumerate(rows)
                if row=="WOLFOS_VIRTIO_GPU_EDID_LIVE_TEST_OK"]
    return (len(edid)==len(display_ack)==len(edid_ack)==1
            and edid[0]<found[0][0]<display_ack[0]<edid_ack[0]
            <rows.index(TEST_OK))

def main() -> int:
    if len(sys.argv)!=2 or not Path(sys.argv[1]).is_file():
        print("Usage: qemu_virtio_gpu_attach_backing_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-virtio-gpu-backing-") as work:
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
            print(f"FAIL: real QEMU four-page backing lifecycle: {error}")
            print(serial.read_text(errors="replace") if serial.exists() else "")
            return 1
        output=serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        if not validate_gpu(output,proc.returncode,require_display_info=True,
                            display_frames=9):
            print("FAIL: prerequisite genuine GPU transport/display proof")
            return 1
        if not validate_backing_marker(output):
            print("FAIL: real QEMU attach/detach/unref acknowledgements/reset proof")
            return 1
        print("PASS: QEMU 64x64 backing attach/detach/unref, four fenced replies, reset-before-free")
        return 0

if __name__=="__main__":
    sys.exit(main())
