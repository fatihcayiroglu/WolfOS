#!/usr/bin/env python3
"""Real QEMU CPU-only bounded graphics command queue framebuffer proof."""
from pathlib import Path
import subprocess
import sys
import tempfile
from qemu_vbe_mode_rollback_smoke import validate as validate_mode

MARKER=(
    "WOLFOS_GPU_SW_QUEUE_OK pci=1234:1111 size=1280x800 pitch=5120 "
    "submissions=2 commands=4 last_fence=2 overlap_copy=1 "
    "untouched_pixel=1 pixels_restored=1 native_accel=0"
)
FORBIDDEN=("WOLFOS_GPU_SW_QUEUE_FAIL","WOLFOS_GPU_SW_QUEUE_TEST_FAILED",
           "WOLFOS_GPU_DRIVER_LOADED","WOLFOS_PANIC")

def validate(output:str, exit_code:int)->bool:
    if not validate_mode(output,exit_code):
        return False
    if any(flag in output for flag in FORBIDDEN):
        return False
    rows=output.splitlines()
    markers=[i for i,row in enumerate(rows)
             if row.startswith("WOLFOS_GPU_SW_QUEUE_OK")]
    mode=[i for i,row in enumerate(rows)
          if row.startswith("WOLFOS_QEMU_VBE_MODE_ROLLBACK_OK ")]
    fb=[i for i,row in enumerate(rows)
        if row.startswith("WOLFOS_FB_TEXT_OK ")]
    boot=[i for i,row in enumerate(rows) if row=="WOLFOS_BOOT_OK"]
    return (len(markers)==1 and len(mode)==1 and len(fb)==1
            and len(boot)==1 and rows[markers[0]]==MARKER
            and mode[0]<markers[0]<fb[0]<boot[0])

def main()->int:
    if len(sys.argv)!=2 or not Path(sys.argv[1]).is_file():
        print("Usage: qemu_gpu_sw_queue_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-gpu-sw-queue-") as d:
        logfile=Path(d)/"serial.log"
        cmd=["qemu-system-x86_64","-M","q35","-m","512M","-smp","1",
             "-vga","std","-cdrom",str(Path(sys.argv[1]).resolve()),
             "-boot","d","-serial",f"file:{logfile}","-display","none",
             "-no-reboot","-device","isa-debug-exit,iobase=0xf4,iosize=0x04"]
        try:
            result=subprocess.run(cmd,capture_output=True,timeout=65,check=False)
        except (subprocess.TimeoutExpired,FileNotFoundError) as exc:
            print(f"FAIL: QEMU GPU software queue: {exc}")
            if logfile.exists(): print(logfile.read_text(errors="replace"))
            return 1
        output=logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if not validate(output,result.returncode):
            print(f"FAIL: QEMU CPU-only GPU queue evidence, exit={result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: real QEMU framebuffer fill+overlap copy through bounded "
              "CPU software queue, two synchronous fences and exact pixel restore.")
    return 0

if __name__=="__main__":
    sys.exit(main())
