#!/usr/bin/env python3
"""BSP QEMU: 64 actual FXSAVE64/FXRSTOR64 switches between two PID images.

This is a legacy x87/XMM hardware-state proof, not a Ring3 process
scheduler, not XSAVE/AVX, and no live CR3/TSS switching.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

PROOFS=[
    "WOLFOS_BOOT_OK",
    "WOLFOS_USER_FX_READY_OK pids=2 owned_pmm_frames=14 images=2 fxsave_bytes=512 aligned=16 bsp_only=1",
    "WOLFOS_USER_FX_SWITCH_OK hardware_fxsave=1 hardware_fxrstor=1 alternations=64 xmm0_isolated=1 stale_restore_denied=1",
    "WOLFOS_USER_FX_CLEANUP_OK released_pmm_frames=14 fx_images_wiped=2 cr3_unchanged=1 bsp_fx_restored=1 no_leak=1 legacy_bytes=512 users_executed=0",
]
BAD=[
    "WOLFOS_USER_FX_ERROR", "WOLFOS_PANIC",
    "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_GP",
    "WOLFOS_EXCEPTION_UD", "WOLFOS_EXCEPTION_DF",
]
def main():
    if len(sys.argv)!=2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_fx_smoke.py path/to/ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-user-fx-") as tmp:
        serial=Path(tmp)/"serial.log"
        cmd=[
            "qemu-system-x86_64","-M","q35","-m","512M","-smp","1",
            "-cdrom",str(Path(sys.argv[1]).resolve()),
            "-boot","d","-serial",f"file:{serial}",
            "-display","none","-no-reboot",
            "-device","isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run=subprocess.run(cmd,timeout=55,capture_output=True,check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: user FX hardware state timed out")
            if serial.exists(): print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU unavailable")
            return 2
        output=serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        pos=[output.find(x) for x in PROOFS]
        if any(x<0 for x in pos) or pos!=sorted(pos):
            print("FAIL: missing or out-of-order PID FX proof")
            return 1
        if any(output.count(x)!=1 for x in PROOFS):
            print("FAIL: duplicate/missing FX success marker")
            return 1
        if any(f in output for f in BAD):
            print("FAIL: kernel fault or FX state mismatch")
            return 1
        if run.returncode!=33:
            print("FAIL: debug exit 33 required; got",run.returncode)
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: 64 live BSP FXSTATE save/restores, 2 separate PID images, zero PMM leaks")
        return 0
if __name__=="__main__":
    sys.exit(main())
