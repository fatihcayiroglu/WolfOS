#!/usr/bin/env python3
"""Isolated QEMU: real BSP CR3 + loaded TSS.RSP0 + FX handoff, 2 READY PIDs.
No actual user instruction, IRETQ, interrupt-time scheduler or TSS stack use.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

MARKERS=[
    "WOLFOS_BOOT_OK",
    "WOLFOS_RING_PREP_OK",
    "WOLFOS_HANDOFF_SETUP_OK ready_pids=2 private_roots=2 guarded_rsp0=2 fx_images=2 real_pmm_frames=25",
    "WOLFOS_HANDOFF_HARDWARE_OK rounds=64 real_cr3_writes=128 real_tss_rsp0=64 real_fx_switches=64 gpr_plan=64 cpl3_executions=0",
    "WOLFOS_HANDOFF_CLEANUP_OK frames_freed=25 cr3_restored=1 tss_restored=1 fx_restored=1 stale_pids_revoked=1 pmm_leak=0",
]
FORBIDDEN=[
    "WOLFOS_HANDOFF_ERROR","WOLFOS_RING_PREP_ERROR",
    "WOLFOS_EXCEPTION_PF","WOLFOS_EXCEPTION_GP",
    "WOLFOS_EXCEPTION_DF","WOLFOS_EXCEPTION_UD","WOLFOS_PANIC",
]

def main():
    if len(sys.argv)!=2 or not Path(sys.argv[1]).is_file():
        print("Usage: handoff_preflight_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-cr3-tss-fx-") as temp:
        serial=Path(temp)/"serial.log"
        cmd=[
            "qemu-system-x86_64","-M","q35","-m","512M","-smp","1",
            "-cdrom",str(Path(sys.argv[1]).resolve()),"-boot","d",
            "-serial",f"file:{serial}","-display","none","-no-reboot",
            "-device","isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run=subprocess.run(cmd,check=False,capture_output=True,timeout=60)
        except subprocess.TimeoutExpired:
            print("FAIL: synchronized CR3/TSS/FX handoff timed out")
            if serial.exists():print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU missing")
            return 2
        out=serial.read_text(errors="replace") if serial.exists() else ""
        print(out)
        positions=[out.find(x) for x in MARKERS]
        if any(x<0 for x in positions) or positions!=sorted(positions):
            print("FAIL: missing or unordered CR3/TSS/FX hardware proofs")
            return 1
        if any(out.count(m)!=1 for m in MARKERS):
            print("FAIL: duplicate marker")
            return 1
        if any(x in out for x in FORBIDDEN):
            print("FAIL: unsafe handoff or CPU exception")
            return 1
        if run.returncode!=33:
            print(f"FAIL: expected QEMU exit 33, got {run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: 64 checked real CPU CR3/TSS/FX handoffs, 25 PMM frames reclaimed; Ring3 scheduling NOT implemented")
        return 0

if __name__=="__main__":
    sys.exit(main())
