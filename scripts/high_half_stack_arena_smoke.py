#!/usr/bin/env python3
"""Real x86-64 two-PID high-half kernel guard arena (never live RSP0)."""
from pathlib import Path
import subprocess
import sys
import tempfile

BASE=[
    "WOLFOS_BOOT_OK",
    "WOLFOS_HIGH_STACK_ARENA_READY_OK pids=2 high_half=1 real_pmm_frames=11 guard_pages=4 private_leaf_pages=8",
    "WOLFOS_HIGH_STACK_ARENA_ISOLATED_OK distinct_rsp0=2 user_bit=0 physical_alias_denied=1 active_stacks=0",
]
FAULTS={
    "lower":("pid1_lower","0xffffd00000000000"),
    "upper":("pid2_upper","0xffffd0000000b000"),
}
def main():
    if len(sys.argv)!=3 or sys.argv[2] not in ("map","lower","upper"):
        print("Usage: high_half_stack_arena_smoke.py ISO map|lower|upper")
        return 2
    iso=Path(sys.argv[1])
    if not iso.is_file():
        print("FAIL: missing ISO");return 2
    mode=sys.argv[2]
    with tempfile.TemporaryDirectory(prefix="wolfos-high-arena-") as t:
        serial=Path(t)/"serial.log"
        cmd=[
            "qemu-system-x86_64","-M","q35","-m","512M","-smp","1",
            "-vga","std","-cdrom",str(iso.resolve()),
            "-boot","d","-serial",f"file:{serial}","-display","none",
            "-no-reboot","-device","isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run=subprocess.run(cmd,capture_output=True,timeout=60,check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: high-half guard QEMU timed out")
            if serial.exists(): print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU unavailable");return 2
        out=serial.read_text(errors="replace") if serial.exists() else ""
        print(out)
        checks=BASE.copy()
        if mode=="map":
            checks+=["WOLFOS_HIGH_STACK_ARENA_CLEANUP_OK physical_frames_freed=11 pmm_no_leak=1 tlb_flushed=12 boot_cr3_intact=1"]
            forbidden=["WOLFOS_HIGH_STACK_ARENA_PROBE_BEGIN",
                       "WOLFOS_EXCEPTION_PF vector=14"]
        else:
            side,addr=FAULTS[mode]
            checks+= [
                f"WOLFOS_HIGH_STACK_ARENA_PROBE_BEGIN side={side} address={addr}",
                f"WOLFOS_EXCEPTION_PF vector=14 address=Ok(VirtAddr({addr}))",
                f"WOLFOS_HIGH_STACK_ARENA_HARDWARE_OK side={side} nonpresent=1 supervisor=1 read=1",
            ]
            forbidden=["WOLFOS_HIGH_STACK_ARENA_CLEANUP_OK"]
        positions=[out.find(mark) for mark in checks]
        if any(x<0 for x in positions) or positions!=sorted(positions):
            print("FAIL: missing or wrong order high-half guard evidence")
            return 1
        if any(out.count(mark)!=1 for mark in checks):
            print("FAIL: duplicate evidence")
            return 1
        if any(f in out for f in (
            "WOLFOS_HIGH_STACK_ARENA_ERROR",
            "WOLFOS_EXCEPTION_DF","WOLFOS_EXCEPTION_GP","WOLFOS_PANIC",*forbidden
        )):
            print("FAIL: unexpected fault or error")
            return 1
        if run.returncode!=33:
            print("FAIL: expected QEMU debug-exit 33, got",run.returncode)
            print(run.stderr.decode(errors="replace"));return 1
        print("PASS: two separate high-half kernel guards, mode="+mode)
        return 0
if __name__=="__main__":
    sys.exit(main())
