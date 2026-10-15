#!/usr/bin/env python3
"""Disposable QEMU: absent lower/upper stack PTE yields real supervisor #PF.

'map' also checks full PMM reclaim after unmapping all four real leaves and
all three PMM page-table frames. Never claim HHDM alias is guarded.
"""
from pathlib import Path
import subprocess
import sys
import tempfile

BASE = [
    "WOLFOS_BOOT_OK",
    "WOLFOS_STACK_GUARD_MAP_OK mapped_pages=4 physical_leaf_pages=4 table_pages=3 guard_pages=2 supervisor=1 user=0",
]
ADDR = {"lower":"0x500000000000","upper":"0x500000005000"}

def main() -> int:
    if len(sys.argv) != 3 or sys.argv[2] not in ("map","lower","upper"):
        print("Usage: kernel_stack_guard_smoke.py ISO map|lower|upper")
        return 2
    iso=Path(sys.argv[1])
    mode=sys.argv[2]
    if not iso.is_file():
        print("FAIL: missing ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-guard-") as tmp:
        log=Path(tmp)/"serial.log"
        cmd=["qemu-system-x86_64","-M","q35","-m","512M",
             "-smp","1","-vga","std","-cdrom",str(iso.resolve()),
             "-boot","d","-serial",f"file:{log}",
             "-display","none","-no-reboot",
             "-device","isa-debug-exit,iobase=0xf4,iosize=0x04"]
        try:
            run=subprocess.run(cmd,capture_output=True,timeout=60,check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: guard QEMU timed out")
            if log.exists(): print(log.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU unavailable")
            return 2
        output=log.read_text(errors="replace") if log.exists() else ""
        print(output)
        markers=BASE.copy()
        if mode=="map":
            markers.append(
                "WOLFOS_STACK_GUARD_REAP_OK physical_frames_freed=7 pmm_no_leak=1 boot_cr3_intact=1 tlb_flushed=1")
            forbids=["WOLFOS_STACK_GUARD_PROBE_BEGIN","WOLFOS_EXCEPTION_PF vector=14"]
        else:
            addr=ADDR[mode]
            markers.extend([
                f"WOLFOS_STACK_GUARD_PROBE_BEGIN side={mode} address={addr} expected_pf=nonpresent_supervisor_read",
                f"WOLFOS_EXCEPTION_PF vector=14 address=Ok(VirtAddr({addr}))",
                f"WOLFOS_STACK_GUARD_HARDWARE_OK side={mode} nonpresent=1 supervisor=1 read=1",
            ])
            forbids=["WOLFOS_STACK_GUARD_REAP_OK"]
        positions=[output.find(x) for x in markers]
        if any(x<0 for x in positions) or positions != sorted(positions):
            print("FAIL: missing/out-of-order hardware guard evidence")
            return 1
        if any(output.count(x)!=1 for x in markers):
            print("FAIL: duplicate or missing guard marker")
            return 1
        if any(s in output for s in (
            "WOLFOS_STACK_GUARD_ERROR",
            "WOLFOS_EXCEPTION_GP","WOLFOS_EXCEPTION_DF","WOLFOS_PANIC",
            "WOLFOS_PAGING_FAULT_OK",*forbids)):
            print("FAIL: unapproved fault or unexpected guard result")
            return 1
        if run.returncode != 33:
            print("FAIL: QEMU exit expected 33, got",run.returncode)
            print(run.stderr.decode(errors="replace"))
            return 1
        print(f"PASS: {mode} real x86-64 stack guard mapping/fault acceptance")
        return 0

if __name__=="__main__":
    sys.exit(main())
