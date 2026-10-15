#!/usr/bin/env python3
"""Genuine hardware CPL3 user->kernel->OTHER USER IRETQ cooperative switch.

Two separately linked ELF64 executables, separate private user CR3 roots,
four guarded TSS.RSP0 pages per PID, 512B FXSAVE64 per process, zero PMM
leaks. Intentionally single BSP IF=0 and volunteer syscall (no timer preemption).
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

STEPS=[
    "WOLFOS_BOOT_OK",
    "WOLFOS_RING_PREP_OK",
    "WOLFOS_RING3_YIELD_START_OK separate_native_elf=2 live_user_roots=2 guarded_kernel_rsp0=2 fx_images=2 owned_frames=25",
    "WOLFOS_RING3_YIELD_HARDWARE_OK native_elves=2 real_cpl3=1 total_traps=10 yields=8 exits=2 iret_cross_pid=9 separate_cr3=1 distinct_guarded_rsp0=1 xmm0_preserved=1",
    "WOLFOS_RING3_YIELD_CLEANUP_OK frames_freed=25 both_ELF_exited=1 fx_wiped=2 tss_restored=1 cr3_restored=1 pmm_no_leak=1",
]
ERRORS=[
    "WOLFOS_RING3_YIELD_ERROR","WOLFOS_PANIC",
    "WOLFOS_EXCEPTION_UD","WOLFOS_EXCEPTION_GP",
    "WOLFOS_EXCEPTION_PF","WOLFOS_EXCEPTION_DF",
]
def main():
    timer_observe = len(sys.argv)==3 and sys.argv[2]=="--timer-observe"
    irq_ready = len(sys.argv)==3 and sys.argv[2]=="--irq-ready"
    if len(sys.argv) not in (2,3) or (len(sys.argv)==3 and not (irq_ready or timer_observe)) or not Path(sys.argv[1]).is_file():
        print("Usage: user_yield_switch_smoke.py kernel.iso [--irq-ready|--timer-observe]")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-real-ring3-yield-") as temp:
        log=Path(temp)/"serial.log"
        cmd=[
            "qemu-system-x86_64","-M","q35","-m","512M","-smp","1",
            "-boot","d","-cdrom",str(Path(sys.argv[1]).resolve()),
            "-serial",f"file:{log}","-display","none","-no-reboot",
            "-device","isa-debug-exit,iobase=0xf4,iosize=0x04"
        ]
        try:
            r=subprocess.run(cmd,capture_output=True,timeout=70,check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: real Ring3 two-ELF cooperative switch timed out")
            if log.exists():print(log.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU unavailable")
            return 2
        out=log.read_text(errors="replace") if log.exists() else ""
        print(out)
        checks=STEPS.copy()
        if timer_observe:
            checks[2]=checks[2].replace("owned_frames=25","owned_frames=28")
            checks[-1]=checks[-1].replace("frames_freed=25","frames_freed=28")
            checks.insert(2,
                "WOLFOS_RING3_TIMER_HIGH_MMIO_OK uc=1 supervisor_only=1 inherited_cr3=2 eoi_high=1 owned_frames=28")
            checks.insert(3,
                "WOLFOS_RING3_TIMER_ARMED_OK real_local_apic=1 user_if=1 no_yield_busy_loops=2")
        if irq_ready or timer_observe:
            checks.insert(checks.index(STEPS[3]),
                "WOLFOS_RING3_IRQ_READY_OK actual_cpl3_if=1 hardware_int80_traps=10 pid_cr3_rsp0_fx_checks=10 pic_masked=1 timer_armed="+("1" if timer_observe else "0"))
            if timer_observe:
                checks.insert(checks.index(STEPS[3]),
                    "WOLFOS_RING3_TIMER_HARDWARE_OK")
                checks.insert(checks.index(STEPS[-1]),
                    "WOLFOS_RING3_TIMER_CLEANUP_OK actual_irq_eoi=1 lvt_masked=1 pic_restored=1 high_mmio_unmapped=1")
            checks.insert(checks.index(checks[-1]),
                "WOLFOS_RING3_IRQ_READY_RESTORE_OK original_pic_masks=1 kernel_if_off=1")
        else:
            if "WOLFOS_RING3_IRQ_READY_OK" in out or "WOLFOS_RING3_IRQ_READY_RESTORE_OK" in out:
                print("FAIL: interruptible guest evidence in IF=0 legacy flavor")
                return 1
        loc=[out.find(p) for p in checks]
        if any(x<0 for x in loc) or loc!=sorted(loc):
            print("FAIL: incomplete or out-of-order real native two-ELF proof")
            return 1
        if timer_observe:
            irq_line=next((line for line in out.splitlines()
                if line.startswith("WOLFOS_RING3_TIMER_HARDWARE_OK ")),None)
            hit=re.fullmatch(
                r"WOLFOS_RING3_TIMER_HARDWARE_OK real_apic_irqs=(\d+) pid1_busy_irqs=(\d+) pid2_busy_irqs=(\d+) eoi_each=1 real_user_if=1 yield_free_busy_windows=8 same_pid_iret=1",
                irq_line or "")
            if hit is None or any(int(n)<1 for n in hit.groups()) or int(hit.group(1))<int(hit.group(2))+int(hit.group(3)):
                print("FAIL: no real xAPIC timer interrupts during BOTH independent users' syscall-free busy windows")
                return 1
        if any(out.count(p)!=1 for p in checks):
            print("FAIL: duplicate evidence markers")
            return 1
        if any(x in out for x in ERRORS):
            print("FAIL: unexpected CPU exception or kernel safety failure")
            return 1
        yields=[l for l in out.splitlines()
            if l.startswith("WOLFOS_RING3_YIELD_TRAP pid=") and "kind=yield" in l]
        exits=[l for l in out.splitlines()
            if l.startswith("WOLFOS_RING3_YIELD_TRAP pid=") and "kind=exit" in l]
        switches=[l for l in out.splitlines()
            if l.startswith("WOLFOS_RING3_YIELD_SWITCH from=")]
        expected_yields=[
            f"WOLFOS_RING3_YIELD_TRAP pid={i%2+1} kind=yield count={i//2+1} cr3_private=1 rsp0_guarded=1"
            for i in range(8)
        ]
        if yields!=expected_yields:
            print("FAIL: real alternating user yields missing, duplicated or reordered")
            return 1
        if exits!=[
            "WOLFOS_RING3_YIELD_TRAP pid=1 kind=exit count=4 cr3_private=1 rsp0_guarded=1",
            "WOLFOS_RING3_YIELD_TRAP pid=2 kind=exit count=4 cr3_private=1 rsp0_guarded=1",
        ]:
            print("FAIL: user ELF exits not both from genuine private CPL3")
            return 1
        if len(switches)!=9 or any(
            l!=f"WOLFOS_RING3_YIELD_SWITCH from={i%2+1} to={(i+1)%2+1} private_cr3=1 tss_rsp0=1 fx_saved=1"
            for i,l in enumerate(switches)
        ):
            print("FAIL: 9 distinct cross-PID IRETQ paths not attested")
            return 1
        if r.returncode!=33:
            print("FAIL: expected QEMU debug-exit 33, got",r.returncode)
            print(r.stderr.decode(errors="replace"))
            return 1
        print("PASS: 2 native ELF Ring3 programs, 8 real INT80 yields, 9 cross-PID IRETQ handoffs, 2 exits, zero leaks; "+("genuine xAPIC timer IRQs in BOTH separate Ring3 busy windows" if timer_observe else "all ten CPL3 frames IF=1 and PIC masked" if irq_ready else "IF=0 legacy"))
        return 0
if __name__=="__main__":
    sys.exit(main())
