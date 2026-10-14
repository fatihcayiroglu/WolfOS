#!/usr/bin/env python3
"""Exercise real BSP-local xAPIC timer IRQ and EOI in 1- and 4-vCPU QEMU."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def exercise(iso: Path, cpus: int, calibrated: bool) -> bool:
    with tempfile.TemporaryDirectory(prefix=f"wolfos-apic-timer-{cpus}cpu-") as tmp:
        serial = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", str(cpus), "-vga", "std", "-cdrom", str(iso.resolve()),
            "-boot", "d", "-serial", f"file:{serial}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=45, check=False)
        except subprocess.TimeoutExpired:
            print(f"FAIL: APIC timer QEMU test timed out ({cpus} CPUs)")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return False
        except FileNotFoundError:
            print("FAIL: QEMU missing")
            return False
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(f"=== xAPIC hardware smoke ({cpus} CPUs) ===")
        print(output)
        if f"WOLFOS_SMP_APS_OK total={cpus} " not in output:
            print(f"FAIL: {cpus}-CPU SMP completion marker missing")
            print(run.stderr.decode(errors="replace"))
            return False
        if calibrated:
            calibration = re.search(
                r"WOLFOS_APIC_CALIBRATION_OK effective_hz=(\d+) initial_count=(\d+) pit_hz=(\d+) pit_ticks=(\d+) divisor=(\d+) target_hz=(\d+)",
                output,
            )
            if calibration is None:
                print("FAIL: PIT2-to-xAPIC hardware calibration marker missing")
                return False
            effective_hz, initial_count, pit_hz, pit_ticks, divisor, target = (
                map(int, calibration.groups())
            )
            if (
                not 1_000 <= effective_hz <= 1_000_000_000
                or initial_count == 0 or pit_hz != 1_193_182
                or pit_ticks != 23_864 or divisor != 16 or target != 100
                or abs(initial_count * target - effective_hz) > target
            ):
                print(f"FAIL: invalid calibration result: {calibration.groups()}")
                return False
            if f"WOLFOS_APIC_TIMER_BEGIN vector=224 count={initial_count} " not in output:
                print("FAIL: calibrated count was not programmed into periodic timer")
                return False
        if "WOLFOS_APIC_TIMER_BEGIN vector=224" not in output:
            print("FAIL: APIC timer hardware start marker missing")
            print(run.stderr.decode(errors="replace"))
            return False
        # Four or more hardware timer IRQs must interrupt a non-yielding
        # BSP function; the first architectural frame is captured read-only.
        frame = re.search(
            r"WOLFOS_APIC_IRQ_FRAME_OK busy_irqs=(\d+) work_steps=(\d+) irq_step=(\d+) rip=0x([0-9a-f]+) rsp=0x([0-9a-f]+) cs=0x([0-9a-f]+) rflags=0x([0-9a-f]+) preemptive=(\d+)",
            output,
        )
        if frame is None:
            print("FAIL: no genuine IRQ-frame snapshot during non-yielding work")
            return False
        busy_irqs, work, irq_step = map(int, frame.groups()[:3])
        rip, rsp, cs, rflags = (int(field, 16) for field in frame.groups()[3:7])
        preemptive = int(frame.group(8))
        if (
            busy_irqs < 4 or work <= irq_step or irq_step == 0
            or rip == 0 or rsp == 0 or rsp % 8 != 0
            or cs == 0 or cs & 3 or rflags & 0x202 != 0x202
            or preemptive != 0
        ):
            print(f"FAIL: invalid interrupted-worker frame evidence: {frame.groups()}")
            return False
        task_proof = re.search(
            r"WOLFOS_APIC_TIMER_TASKS_OK threads=(\d+) dispatches=(\d+) switches=(\d+) stack_kib=(\d+) gated_by_irq=(\d+) preemptive=(\d+)",
            output,
        )
        if task_proof is None or tuple(map(int, task_proof.groups())) != (2, 6, 12, 16, 1, 0):
            print("FAIL: xAPIC tick-gated cooperative context proof absent/invalid")
            return False
        match = re.search(
            r"WOLFOS_APIC_TIMER_IRQ_OK vector=(\d+) ticks=(\d+) eoi=(\d+) spurious=(\d+) preemptive=(\d+)",
            output,
        )
        if match is None:
            print("FAIL: APIC timer hardware completion marker missing")
            print(run.stderr.decode(errors="replace"))
            return False
        vector, ticks, eoi, spurious, preemptive = map(int, match.groups())
        if vector != 224 or ticks < 4 or eoi != ticks or preemptive != 0:
            print(f"FAIL: invalid delivery/EOI evidence: {match.groups()}")
            return False
        asm = re.search(
            r"WOLFOS_APIC_ASM_TRAP_OK frames=(\d+) gprs=(\d+) iretq=(\d+) same_task=(\d+) invalid=(\d+) preemptive=(\d+)",
            output,
        )
        if asm is None:
            print("FAIL: real all-GPR xAPIC IRQ assembly entry and IRETQ proof missing")
            return False
        frames, gprs, iretq, same_task, invalid, asm_preemptive = map(int, asm.groups())
        if (frames != ticks or frames != eoi or gprs != 15 or iretq != 1
            or same_task != 1 or invalid != 0 or asm_preemptive != 0):
            print(f"FAIL: assembly GPR/trap return proof invalid: {asm.groups()}")
            return False
        if "WOLFOS_BOOT_OK" not in output or run.returncode != 33:
            print(f"FAIL: boot did not finish successfully: exit={run.returncode}")
            return False
        if any(s in output for s in (
            "WOLFOS_APIC_TIMER_ERROR", "WOLFOS_APIC_TIMER_TEST_FAILED",
            "WOLFOS_APIC_IRQ_FRAME_ERROR",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF", "WOLFOS_PANIC",
        )):
            print("FAIL: fatal APIC-related kernel diagnostic")
            return False
        print(
            f"PASS: {cpus} CPUs; BSP xAPIC IRQs={ticks}, EOIs={eoi}, "
            f"spurious={spurious}; no preemption asserted"
        )
        return True


def main() -> int:
    calibrated = len(sys.argv) == 3 and sys.argv[2] == "--calibrated"
    if (len(sys.argv) not in (2, 3) or
        (len(sys.argv) == 3 and not calibrated) or
        not Path(sys.argv[1]).is_file()):
        print("Usage: apic_timer_smoke.py ISO [--calibrated]")
        return 2
    iso = Path(sys.argv[1])
    for cpus in (1, 4):
        if not exercise(iso, cpus, calibrated):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
