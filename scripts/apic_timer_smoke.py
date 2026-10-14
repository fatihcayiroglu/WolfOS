#!/usr/bin/env python3
"""Exercise real BSP-local xAPIC timer IRQ and EOI in 1- and 4-vCPU QEMU."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def exercise(iso: Path, cpus: int, calibrated: bool, preemptive: bool) -> bool:
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
        gpr = re.search(
            r"WOLFOS_APIC_GPR_OK samples=(\d+) matches=(\d+) mismatches=(\d+) restored=(\d+)",
            output,
        )
        if gpr is None:
            print("FAIL: no live 15-GPR preservation evidence from assembly probe")
            return False
        samples, matches, mismatches, restored = map(int, gpr.groups())
        if samples < 4 or matches != samples or mismatches or restored != 1:
            print(f"FAIL: IRQ did not preserve all fifteen live GPRs: {gpr.groups()}")
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
        frame_preemptive = int(frame.group(8))
        if (
            busy_irqs < 4 or work <= irq_step or irq_step == 0
            or rip == 0 or rsp == 0 or rsp % 8 != 0
            or cs == 0 or cs & 3 or rflags & 0x202 != 0x202
            or frame_preemptive != 0
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
        vector, ticks, eoi, spurious, irq_preemptive = map(int, match.groups())
        if (vector != 224 or ticks < 4 or eoi != ticks
            or irq_preemptive != int(preemptive)):
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
        expected_preemption = int(preemptive)
        if (frames != ticks or frames != eoi or gprs != 15 or iretq != 1
            or same_task != 1 - expected_preemption or invalid != 0
            or asm_preemptive != expected_preemption):
            print(f"FAIL: assembly GPR/trap return proof invalid: {asm.groups()}")
            return False
        if preemptive:
            handoff = re.search(
                r"WOLFOS_APIC_PREEMPT_OK tasks=(\d+) involuntary_switches=(\d+) task0_irqs=(\d+) task1_irqs=(\d+) task2_irqs=(\d+) work0=(\d+) work1=(\d+) work2=(\d+) exit_task=(\d+) rejected=(\d+) stack_kib=(\d+) bsp_only=(\d+) user_mode=(\d+) deferred=(\d+) nested=(\d+) guard_depth=(\d+) fairness_max_delta=(\d+)",
                output,
            )
            if handoff is None:
                print("FAIL: three-task kernel IRQ round-robin proof marker missing")
                return False
            (tasks, switches, a_irq, b_irq, c_irq, work0, work1, work2,
             exit_task, rejected, stack_kib, bsp, userspace, deferred,
             nested, depth, fairness_max_delta) = map(int, handoff.groups())
            if (tasks != 3 or switches < 36
                or min(a_irq, b_irq, c_irq) < 4
                or a_irq + b_irq + c_irq != switches
                or not all((work0, work1, work2))
                or exit_task not in (0, 1, 2) or rejected != 0
                or stack_kib != 16 or bsp != 1 or userspace != 0
                or deferred < 4 or nested != 1 or depth != 0
                or fairness_max_delta > 1):
                print(f"FAIL: invalid three-task IRQ fairness evidence: {handoff.groups()}")
                return False
            lifecycle = re.search(
                r"WOLFOS_APIC_BLOCK_WAKE_OK task=(\d+) blocked_irqs=(\d+) frozen_samples=(\d+) skipped=(\d+) attempts=(\d+) wakes=(\d+) resumed=(\d+) errors=(\d+) frozen_work=(\d+) postwake0=(\d+) postwake1=(\d+) postwake2=(\d+) stack_resumed=(\d+)",
                output,
            )
            if lifecycle is None:
                print("FAIL: missing hardware-observed Blocked -> Ready -> Resumed lifecycle")
                return False
            (blocked_task, blocked_irqs, frozen, skips, attempts, wakes,
             resumed, lifecycle_errors, frozen_work, post0, post1,
             post2, stack_resumed) = map(int, lifecycle.groups())
            if (blocked_task != 1 or blocked_irqs < 6
                or frozen != blocked_irqs or skips < 2
                or attempts != 1 or wakes != 1 or resumed != 1
                or lifecycle_errors != 0 or frozen_work == 0
                or stack_resumed != 1
                or min(post0, post1, post2) < 4
                or max(post0, post1, post2) - min(post0, post1, post2) > 1
                or fairness_max_delta != max(post0, post1, post2) - min(post0, post1, post2)):
                print(f"FAIL: blocked task advanced before wake, did not resume, or post-wake RR unfair: {lifecycle.groups()}")
                return False
            finished = re.search(
                r"WOLFOS_APIC_FINISHED_OK task=(\d+) mask=(\d+) ready=(\d+) finish=(\d+) frozen_irqs=(\d+) skipped=(\d+) errors=(\d+) frozen_work=(\d+) survivor0=(\d+) survivor1=(\d+) never_rescheduled=(\d+) fx_still_owned=(\d+)",
                output,
            )
            if finished is None:
                print("FAIL: no real-IRQ Finished task retirement evidence")
                return False
            (finished_task, finished_mask, ready_mask, finish_count,
             freeze_irqs, finish_skips, finish_errors, finished_work,
             survivor0, survivor1, never_rescheduled, fx_still_owned) = map(
                int, finished.groups()
            )
            if (finished_task != 2 or finished_mask != 4 or ready_mask != 3
                or finish_count != 1 or freeze_irqs < 6 or finish_skips < 2
                or finish_errors != 0 or finished_work == 0
                or survivor0 < 4 or survivor1 < 4
                or abs(survivor0 - survivor1) > 1
                or never_rescheduled != 1 or fx_still_owned != 1):
                print(f"FAIL: task marked Finished was rescheduled, progressed or revived: {finished.groups()}")
                return False
            recycle = re.search(
                r"WOLFOS_APIC_RECYCLE_OK task=(\d+) old_gen=(\d+) new_gen=(\d+) scrubbed_kib=(\d+) fx_bytes=(\d+) fx_scrub=(\d+) fx_reseed=(\d+) prior_xmm0=0x([0-9a-f]+) stale=(\d+) early_denied=(\d+) grace_denied=(\d+) frame_valid=(\d+) runnable=(\d+) bsp_only=(\d+) executed_new_task=(\d+)",
                output,
            )
            if recycle is None:
                print("FAIL: quiescent finished-slot stack/FX recycling proof missing")
                return False
            (slot, old_generation, new_generation, stack_kib, fx_size,
             fx_scrub, fx_reseed, old_xmm_hex, stale_rejected,
             premature_rejected, grace_rejected, frame_valid,
             runnable, bsp_only, new_task_executed) = recycle.groups()
            (slot, old_generation, new_generation, stack_kib, fx_size,
             fx_scrub, fx_reseed, stale_rejected, premature_rejected,
             grace_rejected, frame_valid, runnable,
             bsp_only, new_task_executed) = map(
                int, (slot, old_generation, new_generation, stack_kib, fx_size,
                      fx_scrub, fx_reseed, stale_rejected, premature_rejected,
                      grace_rejected, frame_valid, runnable, bsp_only,
                      new_task_executed)
            )
            if (slot != 2 or old_generation < 1
                or new_generation != old_generation + 1
                or stack_kib != 16 or fx_size != 512
                or fx_scrub != 1 or fx_reseed != 1
                or int(old_xmm_hex, 16) != 0x0f0e0d0c0b0a0908
                or stale_rejected != 1 or premature_rejected != 1
                or grace_rejected != 1 or frame_valid != 1
                or runnable != 0 or bsp_only != 1
                or new_task_executed != 0):
                print(f"FAIL: recycled stack/FX or generation ownership unsafe: {recycle.groups()}")
                return False
            executed = re.search(
                r"WOLFOS_APIC_REUSE_EXEC_OK task=(\d+) old_gen=(\d+) new_gen=(\d+) via_iretq=(\d+) entry_r12=0x([0-9a-f]+) entry_r15=0x([0-9a-f]+) irq=(\d+) work=(\d+) first_irq_work=(\d+) xmm_initial=0x([0-9a-f]+) xmm_final=0x([0-9a-f]+) xmm_old=0x([0-9a-f]+) corrupt=(\d+) stale=(\d+) finished_new=(\d+) ready=(\d+) bsp_only=(\d+)",
                output,
            )
            if executed is None:
                print("FAIL: second-generation task2 never entered actual IRETQ worker")
                return False
            (task_id, old_gen, new_gen, via_iretq, r12_hex, r15_hex,
             worker_irqs, worker_work, first_irq_work,
             xmm_initial_hex, xmm_final_hex, xmm_old_hex,
             corrupt, stale, finished_new, ready, bsp_only) = executed.groups()
            (task_id, old_gen, new_gen, via_iretq,
             worker_irqs, worker_work, first_irq_work,
             corrupt, stale, finished_new, ready, bsp_only) = map(
                int, (task_id, old_gen, new_gen, via_iretq,
                      worker_irqs, worker_work, first_irq_work,
                      corrupt, stale, finished_new, ready, bsp_only)
            )
            xmm_initial = int(xmm_initial_hex, 16)
            xmm_final = int(xmm_final_hex, 16)
            xmm_old = int(xmm_old_hex, 16)
            if (task_id != 2 or old_gen != old_generation
                or new_gen != new_generation or via_iretq != 1
                or int(r12_hex, 16) != 0x12345678cafef001
                or int(r15_hex, 16) != 0xfaceb00c76543210
                or worker_irqs < 4 or first_irq_work <= 0
                or worker_work <= first_irq_work + 512
                or xmm_initial == xmm_old
                or xmm_old != 0x0f0e0d0c0b0a0908
                or xmm_final != 0xa55af00d9e37cafe
                or corrupt != 0 or stale != 1 or finished_new != 1
                or ready != 0 or bsp_only != 1):
                print(f"FAIL: recycled task ran with stale GPR/SSE or no real IRQs: {executed.groups()}")
                return False
            fx = re.search(
                r"WOLFOS_APIC_FXSTATE_OK format=fxsave64 bytes=(\d+) xmm0=(\d+) fx_switches=(\d+) fx_observations=(\d+) work_checks=(\d+) corrupt=(\d+) original_restored=(\d+) avx=(\d+)",
                output,
            )
            if fx is None:
                print("FAIL: three private task FX images not observed")
                return False
            fx_bytes, fx_tasks, fx_switches, fx_observations, work_checks, bad, restored, avx = map(
                int, fx.groups()
            )
            if (fx_bytes != 512 or fx_tasks != 3 or fx_switches != switches
                or fx_observations < 11 or work_checks < 3 or bad != 0
                or restored != 1 or avx != 0):
                print(f"FAIL: x87/SSE state corrupted in three-task preemption: {fx.groups()}")
                return False
        elif "WOLFOS_APIC_PREEMPT_OK" in output:
            print("FAIL: normal APIC smoke unexpectedly claims task preemption")
            return False
        if "WOLFOS_BOOT_OK" not in output or run.returncode != 33:
            print(f"FAIL: boot did not finish successfully: exit={run.returncode}")
            return False
        if any(s in output for s in (
            "WOLFOS_APIC_TIMER_ERROR", "WOLFOS_APIC_TIMER_TEST_FAILED",
            "WOLFOS_APIC_IRQ_FRAME_ERROR", "WOLFOS_APIC_GPR_ERROR",
            "WOLFOS_APIC_PREEMPT_ERROR",
            "WOLFOS_APIC_BLOCK_WAKE_ERROR",
            "WOLFOS_APIC_FINISHED_ERROR",
            "WOLFOS_APIC_RECYCLE_ERROR",
            "WOLFOS_APIC_REUSE_EXEC_ERROR",
            "WOLFOS_APIC_FXSTATE_ERROR",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF", "WOLFOS_PANIC",
        )):
            print("FAIL: fatal APIC-related kernel diagnostic")
            return False
        print(
            f"PASS: {cpus} CPUs; BSP xAPIC IRQs={ticks}, EOIs={eoi}, "
            f"spurious={spurious}; preemptive={int(preemptive)}"
        )
        return True


def main() -> int:
    calibrated = len(sys.argv) == 3 and sys.argv[2] == "--calibrated"
    preemptive = len(sys.argv) == 3 and sys.argv[2] == "--preemptive"
    if (len(sys.argv) not in (2, 3) or
        (len(sys.argv) == 3 and not (calibrated or preemptive)) or
        not Path(sys.argv[1]).is_file()):
        print("Usage: apic_timer_smoke.py ISO [--calibrated|--preemptive]")
        return 2
    iso = Path(sys.argv[1])
    for cpus in (1, 4):
        if not exercise(iso, cpus, calibrated, preemptive):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
