#!/usr/bin/env python3
"""Demand real, non-yielding timer-IRQ checkpoint and cross-AP IRETQ resume.

One task is preempted by its OWNER AP local xAPIC timer, then the saved
full hardware frame and FX image resume on the NEXT AP after quiescence.
This is NOT a production SMP scheduler or physical-hardware verification.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: ap_irq_migrate_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-irq-migrate-") as tmp:
        logfile = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", "4", "-vga", "std", "-cdrom",
            str(Path(sys.argv[1]).resolve()), "-boot", "d",
            "-serial", f"file:{logfile}", "-display", "none",
            "-no-reboot", "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: forced timer-IRQ stack migration QEMU timed out")
            if logfile.exists():
                print(logfile.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 missing")
            return 1
        output = logfile.read_text(errors="replace") if logfile.exists() else ""
        print(output)
        if "WOLFOS_SMP_APS_OK total=4 " not in output:
            print("FAIL: prerequisite SMP boot and kernel-stack proof missing")
            return 1
        proof = re.search(
            r"WOLFOS_AP_IRQ_MIGRATE_OK cpus=(\d+) aps=(\d+) "
            r"starts=(\d+) resumes=(\d+) hops=(\d+) transfers=(\d+) "
            r"quanta=(\d+) ipis=(\d+) ipi_eois=(\d+) "
            r"timer_irqs=(\d+) timer_eois=(\d+) claims=(\d+) "
            r"finished=(\d+) stale_denied=(\d+) fx_saves=(\d+) "
            r"fx_restores=(\d+) work=(\d+) canary=(\d+) invalid=(\d+) "
            r"spurious=(\d+) offline=(\d+) irq_preempted=(\d+) "
            r"stack_copied=(\d+) bsp_if=(\d+)",
            output,
        )
        if proof is None:
            print("FAIL: no complete genuine AP IRQ-preempted cross-core IRETQ proof")
            return 1
        got = tuple(map(int, proof.groups()))
        expected = (
            4, 3, 1, 12, 11, 11, 12, 12, 12,
            12, 12, 12, 12, 11, 12, 12,
        )
        if got[:16] != expected or got[16] <= 0 or got[17:] != (
            1, 0, 0, 3, 1, 0, 0,
        ):
            print(f"FAIL: invalid cross-core IRQ/FX/ownership evidence {got}")
            return 1
        for marker in (
            "WOLFOS_AP_IRQ_MIGRATE_ERROR",
            "WOLFOS_AP_IRQ_MIGRATE_TEST_FAILED",
            "WOLFOS_AP_IPI_ERROR",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
            "WOLFOS_EXCEPTION_DF", "WOLFOS_PANIC",
        ):
            if marker in output:
                print(f"FAIL: kernel emitted {marker}")
                return 1
        if "WOLFOS_BOOT_OK" not in output or run.returncode != 33:
            print(f"FAIL: kernel did not exit normally code={run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print(
            "PASS: one non-yielding Rust kernel task, 12 AP-local hardware "
            "timer preemptions and EOIs, 11 genuine full-GPR/IRETQ "
            "cross-AP resumptions, 12 saved/restored FX images, and "
            "12 directed IPIs/EOIs; no stack copying or stale owners"
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
