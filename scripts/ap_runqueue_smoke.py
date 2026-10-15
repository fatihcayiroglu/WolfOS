#!/usr/bin/env python3
"""Hardware proof of bounded AP work queues and genuine directed IPI wakeup."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: ap_runqueue_smoke.py ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ap-runqueue-") as tmp:
        serial = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", "4", "-vga", "std",
            "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{serial}",
            "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: three AP bounded runqueue QEMU test timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 unavailable")
            return 1
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        if "WOLFOS_SMP_APS_OK total=4 " not in output:
            print("FAIL: prior SMP stacks and context work not complete")
            return 1

        proof = re.search(
            r"WOLFOS_AP_RUNQUEUE_OK cpus=(\d+) aps=(\d+) "
            r"capacity=(\d+) waves=(\d+) submitted=(\d+) executed=(\d+) "
            r"full_rejected=(\d+) wrong_owner_rejected=(\d+) "
            r"ipis=(\d+) eois=(\d+) fifo=(\d+) wraps=(\d+) "
            r"peak=(\d+) active=(\d+) idle=(\d+) offline=(\d+) "
            r"invalid=(\d+) spurious=(\d+) bsp_if=(\d+) "
            r"task_migrated=(\d+)",
            output,
        )
        if proof is None:
            print("FAIL: bounded hardware IPI runqueue proof absent")
            return 1
        got = tuple(map(int, proof.groups()))
        expected = (
            4, 3, 4, 2, 24, 24, 6, 6,
            6, 6, 24, 3, 3, 0, 3, 3, 0, 0, 0, 0,
        )
        if got != expected:
            print(f"FAIL: invalid per-CPU FIFO/backpressure/overlap/IPI evidence: {got}")
            return 1
        for error in (
            "WOLFOS_AP_RUNQUEUE_ERROR", "WOLFOS_AP_RUNQUEUE_TEST_FAILED",
            "WOLFOS_AP_IPI_ERROR", "WOLFOS_PANIC",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_PF",
            "WOLFOS_EXCEPTION_DF",
        ):
            if error in output:
                print(f"FAIL: kernel emitted {error}")
                return 1
        if "WOLFOS_BOOT_OK" not in output or run.returncode != 33:
            print(f"FAIL: expected clean QEMU exit, got {run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print(
            "PASS: 3 AP-owned four-slot FIFOs, 24 correct jobs across "
            "two real-IPI-triggered waves, 6 actual directed IPIs/EOIs, "
            "6 full-queue rejections, 6 wrong-owner rejections, "
            "3 overlapping AP CPU work contexts and 0 invalid executions"
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
