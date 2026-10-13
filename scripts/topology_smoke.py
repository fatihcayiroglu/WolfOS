#!/usr/bin/env python3
"""Boot four QEMU vCPUs and verify ACPI/MADT plus cooperative job dispatch."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

EXPECTED_CPUS = 4

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: topology_smoke.py out/wolfos-smoke.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-topology-") as temp:
        log = Path(temp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", "4,sockets=1,cores=4,threads=1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{log}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=45, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: 4-vCPU topology QEMU boot timed out")
            if log.exists():
                print(log.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU missing")
            return 2
        output = log.read_text(errors="replace") if log.exists() else ""
        print(output)
        match = re.search(r"WOLFOS_ACPI_MADT_OK enabled_cpus=(\d+) lapic=(\d+) x2apic=(\d+)", output)
        if not match:
            print("FAIL: missing ACPI MADT summary")
            return 1
        total, lapic, x2apic = map(int, match.groups())
        if (total, lapic+x2apic) != (EXPECTED_CPUS, EXPECTED_CPUS):
            print(f"FAIL: expected four enabled CPUs, MADT reported {total}")
            return 1
        ack = re.search(r"WOLFOS_SMP_APS_OK total=(\d+) bsp_lapic=(\d+) ap_acks=(\d+)", output)
        if ack is None:
            print("FAIL: four secondary CPUs were enumerated but Rust AP handoff did not complete")
            return 1
        total_online, _, aps = map(int, ack.groups())
        if total_online != EXPECTED_CPUS or aps != EXPECTED_CPUS - 1:
            print(f"FAIL: expected 3 Rust AP acknowledgements; got total={total_online}, aps={aps}")
            return 1
        if "WOLFOS_SMP_CTX_OK cpus=4 active=4 threads=8 switches=48 yields=12 blocked=4 woken=4 finished=8 stack_kib=8 bank_kib=4096" not in output:
            print("FAIL: four processors did not each resume their own two Rust stacks")
            return 1
        if "WOLFOS_SMP_PERCPU_OK total=4 ap_tables=3" not in output:
            print("FAIL: APs did not finish per-core GDT/TSS/IST initialization")
            return 1
        per_cpu = re.search(
            r"WOLFOS_SMP_AP_IDT_OK total=(\d+) ap_idts=(\d+) ap_bp_returns=(\d+)",
            output,
        )
        if per_cpu is None or tuple(map(int, per_cpu.groups())) != (EXPECTED_CPUS, 3, 3):
            print("FAIL: AP-local IDT and exception return were not verified")
            return 1
        stack = re.search(r"WOLFOS_SMP_STACK_OK total=(\d+) switched=(\d+) stack_kib=(\d+)", output)
        if stack is None or tuple(map(int, stack.groups())) != (EXPECTED_CPUS, 3, 32):
            print("FAIL: 3 APs did not switch to independent 32 KiB WolfOS kernel stacks")
            return 1
        work = re.search(r"WOLFOS_SMP_WORK_OK total=(\d+) workers=(\d+) rounds=(\d+)", output)
        if work is None or tuple(map(int, work.groups())) != (EXPECTED_CPUS, 3, 32768):
            print("FAIL: independent AP work did not finish with verified results")
            return 1
        dispatch = re.search(
            r"WOLFOS_SCHED_OK tasks=(\d+) cpus=(\d+) active=(\d+) bsp_jobs=(\d+) ap_jobs=(\d+)",
            output,
        )
        if dispatch is None:
            print("FAIL: cooperative job queue did not report verified work")
            return 1
        tasks, cpus, active, bsp_jobs, ap_jobs = map(int, dispatch.groups())
        if (tasks, cpus, active) != (512, EXPECTED_CPUS, EXPECTED_CPUS):
            print(f"FAIL: incorrect scheduler job/CPU count {(tasks,cpus,active)}")
            return 1
        if bsp_jobs < 1 or ap_jobs < EXPECTED_CPUS - 1 or bsp_jobs + ap_jobs != tasks:
            print(f"FAIL: verified work must include BSP and 3 APs: {(bsp_jobs,ap_jobs)}")
            return 1
        lifecycle = re.search(
            r"WOLFOS_THREADS_OK threads=(\d+) cpus=(\d+) active=(\d+) yielded=(\d+) blocked=(\d+) woken=(\d+) finished=(\d+)",
            output,
        )
        if lifecycle is None or tuple(map(int, lifecycle.groups())) != (256, EXPECTED_CPUS, EXPECTED_CPUS, 512, 256, 256, 256):
            print("FAIL: kernel tasks did not yield, block, wake and finish on all CPUs")
            return 1
        if "WOLFOS_CONTEXT_OK tasks=2 switches=7 events=6 stacks_kib=16" not in output:
            print("FAIL: BSP context-switch roundtrip did not resume each Rust stack")
            return 1
        if "WOLFOS_KTHREAD_OK threads=3 dispatches=9 switches=18 yields=5 blocked=1 woken=1 finished=3 stack_kib=16" not in output:
            print("FAIL: three context-backed kernel threads did not yield/block/wake and resume")
            return 1
        if "WOLFOS_CTX_BATCH_OK threads=256 dispatches=1024 switches=2048 yields=767 blocked=1 woken=1 finished=256 stack_kib=16 bank_kib=4096" not in output:
            print("FAIL: 256 independent context-backed kernel TCBs did not all resume")
            return 1
        if "WOLFOS_BOOT_OK" not in output or run.returncode != 33:
            print(f"FAIL: kernel not fully booted, QEMU exit={run.returncode}")
            return 1
        print("PASS: four CPUs each switched two private Rust contexts; 256 BSP TCBs remain verified")
        return 0

if __name__ == "__main__":
    sys.exit(main())
