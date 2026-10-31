#!/usr/bin/env python3
"""Real QEMU PMM + no_std multi-resident process table smoke.

No CPL3 execution occurs in this particular feature. Existing distinct
CPL3 file/syscall and sequential PID runs remain CI requirements.
"""
from pathlib import Path
import os
import subprocess
import sys
import tempfile

PROOFS = [
    "WOLFOS_BOOT_OK",
    "WOLFOS_PROCESS_TABLE_RESIDENT_OK ready=3 pids=1,2,3 real_pmm_frames=28 aliases=0 running=0",
    "WOLFOS_PROCESS_TABLE_BOOTSTRAP_OK pids=3 context_frames=3 private_lease_roots=3 atomic_rollback=1 stack_mapped=0 cpl3_executed=0",
    "WOLFOS_PROCESS_TABLE_ELF_PREFLIGHT_OK images=3 file_backed_entries=3 wx_denied=1 late_rollback=1 real_pmm=28 user_mapping=0",
    "WOLFOS_PROCESS_TABLE_REUSE_OK last_pid=4 stale_pid_denied=1 foreign_cr3_denied=1",
    "WOLFOS_PROCESS_TABLE_CONTEXT_REUSE_OK live_contexts=3 retired_pid2=1 fresh_pid4=1 rsp0_reused_safely=1",
    "WOLFOS_PROCESS_TABLE_CLEANUP_OK issued_pids=4 frames_freed=28 pmm_no_leak=1 boot_cr3_preserved=1 cpl3_executed=0",
]
SURFACE_REAP_PROOF = (
    "WOLFOS_SURFACE_REAP_PMM_OK pids=2 real_pmm_pages=4 early_release_denied=1 "
    "half_ack_denied=1 cross_pid_isolated=1 synthetic_gpu_acks=1 "
    "pmm_no_leak=1 cpl3_executed=0 real_gpu_dma=0"
)
BAD = [
    "WOLFOS_PROCESS_TABLE_ERROR", "WOLFOS_PANIC", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_DF", "WOLFOS_EXCEPTION_UD",
]

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: process_table_smoke.py path/to/ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-process-table-") as tmp:
        serial = Path(tmp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{serial}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: process-table PMM QEMU test timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU missing")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        proofs = PROOFS + ([SURFACE_REAP_PROOF] if os.environ.get("WOLFOS_SURFACE_REAP_PMM") == "1" else [])
        locations = [output.find(marker) for marker in proofs]
        if any(at < 0 for at in locations) or locations != sorted(locations):
            print("FAIL: missing/out of order multi-resident PMM evidence")
            return 1
        if any(output.count(marker) != 1 for marker in proofs):
            print("FAIL: duplicated proof marker")
            return 1
        if any(bad in output for bad in BAD):
            print("FAIL: kernel fault or allocation accounting failure")
            return 1
        if run.returncode != 33:
            print("FAIL: debug exit expected 33; got", run.returncode)
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: real PMM, jointly staged PID/bootstrap metadata, strict rollback, context/stack reuse and zero leaks")
        if os.environ.get("WOLFOS_SURFACE_REAP_PMM") == "1":
            print("PASS: real PMM surface retirement and leak-free counted cancellation; GPU completions simulated, no real GPU DMA")
        return 0

if __name__ == "__main__":
    sys.exit(main())
