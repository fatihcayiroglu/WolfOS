#!/usr/bin/env python3
"""Real sequential process ownership proof: TWO distinct PID generations.

Independent, linked ELF64 app runs twice in hardware CPL3. Each launch:
fresh/safely reclaimed PMM frames, independent sanitized CR3, 22 INT80
syscalls, verified user console, EXIT(0), restore boot CR3 and REAP. Exact
chronology, two individual PID markers, 44 total interrupts, no leaks.
This is NOT a concurrent process scheduler or user-facing shell yet.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ENTER = re.compile(
    r"WOLFOS_ELF_RUN_ENTER elf64=1 et_exec=1 pt_load=2 rx=1 rw_nx=2 "
    r"bss_zero=1 cr3_new=1 root_slot=(\d+) user_entry=0x401000"
)
START = [
    "WOLFOS_PROCESS_START pid=1 state=running private_cr3=1 owned_frames=7",
    "WOLFOS_PROCESS_START pid=2 state=running private_cr3=1 owned_frames=7",
]
REAP = [
    "WOLFOS_PROCESS_REAP_OK pid=1 exited=1 restored_cr3=1 freed_frames=7 no_leak=1",
    "WOLFOS_PROCESS_REAP_OK pid=2 exited=1 restored_cr3=1 freed_frames=7 no_leak=1",
]
RELAUNCH = "WOLFOS_PROCESS_RELAUNCH pid=2 generation=2 first_reaped=1"
FINAL = (
    "WOLFOS_PROCESS_LIFECYCLE_OK launched=2 exited=2 reaped=2 "
    "total_int80=44 restored_cr3=1 per_pid_owner=1 pmm_no_leak=1 concurrent=0"
)
HELLO = "Hello from WolfOS!\n"
EXIT = "WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=22"
CLEAN = "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1"
SUCCESS = (
    "WOLFOS_ELF_RUN_OK linked_elf=1 hardware_cpl3=1 user_console=1 "
    "int80_calls=22 exit=0 resources_released=1 real_process_manager=0"
)
def one(output: str, value: str) -> int:
    if output.count(value) != 1:
        raise ValueError("missing or duplicated unique proof: " + value)
    return output.find(value)

def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_process_smoke.py path/to/wolfos-user-process.iso")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-pid-lifecycle-") as temp:
        serial = Path(temp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{serial}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            run = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: two real ELF process launches timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU unavailable")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        entries = list(ENTER.finditer(output))
        if len(entries) != 2 or any(not 1 <= int(e.group(1)) <= 255 for e in entries):
            print("FAIL: two properly isolated ELF CR3 launches required")
            return 1
        try:
            first = [
                entries[0].start(),
                one(output, START[0]),
            ]
            second = [
                entries[1].start(),
                one(output, START[1]),
            ]
            # Common proof markers MUST appear TWICE; split after first
            # complete REAP, preventing late writes from a reaped process.
            common = [
                "WOLFOS_ELF_ID_OK cpl3=1 return_rax=0x574f4c46",
                "WOLFOS_ELF_ADD_OK cpl3=1 return_rax=42",
                HELLO,
                "WOLFOS_ELF_HELLO_OK bytes=19 syscall_iretq=19",
                EXIT, CLEAN, SUCCESS,
            ]
            for token in common:
                if output.count(token) != 2:
                    raise ValueError("expected two complete ELF user runs: " + token)
                first.append(output.find(token))
                second.append(output.find(token, first[-1] + 1) if token == SUCCESS
                              else output.find(token, entries[1].start()))
            first.append(one(output, REAP[0]))
            second.append(one(output, REAP[1]))
            restart = one(output, RELAUNCH)
            finish = one(output, FINAL)
            if any(x < 0 for x in first + second):
                raise ValueError("missing required event")
            if first != sorted(first) or second != sorted(second):
                raise ValueError("per-process events were not sequential")
            if not (output.find("WOLFOS_BOOT_OK") < first[0]
                    < first[-1] < restart < second[0] < second[-1] < finish):
                raise ValueError("process 2 launched before process 1 fully reaped")
        except ValueError as exc:
            print("FAIL: " + str(exc))
            return 1
        for bad in (
            "WOLFOS_ELF_RUN_ERROR", "WOLFOS_RING_PREP_ERROR",
            "WOLFOS_PANIC", "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_GP",
            "WOLFOS_EXCEPTION_UD", "WOLFOS_EXCEPTION_DF",
        ):
            if bad in output:
                print("FAIL: unexpected kernel failure: " + bad)
                return 1
        if run.returncode != 33:
            print(f"FAIL: clean QEMU debug-exit 33 expected, got {run.returncode}")
            print(run.stderr.decode(errors="replace"))
            return 1
        print("PASS: TWO real ELF64 Ring3 PID generations, 44 INT80 calls and no leaked physical pages")
        return 0

if __name__ == "__main__":
    sys.exit(main())
