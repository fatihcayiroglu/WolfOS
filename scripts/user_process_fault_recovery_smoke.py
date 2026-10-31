#!/usr/bin/env python3
"""True hardware recovery: faulting PID1 then independently linked healthy PID2.

Both apps execute from distinct fresh CR3/PMM leases in real CPL3. PID1
deliberately triggers #PF and exits with 139; ONLY after its exact seven-frame
reap, PID2 boots a different ELF, emits real PUTC calls and exits zero.
Fail closed for missing/duplicated/out-of-order events, kernel faults or skips.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

if __package__:
    from .elf_launch_evidence import valid_launch_transactions
else:
    from elf_launch_evidence import valid_launch_transactions


ENTER = re.compile(
    r"WOLFOS_ELF_RUN_ENTER elf64=1 et_exec=1 pt_load=2 rx=1 rw_nx=2 "
    r"bss_zero=1 cr3_new=1 root_slot=(\d+) user_entry=0x401000"
)
START1 = "WOLFOS_PROCESS_START pid=1 state=running private_cr3=1 owned_frames=7"
START2 = "WOLFOS_PROCESS_START pid=2 state=running private_cr3=1 owned_frames=7"
ID = "WOLFOS_ELF_ID_OK cpl3=1 return_rax=0x574f4c46"
ADD = "WOLFOS_ELF_ADD_OK cpl3=1 return_rax=42"
HELLO = "Hello from WolfOS!\n"
HELLO_OK = "WOLFOS_ELF_HELLO_OK bytes=19 syscall_iretq=19"
PF = (
    "WOLFOS_ELF_USER_PF_OK vector=14 cpl3=1 status=139 "
    "address=0xffff800000000000 read_denied=1 user_rip_verified=1"
)
PF_REAP = "WOLFOS_ELF_USER_PF_REAP_OK pid=1 status=139 active_cr3_restored=1 lease=7"
PF_RESULT = (
    "WOLFOS_ELF_USER_PF_RUN_OK linked_elf=1 hardware_cpl3=1 pf_vector=14 "
    "status=139 int80_calls=21 frames_freed=7 pmm_no_leak=1"
)
CLEAN = "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1"
EXIT0 = "WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=22"
SUCCESS0 = (
    "WOLFOS_ELF_RUN_OK linked_elf=1 hardware_cpl3=1 user_console=1 "
    "int80_calls=22 exit=0 resources_released=1 real_process_manager=0"
)
REAP1 = "WOLFOS_PROCESS_REAP_OK pid=1 exited=1 restored_cr3=1 freed_frames=7 no_leak=1"
REAP2 = "WOLFOS_PROCESS_REAP_OK pid=2 exited=1 restored_cr3=1 freed_frames=7 no_leak=1"
TABLE1 = "WOLFOS_PROCESS_TABLE_REAP_OK pid=1 slots=2 occupied=0 running=0 stale_denied=1 double_reap_denied=1 real_cpl3=1"
TABLE2 = "WOLFOS_PROCESS_TABLE_REAP_OK pid=2 slots=2 occupied=0 running=0 stale_denied=1 double_reap_denied=1 real_cpl3=1"
RELAUNCH = "WOLFOS_PROCESS_RELAUNCH pid=2 generation=2 first_reaped=1"
FINAL = (
    "WOLFOS_PROCESS_FAULT_RECOVERY_OK first_pid=1 first_status=139 "
    "second_pid=2 second_status=0 total_int80=43 restored_cr3=2 "
    "frames_freed=14 pmm_no_leak=1"
)

SURFACE_OPEN1 = (
    "WOLFOS_RING3_SURFACE_OPEN_OK pid=1 registry=1 owner_generation=1 "
    "software_submit=1 gpu_dma=0"
)
SURFACE_OPEN2 = SURFACE_OPEN1.replace("pid=1", "pid=2")
SURFACE_GUARD1 = (
    "WOLFOS_RING3_SURFACE_EXIT_GUARD_OK pid=1 real_cpl3=1 restored_cr3=1 "
    "early_reap_denied=1 half_ack_denied=1 retained_handle_denied=1 "
    "software_acks=1 guarded_reap=1 real_pmm_frames=7 gpu_dma=0"
)
SURFACE_GUARD2 = SURFACE_GUARD1.replace("pid=1", "pid=2")
SURFACE_REUSE = (
    "WOLFOS_RING3_SURFACE_REUSE_OK old_pid=1 new_pid=2 slot_reused=1 "
    "generation_advanced=1 stale_handle_denied=1 stale_fence_denied=1"
)

def main() -> int:
    surface = len(sys.argv) == 3 and sys.argv[2] == "--surface"
    if (len(sys.argv) not in (2,3)
            or (len(sys.argv) == 3 and not surface)
            or not Path(sys.argv[1]).is_file()):
        print("Usage: user_process_fault_recovery_smoke.py path/to/recovery.iso [--surface]")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-pf-recovery-") as temp:
        serial = Path(temp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{serial}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: faulted PID1 / healthy PID2 hardware recovery timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 unavailable")
            return 2
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        if not valid_launch_transactions(output, 7, (1, 2)):
            print("FAIL: counted launch rollback, CPU ownership or terminal retirement evidence missing")
            return 1
        entries = list(ENTER.finditer(output))
        if len(entries) != 2 or any(not 1 <= int(m.group(1)) <= 255 for m in entries):
            print("FAIL: two independent hardware ELF/CR3 entries required")
            return 1
        ordered = [
            "WOLFOS_BOOT_OK",
            *([SURFACE_OPEN1] if surface else []),
            START1, entries[0].group(0),
            ID, ADD, HELLO, HELLO_OK, PF,
            *([SURFACE_GUARD1] if surface else []),
            PF_REAP, CLEAN, TABLE1, PF_RESULT, REAP1, RELAUNCH,
            *([SURFACE_REUSE, SURFACE_OPEN2] if surface else []),
            START2, entries[1].group(0),
            ID, ADD, HELLO, HELLO_OK, EXIT0,
            *([SURFACE_GUARD2] if surface else []),
            CLEAN, TABLE2, SUCCESS0, REAP2, FINAL,
        ]
        cursor = 0
        for token in ordered:
            place = output.find(token, cursor)
            if place < 0:
                print("FAIL: missing/out-of-order hardware recovery evidence: " + repr(token))
                return 1
            cursor = place + len(token)
        for token, count in [(ID, 2), (ADD, 2), (HELLO, 2), (HELLO_OK, 2), (CLEAN, 2)]:
            if output.count(token) != count:
                print("FAIL: missing or duplicated per-PID syscall/cleanup: " + token)
                return 1
        for token in [START1, START2, PF, PF_REAP, PF_RESULT,
                      EXIT0, SUCCESS0, REAP1, REAP2, TABLE1, TABLE2, RELAUNCH, FINAL]:
            if output.count(token) != 1:
                print("FAIL: missing or duplicated unique recovery marker: " + token)
                return 1
        if surface:
            if any(output.count(m) != 1 for m in (
                SURFACE_OPEN1, SURFACE_OPEN2, SURFACE_GUARD1,
                SURFACE_GUARD2, SURFACE_REUSE,
            )):
                print("FAIL: duplicate/missing PID-generation and fence-replay evidence")
                return 1
        elif any(m in output for m in (
            "WOLFOS_RING3_SURFACE_OPEN_OK",
            "WOLFOS_RING3_SURFACE_EXIT_GUARD_OK",
            "WOLFOS_RING3_SURFACE_REUSE_OK",
        )):
            print("FAIL: unrequested surface fixture leaked into legacy recovery")
            return 1
        for bad in [
            "WOLFOS_ELF_RUN_ERROR", "WOLFOS_RING_PREP_ERROR",
            "WOLFOS_PANIC", "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_GP",
            "WOLFOS_EXCEPTION_UD", "WOLFOS_EXCEPTION_DF",
            "WOLFOS_PROCESS_LIFECYCLE_OK",
        ]:
            if bad in output:
                print("FAIL: unexpected kernel failure/incorrect process contract: " + bad)
                return 1
        if result.returncode != 33:
            print(f"FAIL: expected clean QEMU debug-exit 33, got {result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        print("PASS: PID1 real CPL3 #PF/status139 -> exact reap -> new healthy ELF PID2 EXIT0; 43 INT80, 14 PMM frames freed")
        if surface:
            print("PASS: PID2 recycled surface slot with new generation, stale PID1 handle/fences refused; synthetic GPU replies, real CPL3 and PMM")
        return 0

if __name__ == "__main__":
    sys.exit(main())
