#!/usr/bin/env python3
"""Actual independently linked ELF64 -> hardware CPL3 -> WolfOS PUTC -> EXIT.

Fail-closed QEMU admission: real ELF64 loader and BSS, supervisor-only new
CR3, genuine serial message from USER CODE via 19 INT80 calls, two register
result returns, EXIT(0), restored boot CR3, an exact 6/7/8/9-frame PMM lease reclaimed by the selected flavor.
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
ONE_LOAD_ENTER = re.compile(
    r"WOLFOS_ELF_RUN_ENTER elf64=1 et_exec=1 pt_load=1 rx=1 rw_nx=1 "
    r"bss_zero=1 cr3_new=1 root_slot=(\d+) user_entry=0x401000"
)
MARKERS = (
    "WOLFOS_ELF_ID_OK cpl3=1 return_rax=0x574f4c46",
    "WOLFOS_ELF_ADD_OK cpl3=1 return_rax=42",
    "Hello from WolfOS!\n",
    "WOLFOS_ELF_HELLO_OK bytes=19 syscall_iretq=19",
    "WOLFOS_ELF_EXIT_OK code=0 cpl3=1 calls=22",
    "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=7 pmm_no_leak=1",
    "WOLFOS_ELF_RUN_OK linked_elf=1 hardware_cpl3=1 user_console=1 "
    "int80_calls=22 exit=0 resources_released=1 real_process_manager=0",
)

ONE_LOAD_MARKERS = (
    "WOLFOS_ELF_ONE_LOAD_ENTER hardware_cr3=1 load_segments=1 "
    "rx_leaves=1 nx_stack=1 owned_frames=6 root_slot=",
    *MARKERS[:5],
    "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=6 pmm_no_leak=1",
    "WOLFOS_ELF_ONE_LOAD_RUN_OK linked_elf=1 hardware_cpl3=1 one_pt_load=1 "
    "rx_leaves=1 stack_rw_nx=1 int80_calls=22 exit=0 restored_cr3=1 "
    "frames_freed=6 pmm_no_leak=1",
)

TWO_PT_MARKERS = (
    "WOLFOS_ELF_TWO_PT_ENTER hardware_cr3=1 root_slot=",
    *MARKERS[:4],
    MARKERS[4],
    "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=8 pmm_no_leak=1",
    "WOLFOS_ELF_TWO_PT_RUN_OK linked_elf=1 hardware_cpl3=1 pt_frames=2 "
    "user_console=1 int80_calls=22 exit=0 restored_cr3=1 frames_freed=8 pmm_no_leak=1",
)

THREE_LOAD_MARKERS = (
    "WOLFOS_ELF_THREE_LOAD_ENTER hardware_cr3=1 root_slot=",
    *MARKERS[:4],
    MARKERS[4],
    "WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed=9 pmm_no_leak=1",
    "WOLFOS_ELF_THREE_LOAD_RUN_OK linked_elf=1 hardware_cpl3=1 pt_frames=2 "
    "rx_leaves=2 second_rx_called=1 int80_calls=22 exit=0 restored_cr3=1 "
    "frames_freed=9 pmm_no_leak=1",
)

STATUS_MARKERS = (
    *MARKERS[:4],
    "WOLFOS_ELF_EXIT_STATUS_OK code=42 cpl3=1 calls=22 saved_rdi=42",
    "WOLFOS_ELF_STATUS_REAP_OK pid=1 code=42 active_cr3_restored=1 lease=7",
    MARKERS[5],
    "WOLFOS_ELF_STATUS_RUN_OK linked_elf=1 hardware_cpl3=1 user_console=1 "
    "int80_calls=22 exit=42 resources_released=1 real_process_manager=0",
)

UD_FAULT_MARKERS = (
    *MARKERS[:4],
    "WOLFOS_ELF_USER_UD_OK vector=6 cpl3=1 status=132 int80_calls=21 user_rip_verified=1",
    "WOLFOS_ELF_USER_UD_REAP_OK pid=1 status=132 active_cr3_restored=1 lease=7",
    MARKERS[5],
    "WOLFOS_ELF_USER_UD_RUN_OK linked_elf=1 hardware_cpl3=1 ud_vector=6 "
    "status=132 int80_calls=21 frames_freed=7 pmm_no_leak=1",
)

PF_FAULT_MARKERS = (
    *MARKERS[:4],
    "WOLFOS_ELF_USER_PF_OK vector=14 cpl3=1 status=139 address=0xffff800000000000 read_denied=1 user_rip_verified=1",
    "WOLFOS_ELF_USER_PF_REAP_OK pid=1 status=139 active_cr3_restored=1 lease=7",
    MARKERS[5],
    "WOLFOS_ELF_USER_PF_RUN_OK linked_elf=1 hardware_cpl3=1 pf_vector=14 "
    "status=139 int80_calls=21 frames_freed=7 pmm_no_leak=1",
)


def valid_table_plan(output: str, tables: int, loads: int, total: int,
                     entry_start: int) -> bool:
    """Require the exact shared-mapper proof before the real CR3 entry row."""
    expected = (f"WOLFOS_ELF_TABLE_PLAN_OK source=elf tables={tables} "
                f"loads={loads} stack=1 total={total} exact_audit=1")
    found = [row for row in output.splitlines() if "WOLFOS_ELF_TABLE_PLAN_OK" in row]
    return (found == [expected]
            and 0 <= output.find("WOLFOS_BOOT_OK") < output.find(expected) < entry_start)


TWO_PT_STAGE_REJECT_PROOF = (
    "WOLFOS_ELF_TWO_PT_STAGE_REJECT_OK wrong_last_frame=1 tables_unchanged=1 "
    "loads_unchanged=1 stack_unchanged=1 pmm_unchanged=1"
)


def valid_payload_plan(output: str, loads: int, total: int, entry_start: int,
                       *, two_pt: bool) -> bool:
    """All layouts use common staging; two-PT runs also prove real rejection."""
    if not valid_table_plan(output, 5 if two_pt else 4, loads, total, entry_start):
        return False
    expected = (f"WOLFOS_ELF_PAYLOAD_PLAN_OK source=recipe loads={loads} "
                f"stack=1 total={total}")
    found = [row for row in output.splitlines() if "WOLFOS_ELF_PAYLOAD_PLAN_OK" in row]
    table = output.find("WOLFOS_ELF_TABLE_PLAN_OK")
    if found != [expected] or not table < output.find(expected) < entry_start:
        return False
    rejected = [row for row in output.splitlines()
                if "WOLFOS_ELF_TWO_PT_STAGE_REJECT_OK" in row]
    if not two_pt:
        return not rejected
    return (rejected == [TWO_PT_STAGE_REJECT_PROOF]
            and output.find("WOLFOS_BOOT_OK") < output.find(TWO_PT_STAGE_REJECT_PROOF) < table)

def main() -> int:
    mode = sys.argv[2] if len(sys.argv) == 3 else None
    one_load_mode = mode == "--one-load"
    two_pt_mode = mode == "--two-pt"
    three_load_mode = mode == "--three-load"
    status_mode = mode == "--exit-status"
    fault_mode = mode == "--user-ud-fault"
    pf_mode = mode == "--user-pf-fault"
    if len(sys.argv) not in (2, 3) or (mode is not None and not (status_mode or fault_mode or pf_mode or one_load_mode or two_pt_mode or three_load_mode)) or not Path(sys.argv[1]).is_file():
        print("Usage: user_elf_run_smoke.py path/to/wolfos-user-elf-run.iso [--one-load|--two-pt|--three-load|--exit-status|--user-ud-fault|--user-pf-fault]")
        return 2
    markers = ONE_LOAD_MARKERS if one_load_mode else THREE_LOAD_MARKERS if three_load_mode else TWO_PT_MARKERS if two_pt_mode else PF_FAULT_MARKERS if pf_mode else UD_FAULT_MARKERS if fault_mode else STATUS_MARKERS if status_mode else MARKERS
    with tempfile.TemporaryDirectory(prefix="wolfos-real-elf-run-") as tmp:
        serial = Path(tmp) / "serial.log"
        command = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(Path(sys.argv[1]).resolve()),
            "-boot", "d", "-serial", f"file:{serial}", "-display", "none",
            "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            result = subprocess.run(command, capture_output=True, timeout=55, check=False)
        except subprocess.TimeoutExpired:
            print("FAIL: real ELF64 hardware CPL3 or cleanup timed out")
            if serial.exists():
                print(serial.read_text(errors="replace"))
            return 1
        except FileNotFoundError:
            print("FAIL: qemu-system-x86_64 unavailable")
            return 2
        # Path.read_text() uses universal newline conversion: COM1 CRLF is
        # correctly presented as LF. Still insist on ONE complete line.
        output = serial.read_text(errors="replace") if serial.exists() else ""
        print(output)
        entry = (ONE_LOAD_ENTER if one_load_mode else ENTER).search(output)
        if not entry or not 1 <= int(entry.group(1)) <= 255:
            print("FAIL: genuine ELF64 independent sanitized CR3 entry missing")
            return 1
        tables, loads, total = ((4, 1, 6) if one_load_mode else
                               (5, 3, 9) if three_load_mode else
                               (5, 2, 8) if two_pt_mode else (4, 2, 7))
        if not valid_launch_transactions(output, total, (1,)):
            print("FAIL: counted launch rollback, CPU ownership or terminal retirement evidence missing")
            return 1
        if not valid_table_plan(output, tables, loads, total, entry.start()):
            print("FAIL: exact ELF-derived table/frame plan and full PTE audit missing")
            return 1
        if not valid_payload_plan(output, loads, total, entry.start(), two_pt=tables == 5):
            print("FAIL: common payload staging or atomic two-PT rejection proof missing")
            return 1
        if one_load_mode:
            live = re.search(
                r"(?m)^WOLFOS_ELF_ONE_LOAD_ENTER hardware_cr3=1 load_segments=1 "
                r"rx_leaves=1 nx_stack=1 owned_frames=6 root_slot=(\d+)$",
                output,
            )
            if not live or live.group(1) != entry.group(1):
                print("FAIL: real one-LOAD, stack protection or six-frame root proof missing")
                return 1
        if three_load_mode:
            live = re.search(
                r"(?m)^WOLFOS_ELF_THREE_LOAD_ENTER hardware_cr3=1 root_slot=(\d+) "
                r"pd_regions=2 pt_frames=2 rx_leaves=2 data_nx=1 stack_nx=1 "
                r"elf_admitted=1 derived_pages=1 owned_frames=9$",
                output,
            )
            if not live or live.group(1) != entry.group(1):
                print("FAIL: real second RX page and nine-frame manifest provenance missing")
                return 1
        if two_pt_mode:
            live = re.search(
                r"(?m)^WOLFOS_ELF_TWO_PT_ENTER hardware_cr3=1 root_slot=(\d+) "
                r"pd_regions=2 pt_frames=2 rx=1 rw_nx=2 elf_admitted=1 "
                r"hhdm_checked=1 derived_pages=1 owned_frames=8$",
                output,
            )
            if not live or live.group(1) != entry.group(1):
                print("FAIL: live two-PT manifest/CR3 root provenance missing or disagrees")
                return 1
        positions = [output.find("WOLFOS_BOOT_OK"), entry.start()]
        positions += [output.find(m) for m in markers]
        if any(i < 0 for i in positions) or positions != sorted(positions):
            print("FAIL: ELF64 ELF/PT_LOAD/IRet/Hello/Exit/CR3 cleanup order wrong")
            return 1
        for marker in markers:
            if output.count(marker) != 1:
                print("FAIL: missing/duplicate native ELF proof: " + marker)
                return 1
        for bad in [
            "WOLFOS_ELF_RUN_ERROR", "WOLFOS_RING_PREP_ERROR",
            "WOLFOS_PANIC", "WOLFOS_EXCEPTION_PF",
            "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_UD",
            "WOLFOS_EXCEPTION_DF",
        ]:
            if bad in output:
                print("FAIL: ELF kernel trap rejected: " + bad)
                return 1
        if pf_mode:
            unexpected = (MARKERS[4], STATUS_MARKERS[4], UD_FAULT_MARKERS[4])
        elif fault_mode:
            unexpected = (MARKERS[4], STATUS_MARKERS[4], PF_FAULT_MARKERS[4])
        elif status_mode:
            unexpected = (MARKERS[4], UD_FAULT_MARKERS[4], PF_FAULT_MARKERS[4])
        else:
            unexpected = (STATUS_MARKERS[4], UD_FAULT_MARKERS[4], PF_FAULT_MARKERS[4])
        if any(marker in output for marker in unexpected):
            print("FAIL: wrong guest exit/fault contract was accepted")
            return 1
        if result.returncode != 33:
            print(f"FAIL: expected clean QEMU debug-exit 33, got {result.returncode}")
            print(result.stderr.decode(errors="replace"))
            return 1
        if one_load_mode:
            if (any(marker in output for marker in (
                "WOLFOS_ELF_RUN_OK ", "WOLFOS_ELF_TWO_PT_RUN_OK ",
                "WOLFOS_ELF_THREE_LOAD_RUN_OK ", "frames_freed=7",
                "frames_freed=8", "frames_freed=9",
            ))):
                print("FAIL: one-LOAD acceptance fell back to larger PMM lease")
                return 1
            print("PASS: one genuine RX PT_LOAD and independent RW/NX stack"
                  " -> hardware CPL3 EXIT -> CR3 restored, six PMM frames freed")
        elif three_load_mode:
            if ("WOLFOS_ELF_RUN_OK " in output
                or "WOLFOS_ELF_TWO_PT_RUN_OK " in output
                or "frames_freed=7" in output or "frames_freed=8" in output):
                print("FAIL: 3-LOAD acceptance fell back to smaller PMM lease")
                return 1
            print("PASS: two genuinely executed RX ELF pages, RW+BSS and NX stack"
                  " -> CPL3 EXIT -> restored CR3 and nine PMM frames reclaimed")
        elif two_pt_mode:
            if "WOLFOS_ELF_RUN_OK " in output or "frames_freed=7" in output:
                print("FAIL: two-PT acceptance fell back to legacy seven-frame runner")
                return 1
            print("PASS: two-PT independent ELF -> real CPL3 INT80 -> EXIT -> CR3 restore + eight PMM free")
        elif pf_mode:
            print("PASS: linked ELF64 -> genuine CPL3 denied supervisor read #PF -> status 139 -> 7 PMM free")
        elif fault_mode:
            print("PASS: linked ELF64 -> genuine CPL3 #UD -> status 132 -> CR3 restore + 7 PMM free")
        elif status_mode:
            print("PASS: linked ELF64 -> real CPL3 EXIT(42) -> exact status reap -> CR3 restore + 7 PMM free")
        else:
            print("PASS: linked ELF64 -> validated RX+RW/BSS -> real CPL3 Hello -> EXIT -> CR3 restore + 7 PMM free")
        return 0

if __name__ == "__main__":
    sys.exit(main())
