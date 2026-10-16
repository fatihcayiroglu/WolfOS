#!/usr/bin/env python3
"""Fail-closed real QEMU acceptance for two native non-yielding Ring3 ELFs.

Only hardware xAPIC IRQ-origin switches count. Each ELF uses exactly one
INT80 for its final EXIT; its instructions contain no voluntary yields.
This intentionally does not attest a production or multi-CPU scheduler.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

MIN_SWITCHES = 8
MIN_PER_PID = 4
PREFIX = "WOLFOS_RING3_NONYIELD_HARDWARE_OK "
ERRORS = (
    "WOLFOS_RING3_YIELD_ERROR", "WOLFOS_PANIC", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_UD", "WOLFOS_EXCEPTION_DF",
    "WOLFOS_RING3_YIELD_TRAP", "WOLFOS_RING3_YIELD_SWITCH",
)


def fail(why, output=""):
    print("FAIL:", why)
    if output:
        print(output)
    return 1



def exit_markers_well_formed(output):
    """Reject duplicate, truncated, or forged extra EXIT/EXIT_SWITCH evidence."""
    lines = output.splitlines()
    exits = [line for line in lines if line.startswith("WOLFOS_RING3_NONYIELD_EXIT ")]
    handoffs = [line for line in lines
                if line.startswith("WOLFOS_RING3_NONYIELD_EXIT_SWITCH ")]
    exit_pattern = (r"WOLFOS_RING3_NONYIELD_EXIT pid=[12] progress=\d+ "
                    r"private_cr3=1 rsp0_guarded=1")
    handoff_pattern = (r"WOLFOS_RING3_NONYIELD_EXIT_SWITCH from=[12] to=[12] "
                       r"private_cr3=1 tss_rsp0=1 fx_saved=1")
    if len(exits) != 2 or len(handoffs) != 1:
        return False
    if not all(re.fullmatch(exit_pattern, line) for line in exits):
        return False
    if not re.fullmatch(handoff_pattern, handoffs[0]):
        return False
    exit_pids = {re.search(r"pid=([12])", line).group(1) for line in exits}
    handoff = re.search(r"from=([12]) to=([12])", handoffs[0])
    return exit_pids == {"1", "2"} and handoff.group(1) != handoff.group(2)

def main():
    four_elf_preflight = len(sys.argv)==3 and sys.argv[2]=="--four-elf-preflight"
    if len(sys.argv) not in (2,3) or (len(sys.argv)==3 and not four_elf_preflight) or not Path(sys.argv[1]).is_file():
        print("Usage: user_timer_nonyield_smoke.py KERNEL_ISO [--four-elf-preflight]")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ring3-nonyield-") as temp:
        log = Path(temp) / "serial.log"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-smp", "1", "-boot", "d", "-cdrom",
            str(Path(sys.argv[1]).resolve()),
            "-serial", f"file:{log}", "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=70, check=False)
        except subprocess.TimeoutExpired:
            return fail("no-yield Ring3 xAPIC smoke timed out",
                        log.read_text(errors="replace") if log.exists() else "")
        except FileNotFoundError:
            return fail("QEMU is unavailable")
        output = log.read_text(errors="replace") if log.exists() else ""
        print(output)
        if proc.returncode != 33:
            return fail(f"unexpected QEMU return status {proc.returncode}")
        if any(error in output for error in ERRORS):
            return fail("unexpected exception, voluntary yield, or kernel error")

        ordered = [
            "WOLFOS_BOOT_OK",
            "WOLFOS_RING_PREP_OK",
            "WOLFOS_RING3_NONYIELD_PREFLIGHT_OK independent_elf=2 kernel_elf_loader=1 ready_for_execution=1",
            "WOLFOS_RING3_TIMER_HIGH_MMIO_OK uc=1 supervisor_only=1 inherited_cr3=2 eoi_high=1 owned_frames=28",
            "WOLFOS_RING3_TIMER_ARMED_OK real_local_apic=1 user_if=1 no_yield_busy_loops=2",
            "WOLFOS_RING3_NONYIELD_START_OK native_elf=2 user_if=1 private_cr3=2 guarded_rsp0=2 fx_images=2 owned_frames=28",
            "WOLFOS_RING3_IRQ_READY_OK actual_cpl3_if=1 hardware_int80_traps=2 pid_cr3_rsp0_fx_checks=2 pic_masked=1 timer_armed=1",
            PREFIX,
            "WOLFOS_RING3_TIMER_CLEANUP_OK actual_irq_eoi=1 lvt_masked=1 pic_restored=1 high_mmio_unmapped=1",
            "WOLFOS_RING3_IRQ_READY_RESTORE_OK original_pic_masks=1 kernel_if_off=1",
            "WOLFOS_RING3_NONYIELD_CLEANUP_OK frames_freed=28 exited=2 fx_wiped=2 tss_restored=1 cr3_restored=1 pmm_no_leak=1",
        ]
        if four_elf_preflight:
            ordered.insert(3,
                "WOLFOS_RING3_FOUR_ELF_PREFLIGHT_OK native_elf=4 unique_binaries=4 strict_loader=1 rx=4 rw_nx=4 executed=2")
        elif "WOLFOS_RING3_FOUR_ELF_PREFLIGHT_OK" in output:
            return fail("four-ELF evidence unexpectedly appears in legacy two-ELF flavor")
        locations = [output.find(x) for x in ordered]
        if any(i < 0 for i in locations) or locations != sorted(locations):
            return fail("required QEMU hardware evidence missing or out of order")
        if any(output.count(x) != 1 for x in ordered):
            return fail("duplicated hardware evidence marker")
        if not exit_markers_well_formed(output):
            return fail("malformed, duplicate, or unexpected EXIT evidence")
        exits = re.findall(
            r"^WOLFOS_RING3_NONYIELD_EXIT pid=([12]) progress=(\d+) private_cr3=1 rsp0_guarded=1$",
            output, flags=re.MULTILINE,
        )
        if sorted(exits) != [("1", "16"), ("2", "16")]:
            return fail("both native ELF64 processes must actually EXIT once with progress 16")
        exit_locations = [
            output.find("WOLFOS_RING3_NONYIELD_EXIT pid=1"),
            output.find("WOLFOS_RING3_NONYIELD_EXIT pid=2"),
        ]
        irq_ready_at=output.find("WOLFOS_RING3_IRQ_READY_OK actual_cpl3_if=1 hardware_int80_traps=2")
        if irq_ready_at<0 or max(exit_locations)>irq_ready_at:
            return fail("exit marker must precede final IRQ readiness evidence")
        exit_switches = re.findall(
            r"^WOLFOS_RING3_NONYIELD_EXIT_SWITCH from=([12]) to=([12]) "
            r"private_cr3=1 tss_rsp0=1 fx_saved=1$",
            output, flags=re.MULTILINE,
        )
        if len(exit_switches) != 1 or exit_switches[0][0] == exit_switches[0][1]:
            return fail("first EXIT must activate the other remaining user PID exactly once")
        switch_at = output.find("WOLFOS_RING3_NONYIELD_EXIT_SWITCH ")
        if not (min(exit_locations) < switch_at < max(exit_locations)):
            return fail("exit handoff must happen between two genuine user EXITs")
        lines = [line for line in output.splitlines() if line.startswith(PREFIX)]
        if len(lines) != 1:
            return fail("must have exactly one genuine timer switch evidence line")
        match = re.fullmatch(
            r"WOLFOS_RING3_NONYIELD_HARDWARE_OK timer_switches=(\d+) "
            r"pid1=(\d+) pid2=(\d+) voluntary_yields=0 exits=2 "
            r"progress_per_pid=16 private_cr3=1 tss_rsp0=1 fx_state=1",
            lines[0],
        )
        if not match:
            return fail("unrecognized timer hardware evidence")
        total, pid1, pid2 = map(int, match.groups())
        if total != pid1 + pid2 or total < MIN_SWITCHES or                 min(pid1, pid2) < MIN_PER_PID or abs(pid1 - pid2) > 1:
            return fail("insufficient or unfair independently counted real xAPIC handoffs")
        print(
            f"PASS: {total} genuine xAPIC IRQ-driven Ring3 cross-PID handoffs, "
            "two no-yield native ELF64 processes, separate CR3/TSS/FX, "
            "exactly two EXIT calls, 28 PMM frames reclaimed, zero skips"
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
