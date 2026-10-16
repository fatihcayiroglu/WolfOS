#!/usr/bin/env python3
"""Fail-closed QEMU acceptance of four genuinely executing no-yield Ring3 ELFs.

Only actual BSP xAPIC timer-IRQ originated preemptions count. Each native ELF
ends in precisely one EXIT(0) INT80; four ordered exits, three nonterminal
handoffs, separate CR3/RSP0/FX and full 50-frame PMM reclamation are required.
This is an isolated QEMU proof, not a production-ready scheduler.
"""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

from user_timer_nonyield_smoke import ordered_evidence_lines

HARDWARE_STEM = "WOLFOS_RING3_FOUR_HARDWARE_OK"
EOI_STEM = "WOLFOS_RING3_FOUR_EOI_OK"
EXIT_STEM = "WOLFOS_RING3_FOUR_EXIT"
SWITCH_STEM = "WOLFOS_RING3_FOUR_EXIT_SWITCH"

ORDERED = (
    "WOLFOS_BOOT_OK",
    "WOLFOS_RING_PREP_OK",
    "WOLFOS_RING3_NONYIELD_PREFLIGHT_OK independent_elf=2 kernel_elf_loader=1 ready_for_execution=1",
    "WOLFOS_RING3_FOUR_ELF_PREFLIGHT_OK native_elf=4 unique_binaries=4 strict_loader=1 rx=4 rw_nx=4 executed=0",
    "WOLFOS_RING3_FOUR_RESIDENT_OK native_elf=4 private_cr3=4 guarded_rsp0=4 owned_frames=47 frame_gprs=4 executed=0 pmm_no_leak=1",
    "WOLFOS_RING3_FOUR_POLICY_FX_OK processes=4 queue_handles=4 fx_images=4 simulated_timer_decisions=32 hardware_irqs=0 fx_wiped=4 executed=0",
    "WOLFOS_RING3_TIMER_HIGH_MMIO_OK uc=1 supervisor_only=1 inherited_cr3=4 eoi_high=1 owned_frames=50",
    "WOLFOS_RING3_TIMER_ARMED_OK real_local_apic=1 user_if=1 no_yield_busy_loops=4",
    "WOLFOS_RING3_FOUR_START_OK native_elf=4 user_if=1 private_cr3=4 guarded_rsp0=4 fx_images=4 owned_frames=50",
    "WOLFOS_RING3_IRQ_READY_OK actual_cpl3_if=1 hardware_int80_traps=4 pid_cr3_rsp0_fx_checks=4 pic_masked=1 timer_armed=1",
    "WOLFOS_RING3_TIMER_CLEANUP_OK actual_irq_eoi=1 lvt_masked=1 pic_restored=1 high_mmio_unmapped=1",
    "WOLFOS_RING3_IRQ_READY_RESTORE_OK original_pic_masks=1 kernel_if_off=1",
    "WOLFOS_RING3_FOUR_CLEANUP_OK frames_freed=50 exited=4 fx_wiped=4 tss_restored=1 cr3_restored=1 pmm_no_leak=1",
)

HARDWARE_PATTERN = re.compile(
    r"WOLFOS_RING3_FOUR_HARDWARE_OK timer_switches=(\d+) "
    r"pid1=(\d+) pid2=(\d+) pid3=(\d+) pid4=(\d+) "
    r"fair_four_min=(\d+) fair_four_spread=(\d+) "
    r"quantum_ticks=2 eligible_irqs=(\d+) "
    r"voluntary_yields=0 exits=4 progress_per_pid=16 "
    r"private_cr3=4 tss_rsp0=4 fx_state=4 executed=4"
)
EOI_PATTERN = re.compile(
    r"WOLFOS_RING3_FOUR_EOI_OK irq_received=(\\d+) eoi_writes=(\\d+) "
    r"same_pid_iret=(\\d+) cross_pid_switches=(\\d+) drained=1"
)
EXIT_PATTERN = re.compile(
    r"WOLFOS_RING3_FOUR_EXIT pid=([1-4]) progress=(\d+) "
    r"private_cr3=1 rsp0_guarded=1"
)
SWITCH_PATTERN = re.compile(
    r"WOLFOS_RING3_FOUR_EXIT_SWITCH from=([1-4]) to=([1-4]) "
    r"private_cr3=1 tss_rsp0=1 fx_saved=1"
)
ERROR_STEMS = (
    "WOLFOS_RING3_YIELD_ERROR", "WOLFOS_PANIC", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_UD", "WOLFOS_EXCEPTION_DF",
    "WOLFOS_RING3_YIELD_TRAP", "WOLFOS_RING3_YIELD_SWITCH",
    "WOLFOS_RING3_NONYIELD_EXIT", "WOLFOS_RING3_NONYIELD_HARDWARE_OK",
)


def strict_four_exit_evidence(output: str) -> bool:
    """Four distinct full-line EXIT records with interleaved forward handoffs."""
    lines = output.splitlines()
    handoffs = [(i, SWITCH_PATTERN.fullmatch(row)) for i, row in
                enumerate(lines) if SWITCH_STEM in row]
    exits = [(i, EXIT_PATTERN.fullmatch(row)) for i, row in
             enumerate(lines) if EXIT_STEM in row and SWITCH_STEM not in row]
    if len(exits) != 4 or len(handoffs) != 3:
        return False
    if any(match is None for _, match in exits + handoffs):
        return False
    pids = [int(match.group(1)) for _, match in exits]
    if len(set(pids)) != 4 or any(int(match.group(2)) != 16 for _, match in exits):
        return False
    for k, (at, match) in enumerate(handoffs):
        if not (exits[k][0] < at < exits[k+1][0]):
            return False
        source, target = int(match.group(1)), int(match.group(2))
        if source != pids[k] or target == source or target in pids[:k+1]:
            return False
    return True


def strict_four_hardware_evidence(output: str) -> bool:
    """Require exact single live four-user proof, real counts, proper position."""
    rows = output.splitlines()
    found = [(i, row) for i, row in enumerate(rows) if HARDWARE_STEM in row]
    if len(found) != 1:
        return False
    at, row = found[0]
    match = HARDWARE_PATTERN.fullmatch(row)
    if match is None:
        return False
    total, p1, p2, p3, p4, fair_min, fair_spread, eligible_irqs = map(int, match.groups())
    counts = (p1, p2, p3, p4)
    if total != sum(counts) or total < 16 or min(counts) < 4:
        return False
    # The fair-four snapshot precedes the first EXIT. Lifetime totals
    # need not remain near-equal after finished PIDs stop accumulating
    # ticks, but while all four run FIFO counts must differ by at most 1.
    if fair_min < 4 or fair_min > min(counts) or fair_spread > 1:
        return False
    # Every *switch* consumes at least two genuine eligible timer IRQs.
    # Same-PID IRQs count as real CPU time, but not as cross-PID switches.
    if eligible_irqs < 2 * total:
        return False
    before = next((i for i, r in enumerate(rows) if
                   r.startswith("WOLFOS_RING3_IRQ_READY_OK ")), None)
    after = next((i for i, r in enumerate(rows) if
                  r.startswith("WOLFOS_RING3_TIMER_CLEANUP_OK ")), None)
    return before is not None and after is not None and before < at < after


def strict_four_eoi_evidence(output: str) -> bool:
    """One physical xAPIC EOI for every authenticated IRQ; no fake switches."""
    rows = output.splitlines()
    found = [(i, row) for i, row in enumerate(rows) if EOI_STEM in row]
    hardware = [(i, row) for i, row in enumerate(rows) if HARDWARE_STEM in row]
    if len(found) != 1 or len(hardware) != 1:
        return False
    eoi_at, eoi_row = found[0]
    hardware_at, hardware_row = hardware[0]
    eoi = EOI_PATTERN.fullmatch(eoi_row)
    proof = HARDWARE_PATTERN.fullmatch(hardware_row)
    if eoi is None or proof is None:
        return False
    received, writes, same, cross = map(int, eoi.groups())
    total, p1, p2, p3, p4, _, _, eligible = map(int, proof.groups())
    if not (received == writes == same + cross
            and cross == total == p1 + p2 + p3 + p4
            and received >= eligible):
        return False
    irq_ready = [i for i, row in enumerate(rows)
                 if row.startswith("WOLFOS_RING3_IRQ_READY_OK ")]
    cleanup = [i for i, row in enumerate(rows)
               if row.startswith("WOLFOS_RING3_TIMER_CLEANUP_OK ")]
    exits = [i for i, row in enumerate(rows)
             if EXIT_STEM in row and SWITCH_STEM not in row]
    return (len(irq_ready) == len(cleanup) == 1 and len(exits) == 4
            and irq_ready[0] < max(exits) < eoi_at < hardware_at < cleanup[0])


def evaluate(output: str, exit_code: int) -> bool:
    if exit_code != 33 or any(stem in output for stem in ERROR_STEMS):
        return False
    if not ordered_evidence_lines(output, ORDERED):
        return False
    if not strict_four_exit_evidence(output):
        return False
    if not strict_four_hardware_evidence(output):
        return False
    if not strict_four_eoi_evidence(output):
        return False
    rows = output.splitlines()
    start = rows.index(ORDERED[8])
    end = rows.index(ORDERED[9])
    exits = [i for i, row in enumerate(rows)
             if EXIT_STEM in row and SWITCH_STEM not in row]
    return len(exits) == 4 and start < min(exits) and max(exits) < end


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_timer_four_live_smoke.py KERNEL_ISO")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ring3-four-live-") as temp:
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
            print("FAIL: four genuine Ring3 timer-scheduled tasks timed out")
            print(log.read_text(errors="replace") if log.exists() else "")
            return 1
        except FileNotFoundError:
            print("FAIL: QEMU unavailable")
            return 1
        output = log.read_text(errors="replace") if log.exists() else ""
        print(output)
        if not evaluate(output, proc.returncode):
            print(f"FAIL: invalid four-live Ring3 IRQ/EXIT/CR3/FX/PMM proof (exit={proc.returncode})")
            return 1
        print("PASS: four actual nonyield ELF64 users, fair real BSP xAPIC timer preemption, "
              "four authentic exits, separate CR3/TSS.RSP0/FX and zero PMM leak")
        return 0


if __name__ == "__main__":
    sys.exit(main())
