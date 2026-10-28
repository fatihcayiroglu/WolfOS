#!/usr/bin/env python3
"""Strict genuine xAPIC timer IRQ -> BLOCKED CPL3 -> saved IRET QEMU evidence.

This proof is NOT the existing IF=0 userspace SIGNAL acceptance. PID2's
independently linked ELF does zero voluntary yields and zero SIGNAL syscalls.
The kernel verifies the APIC ISR bit in the real IRQ dispatch before EOI,
coordinates the wake and returns PID1's saved WAIT frame after IRQ handoff.
"""
from collections import Counter
from pathlib import Path
import re
import subprocess
import sys
import tempfile

BOOT = "WOLFOS_BOOT_OK"
START = ("WOLFOS_RING3_IRQ_WAKE_START_OK native_elf=2 user_if=1 "
         "real_xapic=1 private_cr3=2 rsp0_guarded=2")
WAIT = ("WOLFOS_RING3_EVENT_TRAP pid=1 kind=wait count=1 "
        "cr3_private=1 rsp0_guarded=1")
EXIT1 = ("WOLFOS_RING3_EVENT_TRAP pid=1 kind=exit count=1 "
         "cr3_private=1 rsp0_guarded=1")
EXIT2 = ("WOLFOS_RING3_EVENT_TRAP pid=2 kind=exit count=1 "
         "cr3_private=1 rsp0_guarded=1")
SWITCH = ("WOLFOS_RING3_EVENT_SWITCH from=1 to=2 "
          "private_cr3=1 tss_rsp0=1 fx_saved=1")
EOI = ("WOLFOS_RING3_IRQ_WAKE_EOI_OK vector=224 source_pid=2 isr=1 "
       "physical_eoi=1 event_receipt=1")
HANDOFF = ("WOLFOS_RING3_IRQ_WAKE_HANDOFF_OK from=2 to=1 real_timer_switch=1 "
           "original_wait_iret=1 cr3_private=1 rsp0_guarded=1 fx_saved=1")
RESUME = ("WOLFOS_RING3_EVENT_RESUME_OK pid=1 wait_return=0 saved_gprs=1 "
          "fx_state=1 real_iret=1")
TIMER_CLEANUP = ("WOLFOS_RING3_TIMER_CLEANUP_OK actual_irq_eoi=1 "
                 "lvt_masked=1 pic_restored=1 high_mmio_unmapped=1")
CLEANUP = ("WOLFOS_RING3_IRQ_WAKE_CLEANUP_OK frames_freed=28 "
           "wait_ticket_drained=1 fx_wiped=2 tss_restored=1 "
           "cr3_restored=1 pmm_no_leak=1")
HARDWARE_RE = re.compile(
    r"^WOLFOS_RING3_IRQ_WAKE_HARDWARE_OK events=1 timer_switches=1 "
    r"signal_syscalls=0 voluntary_yields=0 traps=3 physical_irqs=([0-9]+) "
    r"physical_eois=([0-9]+) private_cr3=2 fx=2$"
)
ERROR_STEMS = (
    "WOLFOS_RING3_YIELD_ERROR", "WOLFOS_PANIC", "WOLFOS_EXCEPTION_PF",
    "WOLFOS_EXCEPTION_GP", "WOLFOS_EXCEPTION_UD", "WOLFOS_EXCEPTION_DF",
    "WOLFOS_RING3_EVENT_REJECTED_OK", "WOLFOS_RING3_EVENT_HARDWARE_OK",
    "WOLFOS_RING3_TIMER_HARDWARE_OK", "WOLFOS_RING3_FOUR_HARDWARE_OK",
)
STEMS = (
    "WOLFOS_BOOT_OK", "WOLFOS_RING3_IRQ_WAKE_", "WOLFOS_RING3_EVENT_TRAP",
    "WOLFOS_RING3_EVENT_SWITCH", "WOLFOS_RING3_EVENT_RESUME_OK",
    "WOLFOS_RING3_TIMER_CLEANUP_OK",
)


def evaluate(serial: str, exit_code: int) -> bool:
    if exit_code != 33 or any(stem in serial for stem in ERROR_STEMS):
        return False
    rows = serial.splitlines()
    hardware = [row for row in rows if row.startswith("WOLFOS_RING3_IRQ_WAKE_HARDWARE_OK")]
    if len(hardware) != 1:
        return False
    m = HARDWARE_RE.fullmatch(hardware[0])
    if not m:
        return False
    irqs, eois = map(int, m.groups())
    if irqs < 1 or irqs != eois:
        return False
    required = [
        BOOT, START, WAIT, SWITCH, EOI, HANDOFF,
        EXIT1, RESUME, SWITCH, EXIT2, hardware[0], TIMER_CLEANUP, CLEANUP,
    ]
    required_counts = Counter(required)
    if any(rows.count(item) != count for item, count in required_counts.items()):
        return False
    # No duplicate, substring, suffix, prefix, malicious line or unexpected
    # same-stem proof accepted, even if the genuine markers also appear.
    if any(any(stem in row for stem in STEMS) and row not in required_counts
           for row in rows):
        return False
    pos = 0
    for line in required:
        try:
            pos = rows.index(line, pos) + 1
        except ValueError:
            return False
    return True


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_event_irq_wake_smoke.py KERNEL_ISO")
        return 2
    for vcpus in (1, 4):
        with tempfile.TemporaryDirectory(prefix="wolfos-ring3-real-irq-") as tmp:
            log = Path(tmp) / "serial.log"
            cmd = [
                "qemu-system-x86_64", "-M", "q35", "-m", "512M",
                "-smp", str(vcpus), "-boot", "d",
                "-cdrom", str(Path(sys.argv[1]).resolve()),
                "-serial", f"file:{log}", "-display", "none",
                "-no-reboot", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
            ]
            try:
                result = subprocess.run(cmd, capture_output=True,
                                        timeout=70, check=False)
            except subprocess.TimeoutExpired:
                print(f"FAIL: genuine IRQ wake QEMU timeout on {vcpus} vCPUs")
                if log.exists():
                    print(log.read_text(errors="replace"))
                return 1
            except FileNotFoundError:
                print("FAIL: qemu-system-x86_64 missing")
                return 2
            output = log.read_text(errors="replace") if log.exists() else ""
            print(output)
            if not evaluate(output, result.returncode):
                print(f"FAIL: real xAPIC ISR/EOI -> BLOCKED PID -> original "
                      f"saved Ring3 IRET proof (vCPUs={vcpus}, "
                      f"exit={result.returncode})")
                print(result.stderr.decode(errors="replace"))
                return 1
            print(f"PASS: verified xAPIC IRQ wakes parked PID1, one EOI per "
                  f"real IRQ, original IRET/FX/CR3, no user SIGNAL/YIELD, "
                  f"and zero PMM leak ({vcpus} vCPUs)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
