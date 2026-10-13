# ADR-0011: Each AP loads its own IDT and returns from INT3

Status: Proposed until GitHub Actions verifies actual 1-vCPU and 4-vCPU QEMU boots.

## Context
PR #11 already merged per-AP GDT/TSS, independent double-fault IST
and a shared, immutable IDT. This follow-up deliberately preserves that
tested implementation instead of re-creating GDT/TSS/IST storage.

## Changes
- Reserve a permanent distinct AP IDT for every Limine CPU directory slot.
- On each AP, after loading its existing private GDT and TSS, build and
  load the private IDT (fatal handlers halt without concurrent serial).
- Generate an INT3 on the AP. Its own #BP handler increments an atomic
  counter and returns via IRETQ; then the AP publishes its existing
  release-ordered SMP acknowledgement and parks.
- On the BSP, acquire the AP acknowledgements, verify exactly one #BP
  return per AP and print explicit success only after the count matches.

## Acceptance
- Normal 1-vCPU QEMU boot: 0 APs, 0 AP breakpoints.
- Four-vCPU QEMU boot: 3 AP IDTs, 3 AP INT3 returns and 3 SMP ACKs.
- Source contracts and existing #UD/#PF regressions remain green.

## Boundaries
- Not a scheduler or process execution. The AP still runs on its Limine
  boot stack, with external IRQs disabled and no APIC/IPI routing.
- Fatal exceptions on APs fail-stop; no general concurrent logging.
- 256 slots and 20 KiB unguarded IST stacks are bootstrap limits.
- Host data disks are never accessed.
