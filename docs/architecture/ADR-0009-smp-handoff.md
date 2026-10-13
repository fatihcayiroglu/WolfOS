# ADR-0009: First secondary-CPU Rust handoff

Status: Proposed until GitHub Actions proves the 1-CPU and 4-CPU boots.

## Why
The MADT parser proved that QEMU exposes four CPU records, but not that
WolfOS can actually execute code on secondary processors. This PR adds
a minimal, isolated handoff without prematurely enabling full SMP.

## Mechanism
- Make a Limine MP request (without forcibly enabling x2APIC).
- After BSP-only memory, firmware, paging and framebuffer initialization,
  validate MP CPU count and unique LAPIC IDs.
- Each non-BSP processor uses Limine's MpInfo::bootstrap to enter a Rust
  function on its independently supplied bootloader stack.
- Each AP disables maskable IRQs, writes a unique atomic acknowledgment in
  its assigned static slot (Release) and parks permanently (cli; hlt).
- BSP verifies all expected tokens via Acquire loads and prints counts
  only from BSP so the serial port does not have concurrent writers.
- The handshake remains bounded (256 CPUs maximum in the boot prototype).

## Limitations
This is NOT production multi-core execution:
- No per-CPU GDT/TSS/IDT or IST, no timers, no IPI and no scheduler.
- APs do not touch PMM, PCI config, shared page tables, serial or firmware.
- Limine-provided AP stacks remain alive for the parked processors.
- The current 256 CPU bound is an explicitly scoped prototype limit, not
  the final WolfOS hardware scalability target.
- No user processes, 32-bit support, GPU acceleration or Windows apps.

## Acceptance
- make smoke with 1 CPU: 1 total, 0 secondary acknowledgments.
- make topology-smoke with 4 CPUs: MADT reports 4 CPUs and
  SMP handoff confirms exactly 3 APs ran Rust and acknowledged.
- Existing #UD, #PF and allocation tests remain green.
- No real disk writes.
