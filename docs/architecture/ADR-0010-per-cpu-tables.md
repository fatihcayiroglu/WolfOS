# ADR-0010: Independent per-AP descriptor tables and exception entry

Status: Proposed until normal and 4-vCPU QEMU smoke CI pass.

## Purpose
PR #10 proved 3 APs could run Rust, but they did not install their own
GDT, TSS or IDT. Using the firmware/bootloader's setup indefinitely
would make the eventual scheduler and fault isolation unsafe.

## Decision
- Each AP has its own statically allocated TSS, GDT and IDT, and a dedicated
  20 KiB double-fault IST stack, indexed by unique Limine CPU entry.
- All per-AP memory persists; no heap, reclaim or shared mutable descriptors.
- Each AP disables maskable interrupts, loads CS/SS/DS/ES and TR, verifies
  selectors, loads its private IDT and fires INT3.
- The AP #BP handler records a lock-free global count and returns via IRETQ.
- Each AP then publishes its original atomic acknowledgement and parks.
- BSP verifies all AP acknowledgements and exactly one breakpoint per AP.
- No AP writes serial. Fault handlers on an AP halt immediately.

## Limits and known risks
- 256 AP storage slots are static bootstrapping limits, not final scalability.
- Bootloader-provided AP execution stacks remain in use; this is not stack
  switching or process scheduling.
- AP exception handlers are intentionally minimal and never unwind or recover.
- Double-fault IST stacks have no guard pages yet.
- External interrupts remain disabled; no APIC/IRQ routing, timer, IPIs,
  address-space switching or work-stealing.
- No automatic hardware driver installation or Windows app support.

## Acceptance
- make test source contracts.
- make smoke with 1 CPU requires ap_bp=0.
- make topology-smoke with 4 CPUs requires 3 AP-specific GDT/TSS/IDT
  preparations, 3 DF IST installations, and exactly 3 INT3 handler returns.
- Existing #UD and paging #PF regression tests pass.
- Never run on the user's physical disks.
