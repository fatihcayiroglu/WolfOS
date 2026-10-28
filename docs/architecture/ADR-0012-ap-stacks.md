# ADR-0012: WolfOS-owned AP kernel stacks and independent CPU work

Status: Proposed until all actual QEMU tests pass.

## Context
PR #10 starts APs in Rust. PRs #11 and #13 give each AP private GDT,
TSS, double-fault IST and IDT, with verified breakpoint return. Until
now APs ran on Limine's temporary per-processor stack.

## Choice
- Reserve one permanent, 16-byte-aligned 32 KiB WolfOS-owned stack per
  Limine CPU slot (max 256 slots in this bootstrap configuration).
- BSP prepares per-CPU canaries before publishing each MP entrypoint.
- The AP's Limine bootstrap entry switches stacks using a tiny x86-64
  assembly trampoline (RDI=MpInfo*, RSI=index, RDX=new stack top).
  It aligns RSP, CALLs a never-returning Rust symbol and never resumes
  a Rust frame on the old stack.
- The new Rust entry verifies RSP bounds and canary; installs its
  pre-existing private GDT/TSS/IST/IDT and tests its own INT3 return.
- Every AP publishes a ready token, waits at an Acquire/Release barrier,
  performs 32768 deterministic integer iterations, checks its canary
  again, publishes a result and completion token, then parks.
- BSP releases the work barrier only after all APs are ready and
  verifies every result against an independently computed expected value.
- The BSP alone logs all test outcomes. APs never use the serial device.

## Limitations
- Single bootstrap milestone, not an SMP task scheduler. No preemption,
  timers, thread context switching, user processes or CPU hotplug.
- Fixed 256-slot bank costs up to 8 MiB BSS; 32 KiB stacks have no
  guard pages yet. Future boot should allocate sparse per-CPU stacks
  from PMM and protect them with unmapped guard pages.
- APs keep Limine MpInfo mappings; stack switch does not free the
  bootloader-owned stack.
- A barrier plus successful work on three APs proves cross-CPU code
  execution, not a particular parallel speedup or scheduling fairness.
- No real-disk writes; QEMU only.

## Acceptance
- Single-vCPU QEMU: 0 AP stacks switched, 0 work results; boot finishes.
- Four-vCPU QEMU: 3 independent 32 KiB stacks, 3 IDT/INT3 returns,
  3 CPU results matching 32768 iterations each, final WOLFOS_BOOT_OK.
- Existing source checks, #UD and #PF QEMU tests remain green.
