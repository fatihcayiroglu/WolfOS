# ADR-0015: First real saved-register/RSP context switch

Status: Proposed, requires green GitHub Actions QEMU smoke and review.

## Purpose
PR #16 introduced per-CPU cooperative task state machines but no saved
execution contexts. This PR independently proves two real Rust call stacks
can suspend/resume without discarding the in-progress call frame.

## Design
- Use x86-64 SysV-compatible assembly to push/pop RBX, RBP, R12-R15,
  preserve RSP in a context slot and return to a different saved PC.
- Build two fresh, statically backed 16 KiB kernel stacks with aligned
  initial frames containing the six saved registers and entry address.
- Run the experiment on the boot CPU only **after** all AP work has ended
  and the APs are parked; no shared runqueue/scheduler mutation.
- Task A and Task B alternate three times. On the seventh switch, Task B
  returns directly to the original BSP stack.
- Verify exact event ordering (A, B, A, B, A, B), both finished flags,
  saved context switch count, and stack-bottom canaries.
- Fail-stop for corrupted stacks or unexpected task returns.
- No host physical disks are touched; all tests run inside QEMU.

## Why separate from full SMP task scheduling
x86-64 ABI callee-saved general registers and RSP are only one part of a
complete kernel context. A production scheduler must also address:
- interrupt-safe preemption and lock ownership;
- thread TLS/GS, FPU/SIMD XSAVE state and address space transitions;
- stack isolation/guard pages and separate privilege-level RSP0 stacks;
- yielding while holding locks and later resuming on different CPUs;
- per-CPU run queues and fairness with work stealing and timers.

This PR does NOT wire switch() into the 256 task-state machines from #16,
does not migrate contexts between CPUs, enable preemption, enter Ring3,
or execute Windows/Steam software.

## Acceptance
`make smoke` and `make topology-smoke` both require
WOLFOS_CONTEXT_OK tasks=2 switches=7 events=6 stacks_kib=16.
Existing CPU #UD, paging #PF, ACPI/PCI, PMM and SMP tests stay green.
