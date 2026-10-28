# ADR-0028 — Audited per-process user return frames and RSP0 stacks

Date: 2026-10-15
State: PR acceptance pending; no live user context handoff in this change.

## Context

PR #80 permits several simultaneously READY processes with disjoint
PMM frame ownership. PRs #71-#79 exercise real isolated CPL3 ELF calls,
but still one live hardware user stack, CR3, TSS.RSP0 per smoke. Kernel
task preemption and FXSAVE code exists on distinct IRQ-specific paths;
it is **not** safe to apply its kernel-stack-only switch directly to
multiple user processes.

## Decision

Add `UserContextBank<N>`, a heap-free fixed-capacity bank of exact
`UserSyscallFrame` values (15 saved GPRs + RIP/CS/RFLAGS/RSP/SS).
Each stored frame owns immutable metadata identifying one live PID,
the PID's PMM-owned private root, and an independently allocated 16 KiB
kernel RSP0 stack interval. No pointer into an old IRQ stack is retained.

The model provides two distinct origins:

* `Bootstrap`: explicit loader-generated initial frame for a READY PID.
  No claim that a hardware user trap took place.
* `HardwareTrap`: copied kernel INT80 frame for a RUNNING PID under
  precisely the matching live CR3, with saved frame address inside its
  kernel RSP0 stack. The caller must independently read CR3 and verify the
  trap before invoking this method; the bank does not read CPU registers.

Refuse zero/stale PIDs, CR3 mismatch, out-of-range/misaligned physical
roots, duplicate PIDs, overlapping RSP0 stack intervals, bad user-space
RIP/RSP ranges, invalid RFLAGS (IF, TF, IOPL etc), non-CPL3 selectors,
and frames outside RSP0 allocation. Admission is transactional. No
user-created data is used as a raw kernel pointer.

`plan_next` checks live PID/root ownership again and selects a distinct
PID deterministically without changing the CPU, TSS or process state.
It denies any context whose private user CR3 is still reported active.
A context can be retired only after the owning PID has been removed
from the live process table, preventing stale frame resurrection.

## Hardware evidence and hard limits

Dedicated `user-context-smoke` QEMU boot allocates two actual,
nonoverlapping seven-frame PMM leases, obtains the real boot CR3, uses
two distinct statically allocated 16 KiB kernel stacks, and prepares
two synthetic bootstrap frames. It verifies 64 alternating *plans* with
preserved R12/R13 GPR signatures, rejects a private CR3 as the kernel
root, denies retirement of live PID state and returns all 14 frames
to PMM. Full existing true-CPL3 checks remain required independently.

This change does **not** perform real user A→B switches, save or restore
FPU/SSE/AVX state, write TSS.RSP0, validate live PTE mappings for RIP/RSP,
pin memory, handle asynchronous faults, or install new GDT descriptors.
Kernel-stack static allocations are test fixtures, not real per-process
dynamic kernel stack ownership. A `ResumePlan` is NOT an IRET authorization.

## Future acceptance before genuine Ring3 handoff

1. Dynamically allocate a guarded RSP0 stack per real PID and verify its
   virtual/physical mapping, canaries and lifetime under interrupts.
2. Introduce exact per-process xstate policy (CPUID/XGETBV/XSAVE where
   applicable); save/restore per-task xstate with interrupt-side rules.
3. Add a genuine INT80 or timer-preempted two-user task scheduler that
   copies hardware frames on the proper stack, suspends ownership,
   changes CR3 and TSS.RSP0 under IF=0 and resumes by IRETQ, with
   correct per-process CR3/root guards on *every* transition.
4. Validate two distinct ELF images, interleaved genuine CPL3
   instructions/syscalls, no cross-PID memory aliases, safe fault
   handling and leak-free cleanup in QEMU and then real hardware.
5. Preserve all existing gates. Never treat a context-plan test as
   proof that concurrent user execution works.
