# ADR-0027 — Multiple resident user-process ownership records

Date: 2026-10-15
Status: acceptance pending two exact-head green CI runs.

## Problem

Merged PR #72 proved two strictly sequential genuine CPL3 launches using
one reused process-record slot. PR #79 proved real user OPEN/READ/CLOSE, but
all those isolated boot flavors still own **one live user process at a time**.
A shell, init service and later user task scheduler will need independent
PIDs and physical address spaces that may all remain resident simultaneously.

## Decision

Add a no_std, fixed-capacity ProcessTable over the existing audited
ProcessRecord lifecycle:

- Mint monotonically increasing PIDs in-kernel, never accept caller-selected
  PID numbers; reject u64 generation exhaustion.
- Admit multiple READY records without heap allocation. Each record holds an
  exclusively PMM-allocated, page-aligned root plus an exact bounded array
  of owned page-table and leaf frames.
- Validate each candidate using the existing ProcessRecord root and within-
  record checks, then reject **any** physical frame alias (including CR3
  roots) against **every live record**, transactionally. Full table/invalid
  PID/root/alias rejections do not consume a PID or mutate a record.
- Enforce at most one RUNNING record until saved CPU context, per-task RSP0
  stacks, interrupt timing and real task preemption are designed.
- Add READY cancellation for never-started processes. It refuses zero or
  still-active CR3 and returns *the exact owned frames* for caller-directed
  PMM release. EXIT and REAP retain their existing mandatory CR3 checks.
- Provide a bounded, fail-closed nonreentrant table cell. It does not
  replace IRQ masking or multi-CPU scheduler locks.

## Hardware evidence

The opt-in `process-table-smoke` QEMU boot allocates four disjoint groups
of seven **real PMM frames**, reserves three distinct PIDs simultaneously,
denies a fourth on table capacity, rejects a request to cancel while the
specified root is active, cancels/reclaims the second PID, rejects a new
root alias to PID 1's still-owned physical page, and admits the fourth PID
through the freed *table* slot without recycling the PID generation.
It cancels all remaining READY processes, releases precisely 28 PMM
frames, compares full PMM allocated counts to the original baseline, and
confirms boot CR3 was never activated as a process root. Exact QEMU
marker ordering, zero faults and debug-exit 33 are mandatory.

Host Rust tests cover inter-PID physical aliases, token/PID reuse,
generation overflow, malformed leases, cancellation, one-running policy,
exit/reap ordering and nested lock denial.

## Explicit limits and next steps

THIS QEMU flavor DOES NOT enter Ring3, switch to a private CR3, implement
a context switch, share kernel stacks between CPUs, or execute more than
one user task. Simultaneously READY does **not** mean concurrently RUNNING.
Old, separate true-Ring3 tests remain required by CI.

Next: give every table entry its own saved user trap-frame/TSS.RSP0
context, prove strict alternating resumptions of two real ELF tasks under
independently owned CR3 roots, then attach input queues and an interactive
WolfShell. Do not claim generic ELF execution or physical-hardware safety.
