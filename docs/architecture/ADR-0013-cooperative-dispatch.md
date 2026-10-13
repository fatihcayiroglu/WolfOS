# ADR-0013: Exactly-once cooperative boot job dispatch

Status: Proposed until QEMU and host CI passes.

## Context
PR #14 proved that three secondary CPUs execute independent Rust work
on WolfOS-owned stacks and synchronize through a boot barrier. It did
not dispatch reusable jobs from a shared queue.

## Decision
- Add a no_std, statically bounded queue of 512 deterministic kernel jobs,
  with a per-job state (pending/running/finished), result and per-CPU count.
- Reserve one seed job per CPU to guarantee real participation even under
  slow QEMU time-slicing. CPUs atomically claim remaining jobs from a
  global fetch_add cursor (work-sharing; not preemptive task scheduling).
- Configure once on BSP before secondary CPUs start. After AP-ready,
  BSP releases the existing barrier and also executes queue jobs.
- APs publish Release completion tokens only after they finish boot work
  and queue work, on their own WolfOS stacks with private IDTs.
- BSP waits for all APs (Acquire), verifies all 512 jobs complete, checks
  every deterministic output, checks for duplicate claims and verifies
  that every CPU performed at least its seed job.
- Native Rust host tests exercise 1, 4 and 16 threads, plus replay and
  missing-worker cases; tests deliberately taint reused queues.

## Exclusions
- Not a real OS thread scheduler: no resumable tasks, priorities,
  preemption, context switch, timeslices, user mode or sleep/wake.
- No APIC timer, interrupt routing or IPI work requests are added.
- 512 jobs and 256 CPU slots are boot-prototype limits, not product limits.
- Exact-once output and participation are verified; no benchmark claim.
- QEMU/ISO only. No physical host disk writes.

## Acceptance
- make test: native Rust host concurrency and existing Python tests.
- make smoke: one CPU runs all 512 jobs and zero AP jobs.
- make topology-smoke: four CPUs complete all jobs with BSP and 3 APs.
- Pre-existing CPU exception, paging and device discovery checks remain green.
