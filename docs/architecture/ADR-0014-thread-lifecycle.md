# ADR-0014: Per-CPU cooperative kernel task state machines

Status: Proposed pending successful branch, PR and merged-main QEMU CI.

## Context
PR #15 introduced a cooperative, fixed-batch exactly-once kernel job
dispatcher. PR #16 adds separately tracked, resumable-in-data task
state machines and per-CPU queues while preserving the tested job queue.

## Design
- Maintain 256 statically backed task control blocks (TCBs).
- Each TCB follows explicit Ready -> Running -> Ready (yield);
  Running -> Blocked -> Ready (explicit wake); and
  Running -> Finished transitions, with atomic state validation.
- Exactly 4 deterministic steps per TCB. A task yields at step 1 and 3,
  blocks at step 2, wakes when its local ready queue empties, and
  finishes at step 4. Thread state progression is saved as data only.
- Give each CPU its own mutex-protected fixed-capacity ready and blocked
  FIFOs; initial tasks are assigned round-robin by immutable CPU index.
- Run the BSP and AP workers on their existing dedicated kernel stacks
  after the verified SMP work queue. Only BSP writes to serial.
- After all APs finish, require the expected transitions
  (512 yields, 256 blocks/wakes, 256 completions) and individually
  validate every final TCB state, step count and digest.
- No task can be counted twice; failures reject completion rather than
  claiming success.
- Native Rust multithreaded tests use 1, 4, 16 CPUs and negative tests.

## Important limitations
This does NOT context-switch stacks/registers or resume Rust call frames.
Task steps are finite-state computations executed inside the current
worker's stack. There are no timers, IPIs, preemption, address-space
separation, sleeping on real events or user processes. Blocked tasks
are woken cooperatively by their CPU when no ready tasks remain.

The 256-thread, 256-CPU fixed capacity and O(CPUs*threads) queue slots
are bootstrap limits. The per-CPU queue locks are not interrupt-safe and
must not be used from interrupt context. No physical disk I/O.

## Acceptance
- make test: source contract checks and Rust 1/4/16-CPU host tests.
- make smoke: single CPU finishes 256 tasks with expected transitions.
- make topology-smoke: QEMU 4-vCPU verifies the same transitions and
  participation of all four CPUs, while retaining 512-job queue checks.
- All existing #UD/#PF, memory, ACPI, PCI and SMP tests stay green.
