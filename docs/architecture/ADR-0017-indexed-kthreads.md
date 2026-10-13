# ADR-0017: Indexed context-backed kernel task pilot

Status: Proposed until the latest push and PR GitHub Actions QEMU suites pass.

## Motivation
PR #16 introduced 256 kernel task state-machine TCBs per-CPU, but without
real saved execution contexts. PR #18 demonstrated three real BSP-only
TCBs, using a distinct Rust function for each TCB. Before converting
all 256 state-machine tasks, prove indexed generic context entry and
a bounded runqueue supporting more independent stacks.

## Implementation
- Introduce 16 additional test TCBs, each with permanent 16 KiB stack,
  saved RSP, Ready/Running/Blocked/Finished state, progress and digest.
- Share the public ThreadState definition and THREAD_COUNT capacity
  contract with PR #16 (but do not mutate its existing 256 tasks).
- A generic x86-64 initial-entry trampoline restores the TCB id via
  callee-saved R12, moves it to SysV arg register RDI, aligns RSP
  and calls a single never-returning Rust task entry.
- Use the original PR #17 register/RSP switch primitive (ABI-aligned
  synthetic 8-word frame), not an invented setjmp/longjmp.
- BSP owns one fixed-capacity FIFO, 16 task stacks and a single blocked
  queue slot. Thread #1 blocks after its first dispatch; it is
  explicitly awakened after 20 dispatches.
- All 16 threads execute four rounds each: verify 64 dispatches,
  128 actual switches, 47 yields, one block/wake, 16 finishes.
  Additionally verify every per-thread state, progress, checksum,
  stack-bottom canary, initial FIFO order and exactly four logged
  execution events per TCB.
- Preserve all existing three-context, 256-TCB state-machine, SMP, PCI,
  ACPI, PMM, paging and CPU exception acceptance checks.

## Boundaries
- This is a *pilot*, not full integration of 256 context-bearing TCBs.
  The existing 256 per-CPU state machine tasks remain as before.
- Only BSP executes these contexts, after APs have parked.
- No real interrupt-driven scheduler, thread migration, work stealing,
  FPU/SIMD/XSAVE handling, TLS/GS switching, TSS RSP0, Ring3 or CR3.
- Canaries are not memory guard pages. The 16 x 16 KiB static stack bank
  is a bounded, dedicated test fixture; no dynamic allocation.
- QEMU only, no host real disks are accessed.

## CI
`make test`, `make smoke`, `make exception-smoke`,
`make paging-fault-smoke` and `make topology-smoke` must remain green on both branch
and pull request commits before the PR can be merged.
