# ADR-0016: BSP-only context-backed task control blocks

Status: Proposed until actual GitHub Actions QEMU CI and code review pass.

## What is added
- Reuse the verified original x86-64 SysV context switch (RBX, RBP,
  R12-R15, RSP) from PR #17; expose one unsafe raw primitive to audited
  kernel-internal callers.
- Correct initial synthetic context frames to eight 64-bit words:
  six saved callee registers, entry PC and a dummy return address,
  so the first Rust instruction sees the SysV ABI-required RSP mod 16 = 8.
- Build three concrete TCBs with distinct 16 KiB stacks, saved RSP,
  existing ThreadState (Ready, Running, Blocked, Finished), progress
  and per-task digest. One deterministic BSP-owned ready FIFO.
- Dispatch these three TCBs from the BSP scheduler stack. A thread
  retains its actual Rust call frame across yield and wake.
- Block thread #1 after its first dispatch, defer its wake until at least
  four total dispatches, then resume it from the stored RSP.
- Verify nine exact task execution events, 18 context switches,
  five yields, one block and wake, all three completions, stack
  canaries and independent digest of every thread.
- Existing state-machine-only 256-TCB queues remain unchanged and
  still run on SMP APs. This prototype shares the ThreadState enum
  but does not yet attach saved RSPs to all 256 of those TCBs.

## Safety and exclusions
- BSP only; APs parked. No migration, work stealing, interrupt-safe
  runqueues, timer preemption or true multicore context switching.
- Interrupts disabled throughout; fatal problems cause fail-stop.
- Switch saves only SysV callee-preserved GPRs and RSP, not FPU/SIMD
  extended state, TLS, CR3, TSS RSP0 or Ring 3 privilege state.
- Stack canaries at bottom but no unmapped guard pages.
- Fixed 3 TCBs and 16 KiB stacks are verification fixtures, not a
  production threads limit.
- QEMU virtual machines only; no real disk writes.

## Acceptance
- make test validates source contracts, ABI initial frame fix.
- make smoke validates WOLFOS_KTHREAD_OK with 3 tasks, 9 dispatches,
  18 switches, 5 yields, 1 block and wake, 3 finishes.
- make topology-smoke validates both the existing four-CPU worker
  tests and the BSP-only context-backed threads.
- Prior #UD, #PF, PMM, ACPI, PCI and SMP tests remain green.
