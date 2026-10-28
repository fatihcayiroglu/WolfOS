# ADR-0044 — Bounded generation-safe Ring3 ready-queue policy (host-first)

Date: 2026-10-16
Status: Proposed; exact-head CI pending

## Why

The merged #105 QEMU flavor proved two real CPL3 users with >=8 genuine
xAPIC-driven other-PID preemptions and zero cooperative yields. Its
`ring3_round_robin.rs` is intentionally fixed to exactly two slots.

Before changing any hardware return path, the next #106 phase introduces a
**separate four-slot policy prototype** with explicit generation-safe handles.
The existing two-slot hardware scheduler remains unmodified; no test
threshold, QEMU flavor or required hardware evidence is waived.

## Policy invariants

`kernel/src/ring3_runqueue.rs` has a const generic N (validated at N=4),
fixed-size inline slots and **no allocation, FPU operations, MMIO or interrupts**.
It is compiled in the experimental `p2-ring3-timer-nonyield-smoke` kernel
flavor only as an unused candidate, and separately run as real host Rust tests
from the mandatory `make test` stage. No kernel runtime invokes it yet.

Each admission gets a monotonically increasing nonzero generation and PID
pair. Stale handles cannot wake, reap, exit or influence a reused PID. The
state machine supports READY, RUNNING, BLOCKED, EXITED, EMPTY; cancellation is
restricted to non-running tasks. The only operation that counts a timer
*cross-PID switch* is an authenticated IRQ-origin policy `timer_tick`; EXIT,
BLOCK, wakeup and initial dispatch are never misreported as timer switches.
On every failure, the complete policy ledger must remain bit-for-bit unchanged.

Seven host cases verify 80 fair rotations across four PIDs, blocked/wake
ordering, all tasks blocked/idle, generation-based PID reuse rejection, full
queue and cancellation, out-of-order exits, overflow and zero-capacity
behavior. Existing real hardware CI checks remain mandatory.

## Next gate (not yet done)

Implement a new separate QEMU four-ELF real-CPL3 scenario using exclusive
private CR3 roots, guarded pinned high-half TSS.RSP0 stacks, full GPR/IRET
frames, FX state, hardware IRQ provenance and explicit PMM ownership.
Do not replace #105's two-user QEMU scenario. Prove four live runnable user
processes, zero voluntary yields, repeated genuine xAPIC-origin switches,
fairness, generation-safe exit/reap and exact leak-free teardown, with
independent push/PR and post-merge CI.
