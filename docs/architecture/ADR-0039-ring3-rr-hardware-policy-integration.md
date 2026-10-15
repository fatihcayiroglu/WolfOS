# ADR-0039 — Bind the bounded Ring3 round-robin policy to the real xAPIC acceptance path

Date: 2026-10-16
Status: Proposed; pending complete exact-head QEMU CI.

## Decision

Keep the already merged #95 single-BSP two-ELF xAPIC hardware acceptance completely bounded at **one involuntary timer-induced cross-PID switch per PID**, followed by the existing eight INT80 cooperative yields and two genuine EXITs. Do not claim persistent timer-only multitasking (#96 remains open).

In the dedicated `p2-ring3-timer-preempt-smoke` feature ONLY, instantiate a two-slot, no-heap `RoundRobin` policy ledger. At boot admit each distinct PID and start PID1. During a real, frame-validated hardware timer IRQ from an exact ELF busy interval, the existing full CR3/TSS/FX/IRET validation and test cap must approve the target before the policy `timer_tick` can authorize the cross-PID switch. Subsequent IRQs that return to the same process never invoke the switching policy.

The historical syscall path remains separate. A genuine INT80 YIELD calls `voluntary_yield`, while a genuine EXIT calls `exit`; no voluntary action increments the hardware timer tick counter. Before each actual target IRET, the software-selected PID must equal the hardware-selected PID. After both ELF exits, the policy ledger must report exactly ten state transitions (2 IRQ + 8 syscall), precisely one hardware tick per PID, no active RUNNING PID, and both PID records EXITED.

## Evidence and limits

- Existing required `make test` Rust host tests include denied stale/duplicate PID, counter overflows, missing peers, and explicit interleaved timer/yield/exit.
- The existing real-QEMU `p2-ring3-timer-preempt-smoke` CI gate must now additionally emit a unique, chronologically checked `WOLFOS_RING3_RR_POLICY_OK` marker after policy ledger verification.
- The previously accepted IRQ / ownership / frame / FXSAVE64 / guarded TSS.RSP0 / two CR3 / 28-frame PMM teardown gates stay mandatory and unchanged.
- This is **policy integration with two real timer switches**, not a general preemptive scheduler; it still relies on voluntary yields afterwards and does not prove eight consecutive involuntary handoffs, IRQ nesting, XSAVE, arbitrary Ring3 processes, SMP user scheduling or a stable syscall ABI.

## Follow-up

#96 must introduce a distinct non-yielding user workload and separate single-BSP hardware CI flavor demanding at least eight involuntary cross-PID IRQ switches with fairness and clean EXITs before lifting the two-switch cap. Do not relax the historical gate.
