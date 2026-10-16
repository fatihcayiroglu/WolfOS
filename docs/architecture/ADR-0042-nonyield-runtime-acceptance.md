# ADR-0042 — No-yield Ring3 runtime acceptance plan

Status: proposal (no runtime implementation).

The existing ELF admission gate checks two independent binaries but does not execute them. The next isolated single-BSP QEMU flavor must execute both without voluntary yields, record at least eight genuine xAPIC IRQ-origin cross-PID switches, verify private CR3 and guarded TSS.RSP0 ownership at each handoff, preserve general registers and FXSAVE64 state, and require both programs to exit normally.

Fail closed on stale PID, unexpected interrupt provenance, duplicate EOI, missing fairness evidence, unexpected software yields, or incomplete PMM cleanup. Preserve all existing gates; do not interpret static host checks as proof of timer-driven execution.
