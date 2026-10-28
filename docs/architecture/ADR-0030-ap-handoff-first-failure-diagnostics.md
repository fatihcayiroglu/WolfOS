# ADR-0030 — P0 AP handoff first-failure diagnostics

Date: 2026-10-15
Related: issue #83, initial failure on main 029e421a; rerun of the
exact same code passed.

## Evidence / limitation

A four-vCPU QEMU run failed after only 3 of 12 logical AP quanta.
It printed 3 IPI receives, 3 EOIs, 3 completed tasks, then 3
invalid AP shutdowns. The previous logging collapses several distinct
BSP checks into one `valid=false` branch, making the first cause
unidentifiable. The timeout is an *effect* of fail-closed halting, not
by itself proof of a slow host or too-small spin threshold.

## Decision

Keep all original acceptance predicates intact; divide the combined
BSP validation into pure, short-circuit checks for exact paused task
snapshot, owner, epoch, step, digest, mailbox completion, IPIs/EOIs,
claim counts and execution counts. Add adversarial host tests for every
predicate. Record a single first failure phase and observation and print
it only after the BSP aborts and signals STOP, avoiding serial I/O in
the timing-sensitive publication/dispatch/acknowledgement interval.

The QEMU positive-path script rejects any diagnostic marker, every
existing error marker, invalid counts or exit code. No timeout, spin
limit, expected count, task ownership rule, retry allowance or sequence
constraint is changed. This change instruments failures; it does NOT
claim #83 is fixed or that a passed rerun proves reliability.

## Follow-up

Stress repeated exact-head QEMU runs with host CPU contention. If the
problem reproduces, use the first-failure report to distinguish stale
handoff logic from delayed IPI visibility or a sequencing race. Only
then make a narrowly scoped fix. Require an unchanged passing
36+/38-step regression suite and several genuine QEMU repeated
runs before closing #83.
