# ADR-0045 — Four independently linked Ring3 ELF64 images, real kernel admission only

Date: 2026-10-16
Status: Proposed; full QEMU CI required before merge

## Why
Issue #106 follows the demonstrated two-ELF timer-only hardware round-robin
of #105 and the no-heap generation-safe four-slot policy prototype in #108.
The next separately testable step is admitting **four independent binary
images**, not pretending that four kernel stacks or address spaces exist yet.

## Decision
The experimental `p3-ring3-four-elf-preflight-smoke` Cargo flavor inherits
all existing P2 no-yield xAPIC behavior. GNU as/ld produces four native
ELF64 ET_EXEC applications, parameterized by distinct PID constants.
The host suite inspects all four real executable headers and disassembles
every instruction byte through the EXIT boundary, rejecting hidden syscalls,
traps, forbidden instructions and duplicate PID binaries.

In the actual QEMU kernel path, the established allocation-free ELF preflight
verifies all four separate file images: executable RX code, separately
mapped RW/NX data, correct entry/symbol bounds, unique binary identities
and exactly two PT_LOAD segments. It emits an ordered
`WOLFOS_RING3_FOUR_ELF_PREFLIGHT_OK ... executed=2` marker only after
all four pass. The strict QEMU verifier requires it, and the historical
two-ELF flavor explicitly rejects an accidental extra four-ELF marker.

**Only PID1 and PID2 are executed** in this flavor; they still must satisfy
the original mandatory >=8 real xAPIC timer-origin cross-PID switches,
zero voluntary yields, two real exits and exactly 28 reclaimed PMM pages.
PID3 and PID4 are not loaded into live CR3 roots and never scheduled in
this milestone. All historical hardware and negative tests remain mandatory.

## Next acceptance step, not yet implemented
Provide four disjoint private CR3 roots, guarded supervisor TSS.RSP0 stacks,
per-PID saved full GPR+IRET and FXSAVE images, a verified N=4 queue
handoff path, arbitrary exit ordering and exact PMM retirement. Validate
four actual timer-preempted processes in a distinct QEMU feature, including
fairness, no starvation and zero skips/leaks. Do not close issue #106 on
this image admission milestone alone.
