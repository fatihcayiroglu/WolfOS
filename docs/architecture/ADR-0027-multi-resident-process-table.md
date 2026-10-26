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

## 2026-10-26 follow-up: counted process PMM ownership (P2)

The fixed-capacity tables now record an explicit `frame_count` for each live
PID. `admit_counted` / `reserve_counted` validate `1..=capacity`, require an
all-zero unused tail, and scan only the exact owned prefix for per-process
duplicates and cross-process aliases. Invalid count, malformed padding, and
inter-PID alias attempts must not spend a PID, occupy a slot, or mutate PMM
ownership metadata. `reserve_batch_counted` stages mixed frame-count
admissions atomically on a private table copy.

READY cancellation, BLOCKED cancellation, and EXITED reaping have explicitly
counted return forms. A returned `CountedFrames` is a transfer of metadata
ownership, not a PMM deallocation: callers must release only `as_slice()`,
once, and only after authenticating the hardware supervisor CR3 and retiring
any CPU/FX, wait-gate, or queue references. The old full-array release API
rejects a counted short lease without mutating state. The existing
`saved_binding_lease` registration path also refuses short leases until
its separate PMM-owner/context-retirement contract is made count-aware;
`saved_binding_lease_counted` exposes the necessary typed handoff.

This P2 step does **not** change actual hardware ELF launch counts, dynamically
allocate kernel process slots, generalize shared Ring3 CPU execution, or
claim arbitrary ELF readiness. Existing true-CPL3 and fixed-flavor QEMU
controls must stay green. Subsequent work will integrate the counted lease
end-to-end with context-retirement and Ring3 process creation.
 
## 2026-10-26 follow-up: count-aware saved-context owner matching (P2)

`Ring3SavedBinding` now reads the registry's typed counted PMM snapshot and
compares precisely that ordered live prefix to the separately held
`ActiveAddressSpace` lease. The owner still authenticates PID generation,
CR3 root, live retirement phase, and exact ordered physical frames; an
extra/missing/reordered page or a stale PID refuses registration without
pinning a new saved-context ticket. Legacy full-array matching remains
fail-closed for partial leases.

Host owner/queue/registry composition tests include all four 6/7/8/9-frame
leases, incorrect frame counts, different CR3 roots, old PID generations,
blocked wait cancellation, and real allocator release-count traces.
This does NOT prove a real CPL3 capture, FPU provenance, scheduler lock,
IRQ wakeup, or generic ELF deployment; those remain external obligations.
 
## 2026-10-26: exact counted owner records in real CPL3 ELF smokes (P2)

The existing independently linked ET_EXEC Ring3 QEMU launch paths now
reserve and reap via `ProcessTableCell<2, 9>` with an exact frame-counted
lease. A validated ELF/page-layout budget (7, 8 or 9 frames in the
existing real hardware flavors) is copied into a zero-padded maximum
capacity slot, then admitted through `reserve_counted`. The table
authenticates the live owned prefix and rejects premature active-CR3
reap. The actual hardware exit/fault cleanup restores supervisor CR3,
performs `reap_with_status_counted`, validates the returned length,
releases exactly that prefix through the real PMM, and proves zero
outstanding pages and no double reap. The fixed count array is now
a per-flavor allocation buffer; it is not the process registry's
declared ownership capacity.

All pre-existing 7/8/9-frame real CPL3 hardware QEMU workflows,
including faults, multi-PID sequential launches, and independent
host ownership tests remain required on the exact PR head.

Scope limit: the tested ELFs are still independently linked fixed
fixtures and preflight still requires the expected flavor-specific
page budget. This does not yet admit arbitrary ELF layouts, reclaim
pages on other CPUs, or offer a production generic process launcher.
