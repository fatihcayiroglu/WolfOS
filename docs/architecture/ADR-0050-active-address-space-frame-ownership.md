# ADR-0050: transfer staged frames into explicit active ownership

## Problem

FrameBatch rolls back staging allocations on Drop, but an active CR3 may
still use its backing frames. ADR-0048's retirement ledger owns no memory;
ADR-0049's hardware proof manually retains one root. Publishing staging
frames without transferring their ownership risks premature PMM release.

## Decision

ActiveAddressSpace consumes a complete FrameBatch before any CPU can reserve
or load the private CR3. It validates the ledger identity and roots, requires
the root in the batch, rejects a supervisor root anywhere in the batch, and
checks nonzero, aligned, distinct physical addresses below 2^52. It supports
addresses above 64 GiB without truncation. The trusted source must still
guarantee exclusive PMM ownership; address validation cannot authenticate it.
Image admission and mapping permissions remain external responsibilities.

Publication failure returns the original staged guard with automatic
rollback intact. Success wraps the guard in ManuallyDrop and embeds a private
RetirementGate. Neither the ledger nor the staging guard can be extracted or
replaced through the API. Active owners cannot be copied or cloned.

Dropping a live, pending, retiring OR retired owner deliberately retains all
frames. Lost bookkeeping is a leak, never implicit permission to release a
possibly active address space. General lost-owner recovery is not provided.

Reservation, confirmation, retirement and per-CPU acknowledgements delegate
to the embedded ledger. Finishing retirement remains metadata only. The
consuming unsafe reclaim operation requires Retired and independently
established external quiescence: authenticated per-CPU CR3 restoration,
pending-load cancellation, completed local invalidation with PCID disabled,
no surviving private global translations, and no saved contexts, queues,
walkers, aliases or device references that can use the frames. Retired alone
does not authorize reclamation. This change does not add an IPI shootdown.

Reclaim refusal returns the complete owner unchanged. Success extracts the
guard exactly once and uses its existing reverse-order explicit close.
Backend failures are counted and never retried by a destructor; failed
releases remain allocated and require separate allocator diagnosis.

## Hardware integration and limits

The existing isolated four-CPU CPL0 proof now stores an ActiveAddressSpace
under its coordinator lock. Its one-shot BSP initialization borrows the
static PMM provider before any AP starts. All actual CR3 loads reserve on
that owner's ledger. The last AP remains deliberately active while PMM
accounting confirms the entire owned batch is still resident. Only after
all four authenticated CPUs have restored their original CR3 can BSP finish
retirement and call unsafe reclaim, with an exact one-frame release report.
Shared child tables and their unchanged global kernel mappings stay resident.
Every failure after publication retains the active owner or leaks its frames.
The proof's PMM adapter handles UEFI exposing usable physical frame zero:
it holds zero while allocating a nonzero root, then returns zero before
publication (also on allocation exhaustion). Freeing zero before retrying
would continually select it again. The ledger's nonzero-root validation is
preserved; this does not reserve frame zero globally or change PMM policy.

Before AP release, an additional real BSP CR3 roundtrip deliberately drops a
separate active owner. PMM usage must stay exactly one above baseline while
its CR3 is still active. BSP then restores the original root unconditionally.
Only this isolated test, with sole-CPU access, no saved context or pending
load, independently recovers that intentional one-frame leak and verifies
the baseline. This is not a general process recovery mechanism.

The runner requires both exact ordered ownership and four-CPU retirement
proofs, normal boot and debug exit 33. Missing/duplicate/decorated/reordered
evidence, hardware faults and failed exits remain failures. All historical
P0 gates remain mandatory. Host tests exercise observable release effects,
all 24 four-CPU departure orders, stale and pending reservations, failed
publication rollback, all Drop phases, release failures and high addresses.

This bounded owner/proof does not integrate arbitrary Ring3 saved-context
retirement, dynamic scheduling, CPU hotplug, PCID/INVPCID, live page-table
mutation, private global translations or IPI TLB shootdown. Production
multicore process teardown and crash recovery remain separate work.
