# ADR-0048: reserve CPU participation before address-space activation

## Problem

The staged `FrameBatch` guard releases its frames on Drop and must never be
used as active-address-space ownership. Process lifecycle bookkeeping also
cannot establish that every CPU has stopped using a private CR3. Observing
only the coordinator's supervisor CR3 leaves a remote activation race.

## Decision

Introduce a bounded, allocation-free `RetirementGate<CPUS>` as a prerequisite
contract, independent of PMM release and existing process/scheduler behavior.
It is deliberately not a frame owner or a reclamation authorization token.

The owner creates one ledger for a globally unique address-space generation,
private root and independently authenticated supervisor root. Serialized
transitions are `Staged -> Live -> Retiring -> Retired`. Staged cancellation
may transition directly to Retiring. Neither Retiring nor Retired can reopen.

Before a CPU can load the private CR3 it must reserve a generation-tagged,
monotonically increasing ticket under the shared coordinator lock. The CPU
then confirms its actual CR3. Starting retirement closes new reservations.
If retirement wins between reservation and the hardware load, confirmation
fails but the outstanding reservation remains pinned. Finishing retirement
requires every reserved and active ticket to drain, including that late load.

Only the ticket's CPU can supply its completed switch back to the registered
supervisor root. Pending hardware work must first be cancelled; otherwise an
acknowledgement could precede the delayed load. Normal deactivation in Live
also drains a ticket. A subsequent activation gets a new epoch, preventing a
delayed or duplicate acknowledgement from clearing the new CPU reservation.
Invalid identity, CPU, roots, epoch exhaustion and rejected transitions leave
state unchanged. The gate supports 1..64 CPU indices, not APIC IDs.

## Required integration invariants

- All operations on a ledger use one exclusive lock; the same generation is
  never represented by multiple ledgers. Every possible CR3 load reserves
  first. The lock orders retirement with reservation, not just confirmation.
- A CPU acknowledges its own observed root after deactivation and completion
  of required local invalidation. A coordinator's CR3 cannot stand in for it.
- The initial contract requires PCID disabled and no private global
  translations. PCID/INVPCID and cross-core TLB/IPI protocols need separate
  hardware validation before extending it to those configurations.
- Saved GPR/IRET, FX state, wait/runqueue references and shared page-table
  ownership must independently be retired before any frame release.
- `Retired` is only ledger state. No method, destructor, ticket or snapshot
  releases a frame or proves the above external hardware invariants.

The existing staging guard and Ring3 execution/cleanup paths remain unchanged.
No general active-user-address-space retirement is enabled by this change.

## Evidence

Host tests cover all 24 acknowledgement orders of four active CPUs, mixed
active/reserved participants, late activation, CPU re-entry with stale epochs,
foreign identities/roots, duplicate messages, terminal states, the highest CPU
bit and epoch exhaustion. Evidence-parser tests reject missing, duplicate,
partial, reordered, fault-bearing or unsuccessful QEMU results.

`make address-space-retirement-smoke` runs 1/4-vCPU QEMU configurations. Before
WolfOS starts AP workers, the BSP copies its complete PML4 into one private
PMM frame while borrowing all original child tables. With IF=0 and PCID=0 it
really loads that CR3, observes rejection while active, restores the original
root and drains its ticket. A second real load occurs after retirement begins
to exercise the reserved-but-unconfirmed race. Only the private PML4 is freed,
after independently verifying the original CR3 is restored; PMM usage must
return exactly to its initial value. Shared tables are never freed.

This is a BSP-only CPL0 proof even in the four-vCPU configuration. It proves
neither Ring3 process retirement nor remote CPU quiescence or TLB shootdown.
The full existing QEMU suite remains mandatory before merging.
