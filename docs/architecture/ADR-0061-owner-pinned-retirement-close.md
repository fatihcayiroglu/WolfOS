# ADR-0061: An armed retirement round must gate owner closure

Status: Experimental, narrowly scoped four-vCPU CPL0 evidence; not general Ring3 reclamation.

## Context

ADR-0060 demonstrated real CPU-local supervisor CR3 reloads before a private PML4
was freed. However, `ActiveAddressSpace::finish_retirement()` still accepted a
CPU/context-empty owner after an independently published retirement shootdown,
even if one targeted CPU had not acknowledged its local invalidation. An external
caller could accidentally retire that owner early, while the unsafe PMM reclaim
contract remained separate.

## Decision

- A move-only `ActiveAddressSpace` stores the single generation-tagged
  `Round` it successfully published through `begin_retirement_shootdown`.
  A second publication is rejected without mutating the original barrier.
- Each barrier instance gets a monotonic non-reused identity, embedded in its
  opaque `Round`. A distinct barrier of the same generation and epoch cannot
  acknowledge or complete the owner's published round. Identity exhaustion
  refuses construction rather than wrapping.
- Once a round is armed, legacy `finish_retirement()` refuses with
  `OutstandingShootdown`, even if all CPU reservations and saved contexts have
  already drained.
- `finish_retirement_after_shootdown(barrier, round)` checks the exact recorded
  round, address-space generation, the historical CPU target mask and completed
  acknowledgement state before closing the context and CPU retirement gates.
  Any mismatch or missing last acknowledgement preserves the owner.
- The four-vCPU QEMU harness now explicitly proves legacy finish is rejected
  while the final AP is held, and invokes the new method only after all four
  real local CR3 reloads. Host tests reject wrong generation, a different round
  epoch, rearming, and incomplete last-CPU coverage.

## Boundary / obligations

This API checks coordinated metadata after callers perform genuine hardware
operations. `ShootdownBarrier` is not an interrupt delivery mechanism and its
acknowledgements are caller-authenticated unsafe operations. This change
does **not** prove general IPI-backed Ring3 unmapping, PCID/global invalidation,
hotplug/offline CPUs, device DMA quiescence, or reclamation of borrowed child
page tables. The existing unsafe `reclaim()` still requires external proofs.

Owners that never armed a shootdown retain the earlier legacy metadata-only
finish path for existing simulated and single-CPU callers. Future production
Ring3 memory reclamation must require the stricter path and independently
account for every other hardware reference.

No physical disks are accessed by these tests; QEMU boots from disposable ISO
images. Failures and timeouts retain frames rather than relaxing any gate.
