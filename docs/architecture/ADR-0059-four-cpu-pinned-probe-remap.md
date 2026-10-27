# ADR-0059 — Four-CPU pinned-probe remap observation

## Decision

Extend only the existing `tlb-shootdown-hardware-smoke` QEMU flavor. Before AP startup, the BSP allocates two distinct PMM frames, writes different 64-bit markers through the HHDM, and installs one supervisor-only, NX, writable probe page in the shared boot CR3. Both frames and the mapping's page tables remain pinned for the entire boot. They are never returned to the PMM during this test.

The existing xAPIC UC alias remains mapped, so the test can always send IPIs and issue local EOIs.

Three rounds use the same four-vCPU generation/epoch-tagged barrier and the pre-existing last-AP withholding check:

1. Every target AP invalidates the xAPIC alias and probe virtual address locally, reads marker **A** from the real mapped page, then acknowledges.
2. Only after round 1 has fully completed, the BSP replaces the probe PTE with the pinned frame **B** and invalidates its own translation. Every AP executes its own `INVLPG`, reads **B**, and then acknowledges.
3. Only after round 2 has fully completed, the BSP remaps back to pinned frame **A**. Each AP must invalidate, read **A**, and acknowledge. The last AP's IPI is intentionally withheld until pending state and blocked next-epoch admission have been independently observed.

The BSP must never change the PTE while an IPI round is in flight. AP reads happen only in the local fixed-vector handler, under the same no-allocation lock as the barrier. The host parser requires exactly two remaps, nine probe-local invalidations, nine correct reads, nine original APIC-alias invalidations, and successful QEMU exit.

## Boundaries

- This is real hardware-emulated CPU/PTE behavior for a **supervisor** test mapping in QEMU, not an unmapped Ring3 page, saved user CR3, production scheduler, or general-purpose shootdown protocol.
- The two physical frames are deliberately **never freed**. Correct markers and complete acknowledgements do not prove that physical reclamation is safe.
- PCID is disabled. No private-global or retained-PCID invalidation coverage is claimed.
- Other CPU identity, generation, hotplug, shared-page walks, device access, fault handling, and external coordinator-lock obligations remain separate.
- QEMU may perform broader internal translation invalidation than real hardware. This test proves that each AP executes the ordered invalidation and observes the new mapping; it cannot independently prove that a stale cache would have persisted without `INVLPG`.
- No physical disk access, partitioning, installation, or user-data mutation is involved.
- Any missing IPI, wrong marker, invalid remap, timeout, or changed output count is a **test failure**, not an inferred acknowledgement.
