# ADR-0074 — QEMU-only read-only VirtIO-GPU common MMIO proof

Status: **proposed** (stacked draft; NOT production driver support)

## Context

ADR-0073's measured PCI BAR apertures and exact COMMAND/BAR rollback prove
real QEMU PCI configuration behavior. They do **not** prove access to device
registers. Limine's HHDM is a physical-RAM mapping, not a promise that PCI
MMIO exists there; silently dereferencing a BAR through HHDM is unsafe.

WolfOS also needs monitor resolution/refresh auto-selection with user override.
That requirement eventually needs a complete VirtIO driver, EDID/display
capability transport, validated mode negotiation, safe rollback, persistent
user preferences, and hotplug handling. This ADR is only a small prerequisite,
not evidence that those end-user features are implemented.

## Decision

A dedicated `qemu-virtio-gpu-common-mmio-smoke` flavor, never part of the
default boot or a physical-GPU driver:

1. Enumerates precisely one QEMU VirtIO-GPU `1af4:1050` device and reads its
   validated PCI vendor capability chain and BAR assignment.
2. Briefly disables PCI decode, probes the preferred common BAR aperture, and
   restores COMMAND and every touched BAR register **exactly**; stops on any
   failure. This is inherited from the preceding BAR-size smoke.
3. Carries the independently measured BAR base, aperture, common offset/length,
   and memory-vs-I/O classification to the MMIO layer. Rejects I/O BARs,
   unassigned/misaligned/overflowed windows, short common regions, cross-page
   capabilities, and mappings overlapping RAM or the boot framebuffer.
4. On the BSP, with interrupts disabled and before any AP starts, maps exactly
   **one 4KiB page** at private virtual slot `0x0000_4000_0000_3000`.
   Leaf permissions are PRESENT + NO_CACHE + WRITE_THROUGH, **not** writable or
   user-accessible. No presumed MMIO HHDM alias is used.
5. Volatile-reads only `num_queues` (offset 0x12), `device_status` (0x14),
   `config_generation` (0x15). It makes no MMIO writes, queue configuration,
   VirtIO feature negotiation, GPU commands, memory allocation for DMA, or mode
   changes. It unmaps and flushes TLB before validating readback and success.
6. The mandatory CI runs genuine QEMU `-device virtio-vga` and asserts exact
   ordering of the BAR rollback, MMIO read, mandatory gate, framebuffer and
   boot markers. Python offline unit tests are additional, never substitutes
   for that real QEMU boot.

There is intentionally no physical-GPU discovery-to-MMIO binding path.
Other flavors remain read-only or unchanged. CI failure blocks integration.

## Deferred

Multi-page/unaligned common config handling, physical PCI resource manager,
cache-type alias checks, MSI-X, mapped BAR lifetime ownership, virtqueue
transport, interrupt routing, real EDID transport, refresh rates, safe
atomic mode-setting, per-monitor UI controls, hotplug, and real-hardware tests.

## Verification

Evidence must be added from the PR's **first** exact-head GitHub Actions run,
including any failure and the actual fix. A green host mock is not sufficient.
Keep the PR draft and stacked on its dependency until approved for integration.
