# ADR-0077 — QEMU-only VirtIO feature bank1 selector transaction

Status: **proposed**, draft dependency after PR #308. No authorization
to merge this stack to production `main`.

## Context

ADR-0076 proved read-only QEMU VirtIO common-config bank0, an unclaimed
control queue and an optional EDID feature flag. To negotiate VirtIO 1.2
later, WolfOS must independently establish whether the device advertises
`VIRTIO_F_VERSION_1` (bit 32, represented as bit 0 in feature bank 1).

Reading bank1 requires writing `device_feature_select`. That is a
different risk profile from the earlier purely read-only milestones.

## Decision

An isolated, **QEMU `-device virtio-vga` only** feature runs after all
prior genuine QEMU PCI/BAR/common/device/preflight tests pass.

1. Reuse the BAR measured with exactly restored PCI BAR/COMMAND registers.
   Refuse I/O BAR, invalid aperture, cross-page common capability, managed
   RAM/framebuffer overlap, enabled interrupts or pre-existing VA mapping.
2. On the BSP before any AP starts, map one 4KiB uncached page at
   `0x0000_4000_0000_6000`. Unlike the read-only steps this mapping has a
   temporary **supervisor-only writable** leaf solely for one 32-bit
   selector register. Never use a guessed MMIO HHDM alias.
3. Under the existing preflight contract, first verify device status=0,
   queue enable=0, current feature bank=0 and queue selection=0. If any
   fail, perform **no MMIO writes**.
4. Snapshot selector and bank0 features. Volatile-write selector=1,
   read back selected bank and feature word; **unconditionally** restore
   selector=0 before any validation/early return. Verify selector now0,
   bank0 features byte-for-byte unchanged, status and queue enable still0,
   and bit0 of bank1 advertises `VIRTIO_F_VERSION_1`.
5. Unmap and flush TLB before reporting success. One failed restore or
   invalid readback fails the boot smoke; never treat it as a pass.
6. Mandatory CI launches a fresh genuine QEMU ISO and checks exact proof
   marker order, exactly two selector writes, restoration, bank0 equality
   with the preceding read-only proof, VERSION_1 observation, and **no**
   DMA, queue provisioning or GPU driver activation.
7. No selector writes in default kernels, other QEMU smoke flavors, or
   physical GPU detection. Do not add automatic retry/skip behavior.

## Boundaries

Still no VirtIO ACK/DRIVER/FEATURES_OK/DRIVER_OK handshake,
driver-feature acceptance, queue memory, notify, DMA, real EDID request,
resolution/refresh setup or user-adjustable display controls.
This is a reversible QEMU-only capability proof, not a GPU driver.

Source: VirtIO 1.2 §4.1.4.3 and §6, `device_feature_select` and
`VIRTIO_F_VERSION_1` definition.
