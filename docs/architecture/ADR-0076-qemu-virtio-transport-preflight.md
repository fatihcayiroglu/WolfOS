# ADR-0076 — QEMU-only read-only VirtIO transport preflight

Status: **proposed**, stacked after ADR-0075 / PR #307, without production
`main` integration authorization.

## Purpose

WolfOS needs actual EDID and supported monitor modes to select resolution
and refresh rate automatically, while honoring a reversible user override.
Before introducing GPU command transport and DMA-backed virtqueues, prove
the unclaimed QEMU VirtIO-GPU's common configuration fields are readable.

VirtIO 1.2 §4.1.4.3 specifies the common configuration offsets and
`VIRTIO_GPU_F_EDID` (device feature bit 1) indicates EDID support. Merely
reading that feature does **not** retrieve EDID or promise that a physical
monitor supports any particular timing.

## Decision

- Retain the first two read-only MMIO diagnostics and exact QEMU BAR
  measurement/COMMAND rollback. Never presume Limine HHDM covers MMIO.
- Feature-isolate one additional real QEMU boot under
  `qemu-virtio-gpu-transport-preflight-smoke`.
- On BSP before AP startup, explicitly map one already-bounded physical
  common-config page into a private virtual slot, uncached and read-only.
  Reject overlap with RAM, boot framebuffer, or an occupied slot.
- Perform only volatile reads of `device_feature_select` (0x00),
  `device_feature` (0x04), `device_status` (0x14),
  `queue_select` (0x16), `queue_size` (0x18) and
  `queue_enable` (0x1c). The selected feature word is interpreted as EDID
  only if the selector is exactly zero. Refuse nonzero selector,
  nonzero queue selector, active queue, nonzero device status, and invalid
  queue size. These conditions guard a specifically unclaimed QEMU device.
- Never write selectors, device/driver features, queue addresses, device
  status or notifications. No EDID request, DMA, graphic command, cursor
  update, mode change, physical GPU or disk access.
- Unmap and flush TLB **before** register verification/success marker.
- Treat EDID feature bit as a true/false observation and assert exact
  consistency in the real-QEMU serial validator; never fake a yes.
  Additional independent host Rust and Python negative tests complement
  the mandatory real QEMU gate.

## Deferred and risk

No configured queue means no GET_DISPLAY_INFO/GET_EDID, hotplug, actual
resolution or Hz negotiation, and no physical hardware support yet.
If QEMU firmware already claimed the device or switched feature banks,
the smoke fails closed and this code must not be broadened to a production
driver without safe ownership/state restoration and independent verification.

User preferences remain an explicit product requirement, not a feature
that is claimed complete by this PR.
