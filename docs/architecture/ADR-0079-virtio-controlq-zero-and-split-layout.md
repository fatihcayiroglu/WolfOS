# ADR-0079 — QEMU-only controlq zero-state and split-ring layout

Status: **proposed**, draft stacked after #310. No production merge authorization.

## Purpose

The verified VirtIO 1.2 feature handshake resets the device without setting
DRIVER_OK. Before allocating DMA-capable buffers, inspect the **real QEMU**
control queue (queue0) address registers and derive a strictly bounded,
spec-conformant split-ring memory plan.

## Decision

- Run only under `qemu-virtio-gpu-controlq-ro-smoke`; inherit all previous
  isolated QEMU PCI, BAR, MMIO, feature-bank and reset checks.
- A distinct private virtual page mapped **supervisor-only, uncached and
  read-only** through the verified VirtIO common-config BAR. Refuse RAM and
  framebuffer overlaps, active interrupts, occupied VA, invalid aperture.
- Read `num_queues`, `queue_select`, `queue_size`, `queue_enable`,
  `queue_notify_off`, `queue_desc`, `queue_driver`, `queue_device`,
  `device_status`; split the 64-bit address reads into 32-bit MMIO halves.
- Demand at least two queues (GPU controlq0 and cursorq1), queue0 selected,
  status0, queue disabled, zero descriptor/driver/device physical addresses,
  power-of-two advertised queue size 2..32768.
- Build a pure checked-Rust future split-ring plan, capping descriptor count
  at 256: descriptor `16*n`, available ring `6+2*n`, used ring `6+8*n`,
  with 4096-byte page-rounded lengths. `VIRTIO_F_EVENT_IDX` is not
  negotiated, so event-index trailing fields are excluded.
- Prove future independent physically contiguous areas have non-null,
  4096-aligned addresses, no overflow and no overlap. These are HOST
  contracts only: **no physical buffers have been allocated yet**.
- Unmap MMIO page, flush TLB and require a strict real-QEMU serial marker
  matching the earlier queue size and original num_queues. Earlier smoke
  flavors must reject this proof.
- Never write queue registers, set queue_enable/DRIVER_OK, notify device,
  allocate DMA, change display modes, touch disks or bind a physical GPU.

## Not completed

This PR does not make a functioning VirtIO GPU or perform display queries.
Next: implement PMM-backed ownership of three queue memory areas, validate
physical contiguity and cleanup, configure and reset queue0 in QEMU with
no DRIVER_OK, then actual GET_DISPLAY_INFO/GET_EDID requests and verified
auto resolution + refresh settings with user overrides.

Reference: OASIS VirtIO 1.2 §§2.7 and 4.1.4.3.
