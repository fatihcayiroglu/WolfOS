# ADR-0078 — QEMU-only VirtIO 1.2 feature handshake and reset

Status: **proposed**. Isolated draft stacked after #309; no production merge authorization.

## Context

PR #309 proved bit 32 `VIRTIO_F_VERSION_1` using a reversible device-feature bank selector. Later GPU display and EDID requests require an independently proven modern feature negotiation handshake.

## Decision

- Enable only `qemu-virtio-gpu-negotiate-smoke` in a fresh isolated `qemu-system-x86_64 -device virtio-vga` run; never on physical GPUs.
- Run PCI capability, BAR-size exact restoration, read-only MMIO, transport preflight, and #309 feature-bank transaction before negotiation.
- Check one bounded MMIO page, managed RAM and framebuffer disjointness, interrupts disabled, unmapped supervisor-only VA, device-feature bank0, driver-feature bank0, status0 and queue0 unclaimed.
- Use one temporary uncached **supervisor-writable** page. Write `device_status=0` initially; `ACKNOWLEDGE=1`; `DRIVER=3`; select driver-feature bank1; accept only feature bit32 (`VIRTIO_F_VERSION_1`); restore selector0; set `FEATURES_OK=11` and require exact acceptance.
- **Always** write `device_status=0` before evaluating intermediate readback, with bounded reset polling. Require queue0 disabled, unmap and flush TLB.
- Verify genuine QEMU log marker order and fail-closed negative tests. No retries, test skipping or fake green.
- Never set `DRIVER_OK`, allocate queue/DMA, notify, change scanout/mode, or touch real disks.

## Next

Prove bounded controlq virtqueue + PMM ownership/reclamation, then `GET_DISPLAY_INFO` and optional `GET_EDID`, then safe automatic resolution/refresh with manual override, rollback and hotplug.

Reference: OASIS VirtIO 1.2 §§2.1, 2.2, 2.4, 3.1, 4.1.4.3.
