# ADR-0071 — Read-only PCI BAR kind/assignment proof for VirtIO-VGA

Status: draft, stacked on ADR-0070 / PR #302.

## Decision

For the QEMU-only feature `qemu-virtio-gpu-bars-smoke`, inspect the
genuine VirtIO-VGA PCI BAR registers at config offsets 0x10..0x24 after
checking the mandatory common/notify/ISR/device vendor capabilities.
Classify referenced BARs as I/O, 32-bit memory, or 64-bit memory;
disallow unavailable/zero base addresses, reserved memory BAR types,
the high half of a 64-bit BAR, and malformed 64-bit BAR5.
Multiple capabilities may legally reference one BAR. The host-only
validator includes 11 tests, with a mandatory second genuine QEMU boot
and a strict serial proof, on top of the existing PCI-only smoke.

Primary specification:
https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html
(section 4.1.3 PCI Device Layout and 4.1.4 vendor-specific mappings).

## Strict boundaries

- **Reads only:** 0xCF8 device-selection writes and 0xCFC reads, never
  PCI BAR write-probing, device config writes, MMIO or DMA.
- This proves *assigned BAR register type*, NOT actual BAR aperture
  size, address-space mapping, region containment, safe register access,
  virtqueue transport, feature negotiation or any loaded GPU driver.
- No physical disk or graphics card is accessed; QEMU ISO is a virtual
  read-only CD-ROM.
- Future work: resource-aware BAR size/ownership source, kernel-owned
  MMIO mapping with page permissions, reset/feature-negotiation,
  bounded DMA/virtqueues, fenced GET_EDID, then auto/manual modes.
- VirtIO 1.2 allows multiple vendor capability instances, including
  alternative notification BARs. The earlier #302 proof is intentionally
  a narrow QEMU four-capability subprofile and is **not yet general
  VirtIO GPU device coverage**. Do not claim broad GPU support.
