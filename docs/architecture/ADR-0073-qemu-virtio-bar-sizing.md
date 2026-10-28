# ADR-0073 — QEMU-only reversible PCI BAR-size measurement

Status: draft, stacked on PR #304 / ADR-0072.

## Purpose

A real VirtIO GPU MMIO mapping must know the hardware BAR aperture and
prove that the selected common-configuration structure fits within it.
PCI BAR assignment/type from PR #303 is necessary, not sufficient.
This feature is an **explicit isolated QEMU smoke**, disabled by default.

## Transaction

For exact QEMU `1af4:1050`, only in feature
`qemu-virtio-gpu-bar-size-smoke`:

1. Verify the genuine PCI vendor capability chain and assigned BAR type
   read-only. Obtain preferred common-config BAR, offset and length.
2. Snapshot the 16-bit PCI COMMAND and BAR low/high dwords. Disable
   I/O decode, memory decode and bus mastering (COMMAND bits 0..2).
   Write **only 16 bits** of COMMAND: the upper STATUS bits contain W1C
   flags and may NOT be written back from a 32-bit read.
3. While decode is stopped, write all-ones BAR size masks, read back
   hardware-emulated masks and restore every original BAR immediately
   with no early-exit path. A 64-bit BAR is treated as a paired low/high
   register.
4. Restore COMMAND exactly, re-read original BARs and COMMAND, and
   refuse success on any mismatch. Validate power-of-two aperture,
   naturally aligned base and complete in-range common configuration.
5. Emit precise `WOLFOS_VIRTIO_GPU_BAR_SIZE_OK` and boot proof only
   after full rollback + mathematical checks. Mandatory real QEMU smoke
   and strict Python evidence reject missing, forged or duplicate proof.

## Rules and limits

- **QEMU-only** PCI config writes, never physical GPU or disks. The ISO
  is virtual read-only CD-ROM. Existing PCI and BAR read-only features
  continue to issue no device configuration writes.
- No BAR programming persists after the smoke. No MMIO dereference,
  cache policy, DMA, driver binding, feature negotiation, virtqueue
  or real EDID query. A verified aperture does NOT by itself authorize
  kernel mapping or a production driver.
- Treat unexpected QEMU mask/restore mismatch as a hard failing first
  attempt; do not skip tests or claim success on serial marker alone.
- The isolated test does not provide general PCI enumeration for PCIe
  ECAM, OS-managed BAR resource allocation or physical GPU support.

Primary implementation references:
- Linux PCI BAR sizing implementation:
  https://github.com/torvalds/linux/blob/master/drivers/pci/probe.c
- VirtIO PCI capability mapping:
  https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html

Next: OS-owned aperture/resource allocation, page-table MMIO mapping
with PAT/cache flags and strict lifetimes, then bounded VirtIO device
reset/feature negotiation and control-queue transport for GET_EDID.
