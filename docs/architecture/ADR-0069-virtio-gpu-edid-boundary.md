# ADR-0069 — Trustworthy VirtIO-GPU EDID response and hotplug boundary

Status: draft. Stacked on ADR-0068, PR #300.

## Decision
Define a no-heap Rust **wire-level** GET_EDID request/response verifier,
consistent with OASIS VirtIO GPU 1.4 and upstream QEMU virtio_gpu.h:
- feature bit VIRTIO_GPU_F_EDID=1 must be *negotiated*;
- request opcode 0x010A with nonzero fence, scanout < negotiated 1..16;
- expected response opcode 0x1104, full 1056-byte control-queue response
  (24-byte header + 8-byte size/padding + 1024 EDID storage);
- validate little-endian fields, echoed fence, reserved/ctx/ring flags,
  size in 128-byte blocks <=1024, then parse the **entire** EDID through
  the strict parser from #300.
- check connector generation *before* and *again upon selection*.
  VIRTIO_GPU_EVENT_DISPLAY invalidates old replies and choices.
- user-selectable resolution/Hz must also survive separate pipeline/link
  capability checks. Unknown/invalid EDID does not become a selectable mode.

Normative primary sources:
https://github.com/oasis-tcs/virtio-spec/blob/master/device-types/gpu/description.tex
https://github.com/qemu/qemu/blob/master/include/standard-headers/linux/virtio_gpu.h

## Scope and hard limits
This change implements the **packet boundary and validation**, with
synthetic, hostile host fixtures only. It does NOT yet initialize VirtIO
PCI or a DMA virtqueue, negotiate device features on hardware, receive a
real QEMU GET_EDID completion, or implement resource/scanout updates.
Current QEMU Bochs VBE path remains separate and does NOT expose a known
refresh Hz. No DDC/I2C, display-control UI, hardware mode set, actual
Hz readback, GPU power/performance or physical monitor proof.

Next integration: VirtIO PCI transport + control virtqueue + fenced
GET_DISPLAY_INFO/GET_EDID on QEMU virtio-gpu only; compare actual used_len
to 1056 (not descriptor capacity), stop on timeout and unexpected
response, bump generation on display change, then connect modes to
the 15-second-confirmed compositor transaction. Do not use physical
GPU or host disks in early validation.
