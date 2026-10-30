# ADR-0098 — QEMU partial-width damage host pixel proof

Status: proposed, QEMU-only. Stacked on ADR-0097 / PR #325.
Date: 2026-10-31.

## Intent

After the already-proven native 1024x768 QEMU desktop image, change exactly
the rectangle x=73, y=91, w=32, h=32 (1,024 pixels) in the original backing
resource and the real Limine framebuffer. Submit one 56-byte
VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D request and a matching 48-byte
VIRTIO_GPU_CMD_RESOURCE_FLUSH request, with two distinct nonzero fences.
Each command must have its own genuine used-index/head/length/type/fence
completion. No SET_SCANOUT, resource reallocation, or device reset occurs
between these two on-screen images.

The host takes a synchronized QMP screenshot after the partial transfer+flush,
compares every RGB byte of the 1024x768 screen, including the 785,408
unchanged pixels outside the rectangle, and releases the guest stage token
only on a perfect match.

Then the guest restores exactly the same 32x32 rectangle (no full-band
retransfer), independently fences another transfer+flush pair, and the host
checks another entire screenshot against the original 1024x768 image,
byte-for-byte. The guest also compares the backing-page digest to the
original source digest. Only after this proof may the original second-mode
and 15-second transactional path proceed, followed by device reset and safe
release of all 773 PMM frames.

## Isolation

QEMU-only feature qemu-virtio-gpu-damage-live-smoke inherits the desktop
QEMU feature but is not enabled in normal WolfOS boots or any previous QEMU
flavor. The existing 38/46-index desktop tests stay unchanged. The new flavor
uses 42/50 control-queue completions for normal/expired verdict respectively.
Only QEMU screenshots, not guest assertions, are pixel authority.

## Bounds and limitations

This is one deliberately chosen 32x32 dirty rectangle on a single
VirtIO-GPU 2D resource with one scanout, not a production compositor,
GPU page flip, arbitrary dirty-surface scheduler, hardware GPU driver,
refresh-timing control, or hotplug implementation. This does not make the
operating system ready for daily use.

CI must run the real new flavor and all pre-existing P0 regressions, including
first-failure-only, negative attestation, 15-second rollback, CPL3, and SMP.
No retries, fake-green skips or physical GPU/disk operations.
