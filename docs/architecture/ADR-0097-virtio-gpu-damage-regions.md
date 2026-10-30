# ADR-0097 — Bounded VirtIO-GPU damage regions (first increment)

Status: proposed, QEMU-only, stacked after ADR-0096
Date: 2026-10-31

## Motivation

ADR-0096 uses one 1024×768 xRGB resource with a 4096-byte row stride.
Its 1024×384 mode currently re-transfers the six 64-row bands it
overwrote and flushes the entire selected rectangle. This is safe but
not a general compositor: one changed pixel should not force a full
band or frame upload.

A partial rectangle requires a **full-resource stride**, not a tightly
packed stride based on the damage width. It must carry the same x/y/w/h
in both VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D (0x0105) and
VIRTIO_GPU_CMD_RESOURCE_FLUSH (0x0104). The transfer's offset is

    offset = y * (1024 * 4) + x * 4

and remains inside the original 3 MiB resource, even if the current
scanout shows only 1024×384.

## Decision: bounded, no-allocation damage policy

The new kernel/src/virtio_gpu_damage.rs supplies:

- Checked, nonempty 2D rectangles with overflow/out-of-bounds refusal.
- Exact 56-byte transfer and 48-byte flush wire encodings, including
  distinct nonzero fences, resource_id=1, and zero padding.
- Conservative bounding-box coalescing. It may upload unchanged pixels
  enclosed by disjoint damage, but cannot drop any changed pixel.
- A one-in-flight DamageTracker that refuses new edits while commands
  are outstanding. Damage is *not cleared* until a real, independently
  validated transfer completion **and then** a separately fenced flush
  completion. A failed/missing completion keeps the resource pinned.
- No heap, MMIO, DMA, GPU control-queue writes or timer dependencies.

The existing virtio_gpu_desktop_wire.rs routes its complete 64-row
desktop and reduced-band transfer encodings and the two full-scanout
flush encodings through the same rectangle encoder. Their expected
wire bytes are unchanged, so the existing real-QEMU baseline remains a
mandatory regression test. This first increment does **not** substitute
an unproven partial-width transfer for the attested full-screen path.

## Evidence required

- Standalone Rust wire and adversarial tests: one-pixel last corner,
  nonzero x/y offset, zero/overflow/out-of-bounds cases, distinct fences,
  two acknowledgements in the correct order, conservative union, and
  preservation of existing band wire format.
- Existing desktop attestation and rollback QEMU gates must still pass
  on the **exact PR head** before any readiness claim.

## Limitations and next step

This PR establishes a request encoding and host-testable compositor
damage accumulator, **not** a proven on-screen partial-width update.

Follow-up QEMU proof must modify a small rectangle in the already
attached resource, issue its bounded transfer+flush with independently
validated completions/fences, and compare an entire host screenshot
before/after. It must deliberately corrupt a pixel outside the damage
and reject that result. Only after that proof may partial rectangles be
used to optimize mode transitions. No device reset or PMM-page release
may occur while any damage command remains unresolved.

Remaining: multiple dirty rectangles without bounding-box amplification,
real compositing/surfaces, double buffering, page-flip, resize-specific
resource allocation, hotplug, physical GPUs and refresh-rate programming.

Specification: OASIS VirtIO-GPU device type,
https://github.com/oasis-tcs/virtio-spec/blob/master/device-types/gpu/description.tex
