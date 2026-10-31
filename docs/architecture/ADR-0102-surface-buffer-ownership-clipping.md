# ADR-0102 — Checked pixel ownership and clipped software composition

Status: proposed; stacked on draft PR #329 (opaque QEMU z-order proof).

## Why this increment

ADR-0101 paints hard-coded red/blue rectangles directly into the kernel
framebuffer and VirtIO-GPU backing. Those pixel masks prove real QEMU overlap
but do not establish independent application-associated pixel storage.

Before adding mapped user buffers or a real compositor, require a small,
pure and allocation-free Rust contract that can compose two read-only source
slices into **only** a caller-chosen damage rectangle, preserving every
other destination pixel.

## Contract

`kernel/src/virtio_gpu_surface_pixels.rs` provides:

- `Identity`: nonzero surface slot + generation and nonzero process PID +
  generation. The trusted kernel caller supplies two expected identities
  from its handle table, not from untrusted surface content; a stale binding
  cannot be rendered under the new generation.
- `SurfacePixels`: a checked, immutable xRGB8888 `&[u32]`, own rectangle,
  stride measured in *pixels*, and exact padded row length. Zero dimensions,
  out-of-resource geometry, strides below width, size overflow and missing
  pixels fail closed before any output write.
- `compose`: validates the viewport, damage containment, output/background
  lengths, both expected identities, distinct slots and exact top identity.
  Only then does it restore the background and composite one visible owner
  per dirty pixel, with topmost opaque pixels replacing the lower layer.
  No allocation, unsafe block, I/O or unbounded queue.
- `CompositionReport`: reports exact background/first/second pixel counts.
  These **do not** replace host screenshot or real GPU completion authority.

Test fixtures cover true overlapping source colors, blue/red z-order,
padding/stride correctness, screen-edge clipping, narrow dirty rectangles,
stale process generation, wrong top handle, duplicate slots, invalid
damage, invalid geometry and overflow. Every rejected composition must leave
the destination completely unmodified.

The new module is included by the desktop wire contract; `make test`
already runs `rustc --test kernel/src/virtio_gpu_desktop_wire.rs` so
these tests become a mandatory offline P0 gate. The existing exact QEMU
host-pixel and fence acceptance steps must remain unchanged.

## Limits and next integration

This proves a *software reference composition policy* for two trusted
read-only in-memory slices. It is **not** an actual Ring3 shared memory
mapping, secure handle table, process permission boundary, GPU DMA mapping,
a frame scheduler, live keyboard focus or real application-owned window
surface. The kernel must authenticate process/surface handles before
calling this API and must separately prove DMA completion and host-visible
pixels before committing a rendered scene. Never treat the pure report as
device evidence.

Follow-up: introduce guarded user-surface allocations and mapping leases,
copy-on-submit or pinning/retirement policy, full-screen host QMP checks
with real source pixel buffers, focus and input routing policies, then
extend beyond two surfaces only with bounded damage and verified rollback.

No new physical GPU claims; do not merge any of the draft stack to main
without approval or claim CI pass before the exact branch head completes.
