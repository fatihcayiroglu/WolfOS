# ADR-0108 — Bounded per-process user-VA surface snapshots

Status: proposed; stacked draft above PR #336 / ADR-0107.

## Goal

PR #336 verified kernel-side software composition of pixels taken from
physically real PMM-backed pages owned by two processes. Those pixels were
written and read through the privileged HHDM; no user virtual address was
translated. This increment provides a narrow, reusable and host-testable
bridge from **a user virtual address in each authenticated ProcessTable CR3**
to an immutable, kernel-owned xRGB8888 compositor snapshot.

## Design

`virtio_gpu_user_surface_copy.rs` accepts two `UserSurface` descriptors,
an authoritative `ProcessTable`, the existing `SurfaceLedger`, and two
trusted physical-memory callbacks. The descriptors identify a PID-bound
surface, a rectangle, pixel stride, and one user virtual address; they are
never permission to access arbitrary kernel physical memory.

- Both owners must still be READY/RUNNING/BLOCKED, and their PID must equal
  the registry's monotonic process generation token. The exact generation-
  tagged surface must be LIVE. Exited/unknown/stale owners are denied.
- Each source is capped at 64 pixels, 256 bytes, matching the existing
  `user_copy::MAX_COPY`; multiplication, extent and stride are checked.
- The existing four-level `user_copy::copy_from` refuses supervisor,
  missing, huge-page, noncanonical, bad-range and unmapped user addresses.
- Crucially, the caller's **PTE physical reads** and **pixel data physical
  reads** are BOTH restricted to exact physical frame numbers from the
  authentic `ProcessRecord::owned_frames()`. Even a present/user page-table
  entry that maps to another PID's page is rejected before any destination
  pixel is modified.
- The sources are copied into bounded, kernel-owned byte buffers and
  converted little-endian to immutable `u32` xRGB8888 snapshot arrays.
  Only after both snapshots have succeeded does the compositor receive
  the slices. It then rechecks the authenticated ledger and writes the
  requested damage rectangle with exact opaque z-order.
- On any failed copy, owner check, source dimension, or compositor
  validation, the destination is byte-for-byte unchanged. The temporary
  snapshot data are discarded.

The mandatory desktop-wire host test suite includes adversarial tests for
correct two-owner 64-pixel output, forged generations, closed owner,
foreign-owner leaf mapping, supervisor-page flags, cross-page refusal,
overflow and invalid z-order.

## Security boundary: NOT a completed Ring3 GUI

This is *policy and executable software* using an abstract trusted physical
provider. It does **not** register an actual graphics syscall, write a user
surface from running Ring3 code, pin hardware page tables, serialize the
process scheduler, or submit pixels to VirtIO-GPU. The physical reader
callbacks in host tests are modeled, while PR #336 separately verified real
PMM source bytes in QEMU. Combining both into an actual hardware CPL3
memory-copy/pixel-display proof remains a future milestone.

For production, hold one scheduler/graphics/PMM coordinator lock for the
entire source-copy plus composition and exclude all concurrent unmap/reap or
page-table mutation. The caller must also authenticate the user trap and
current CR3, keep all referenced PMM pages pinned, validate the physical
memory reader never addresses MMIO, and ensure the renderer's own destination
is a kernel-owned buffer. The current `user_copy::copy_from` repeats reads
after validation and is not safe against a concurrent mutable mapping without
such a lock. No physical page may be released until the CPU and GPU
quiescence protocols from earlier ADRs are satisfied.

The bridge is available only in `rustc --test` or opt-in
`user-copy-smoke` builds; normal boot does not link the isolated
ProcessTable/UserCopy flavor merely because graphics is available.

Keep draft and stacked; preserve existing QEMU host-pixel and GPU DMA
regressions, never merge to main without explicit approval.
