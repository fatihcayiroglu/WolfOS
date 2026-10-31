# ADR-0103 — Per-process surface lifetime and two-fence retirement

Status: proposed. Stacked draft increment on #330 / ADR-0102.

## Purpose

ADR-0102 proves that bounded, immutable pixel slices can be composited with
checked bounds and opaque z-order. It does not revoke images when their owner
exits or keep backing alive while GPU DMA remains incomplete. This increment
adds a fixed-capacity, allocation-free metadata ledger that models those
conditions without pretending to own device or process resources.

## Model

`kernel/src/virtio_gpu_surface_ledger.rs` implements
`SurfaceLedger<const N: usize>`, a pure state machine:

- Open accepts a caller-verified nonzero PID and process generation, mints a
  monotonically increasing surface generation and returns a bound
  `Identity { slot, surface_generation, pid, process_generation }`.
  An empty slot remembers its last generation after release.
- `begin_submit` accepts two strictly increasing nonzero fence numbers,
  greater than the last GPU fence issued **globally across every slot** and
  every previous generation. A completion fence cannot be recycled between
  two different surfaces. The backing is considered pinned from this point.
- `ack_transfer` and `ack_flush` are separate, ordered transitions.
  Duplicate, stale, wrong-fence, early-flush and mismatched-handle
  acknowledgements do not advance state. The real driver MUST first validate
  used-ring index/head/length/type and echoed fence; these pure functions
  do not access hardware.
- `close_owner(pid, process_generation)` immediately revokes new renders
  and submissions for every owned surface. Unacknowledged transfer/flush
  work is retained in closing-in-flight states; repeated close is
  idempotent for the same still-live owner generation.
- `release` authorizes metadata retirement ONLY from `Closing` after
  both acknowledgements or without any prior GPU submission. No still-live,
  submitted or half-completed surface may be released. A stale generation
  cannot reclaim a newly recycled slot.
- `compose_live` joins the prior reference pixel composition contract to
  ledger authorization. This is single-threaded pure logic: the kernel must
  hold the actual owner/render synchronization lock across authorization and
  pixel reads and separately pin/map user buffers.

The ledger stores NO pixels or real physical frame leases. `release`
returns a logical identity, not a PMM frame or permit to free memory while
other CPU references exist. There is deliberately no timeout-based success,
unverified "force complete" method, or automatic freeing on process exit.
Missing device completion fails closed, potentially retaining the backing
until real hardware reset and teardown are independently verified.

## Acceptance and limitations

The Rust tests cover two-window composition and failed renders, exact
per-process generation matching, immediate revocation, two-stage in-flight
draining, wrong/duplicate/out-of-order or cross-surface reused fences, repeated close, slot reuse
against ABA and stale PID/handle references, bounded capacity and empty
ledger. The new module is included by `virtio_gpu_desktop_wire.rs`, which
the existing mandatory `make test` and QEMU smoke targets already compile.

This is NOT a real shared-memory mapping, production process capability
system, SMP-safe lock, physical GPU buffer owner or on-screen rendering
integration. A later hardware milestone must bind an authenticated process
record, real guarded PMM pages, CPU reference leases, GPU queue descriptors,
verified device reset and host-visible QMP pixels. No change to real QEMU
GPU command submissions is made here; the existing P0 suite stays intact.

Keep PRs draft and stacked. Neither production `main` nor real disks
must be modified without explicit integration authorization.
