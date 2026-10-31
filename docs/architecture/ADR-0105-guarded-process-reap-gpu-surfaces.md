# ADR-0105 — Call-through surface barriers for counted process retirement

Status: proposed (stacked draft after PR #332 / ADR-0104).

## Problem

ADR-0104 links an authenticated monotonic PID to each graphics surface and
offers `close_exited` / `ready_to_reap` as standalone checks. This leaves a
dangerous integration mistake possible: callers may accidentally invoke
`ProcessTable::reap_with_status_counted` or cancel while an opaque GPU
surface remains live or pinned.

## New callable policy

`virtio_gpu_surface_process_bridge.rs` now implements three typed,
bounded and allocation-free *call-through* helpers:

- `reap_counted_guarded` first verifies EXITED state, closes all surfaces
  for that PID generation, checks zero remaining handles and only then
  calls `ProcessTable::reap_with_status_counted` with the caller's supervisor
  CR3. A pending or completed-but-not-released GPU transfer never returns a
  PMM frame lease. The original ProcessTable CR3 exclusion checks remain.
- `cancel_ready_counted_guarded` requires exact READY state, revokes
  graphics, checks all surface handles retired and only then calls the
  counted READY cancellation path.
- `cancel_blocked_counted_guarded` does the corresponding BLOCKED check,
  with no substitution of READY for a blocked saved-context owner.
- Surface closure on a rejected early reap/cancel is deliberately sticky.
  The transition fails closed and may be retried after genuine driver
  acknowledgements and logical handle release. There is no automatic
  device reset, GPU response forgery, user-memory unmap, or forced release.

Five new adversarial tests drive actual `ProcessTable` transitions through
these helpers, proving in-flight GPU refusal, partial transfer refusal,
completion-but-still-retained handle refusal, corrupted/foreign supervisor
CR3 rejection, distinct READY/BLOCKED states, unaffected second PID, stale
PID refusal and valid zero-GUI teardown without imaginary fences.

## Trust boundary and limitations

These functions offer a **correct reusable entry point** but are *not yet*
wired into every production EXIT/fault/READY-cancel/BLOCKED-cancel call
site. The existing `ProcessTable` public APIs remain callable; that
bypass risk is explicit and must be addressed before a production GUI.
Normal GPU builds intentionally compile no process-table code, so this
feature-isolated bridge runs in Rust host tests and process-table-specific
build flavors only.

The caller must take the SAME trusted external coordinator lock covering
both registries, CPU saved contexts, process frame ownership, mapped user
pixels and GPU fence verification. The process frame lease returned from a
successful call is metadata only until the kernel separately proves CPU
CR3 departure, TLB shootdown and real DMA quiescence. No host screenshot
or actual Ring3 pixel buffer access is established by this increment.

## Acceptance

Require exact-head `make test`, normal QEMU boot and all mandatory P0
GPU/Ring3/SMP regressions; never claim green before actual run completion.
Keep every stacked PR draft and leave `main` and physical disks untouched.
