# ADR-0104 — Surface owner authentication against WolfOS ProcessTable

Status: proposed; independent, stacked draft above PR #331 and ADR-0103.

## Problem

ADR-0103 introduced a safe, bounded surface lifetime ledger but its low-level
`SurfaceLedger::open(pid, process_generation)` accepts both identifiers from
the caller. They are only trustworthy if the kernel's authentic process
registry supplied them under the scheduler/owner lock.

WolfOS already has a `ProcessTable` with monotonically allocated `u64`
PIDs and generation-safe snapshots. A second untrusted generation cannot
be invented by a Ring3 application. We must bind GUI admission and teardown
to the *same* live process record that controls PMM and CR3 retirement.

## Implementation

`virtio_gpu_surface_process_bridge.rs` is a pure reference policy that uses
the real `ProcessTable::snapshot` API:

- `open_registered` accepts a live `Ready`, `Running` or `Blocked`
  owner only; its immutable 64-bit PID is also the current process-generation
  token. Reaped, nonexistent, zero and `Exited` owners cannot open surfaces.
- `compose_registered` re-authenticates both surface owners from the live
  registry before the existing exact-handle/fence-aware ledger and checked
  software compositor are reached. It rejects a mismatched generation even
  when another process or surface slot was subsequently recycled.
- `close_exited` accepts only a real `Exited` process, revokes its surfaces
  and leaves GPU-in-flight buffers pinned. `ready_to_reap` fails while ANY
  live, closing, transferred or in-flight surface metadata remains.
- `close_for_cancel` and `ready_to_cancel` provide the equivalent barrier
  for `Ready` or `Blocked` process cancellation before PMM release.
  Processes with no surfaces are valid and do not need a fake GPU fence.
- `SurfaceLedger::owner_remaining` counts exact PID + generation matches
  across all retained metadata states, not the current occupancy of an
  unrelated process.

The bridge is compiled only for `rustc --test` or the existing
`process-table-smoke` feature, because normal boot and standalone GPU
flavors intentionally do not link `crate::process_table` or
`crate::process_lifecycle`. It must not unconditionally pull those
feature-gated kernel modules into ordinary GPU boots.

Rust adversarial tests use the actual `ProcessTable` implementation
(included as a nested test fixture under standalone `rustc --test`),
including genuine table reserve/mark-running/exit/reap and cancel transitions.
Five new tests check forged process generations, unknown/exited owners,
cross-PID clipping, stuck transfer/flush lifetimes, no-GUI exit and
generation-recycled slots. Existing mandatory `make test` compiles the
new bridge via `virtio_gpu_desktop_wire.rs`.

## Exact limitations

This is a *registry-backed ownership policy*, not a production GUI system:
the existing live GPU QEMU smoke sequence still uses two hard-coded demo
windows rather than Ring3-owned surface pixels. This module DOES NOT yet
wire into the production syscall dispatcher, the actual process reaping
entrypoint, a scheduler lock, guarded user page mapping, PMM frame release,
a real GPU command queue or host screenshot verification.

**In particular, `ready_to_reap` does not automatically prevent a legacy
call site from directly calling `ProcessTable::reap`.** Integrating the
barrier with the sole trusted kernel teardown coordinator is the next
required milestone. The driver must independently verify hardware used-ring
responses, and the caller must hold one exclusive coordinator lock across
the process registry, surface ledger, memory mappings and all transitions.

Do not claim that this is user-visible window creation, a live Ring3 GUI
program, physical GPU support, refresh negotiation, or safe general
teardown without the missing real hardware and kernel call paths.

## Acceptance

- Exact-head mandatory P0 CI on this PR must complete, no skipped tests
  disguised as green; all prior real QEMU GPU and Ring3/SMP tests preserved.
- No disk installation; QEMU isolated smoke only.
- All stacked PRs remain draft, no automatic integration to `main`.
