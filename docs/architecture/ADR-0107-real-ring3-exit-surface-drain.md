# ADR-0107 — Genuine CPL3 EXIT through a surface-guarded PMM retirement gate

Status: proposed, isolated QEMU smoke, stacked on PR #334 / ADR-0106.

## Objective

Previous increments prove GPU surface owner lifetime (pure Rust metadata),
its association with the real ProcessTable, and a separate real-PMM QEMU
fixture. This experiment proves that an actual independently linked ELF64
program running in **hardware CPL3**, exiting via INT80, restores the
supervisor CR3 and invokes the authenticated graphics-surface drain guard
**before returning its actual seven-frame PMM lease**.

## Architecture

The opt-in `user-surface-exit-smoke` feature inherits the existing
`user-elf-run-smoke`. The entire preexisting hardware ELF preflight,
real protected CR3/IRET, Ring3 syscalls, source-data audit, CPU reservation,
retirement and exact physical memory cleanup remain unchanged.

The isolated BSP-only IF=0 path uses a fixed `SurfaceLedger<1>` in a
single-owner `UnsafeCell` fixture. After ProcessTable's real RUNNING
transition and before IRET, `open_registered` verifies the actual PID
and process generation (PID is monotonic `u64`), then stages a pair of
**synthetic software** transfer/flush fence numbers. No GPU command or
DMA request is sent.

The genuine Ring3 program prints its usual 19 bytes and calls EXIT(0).
The kernel's existing terminal `finish_exited` first proves the real
active CR3 ownership, restores the real boot CR3, and verifies the CPU has
left the user address space. Only then does the new feature-specific path:

1. Invoke `reap_counted_guarded` against the actual ProcessTable and
   refuse a process lease while the surface is `ClosingSubmitted`;
   the full real PMM count must remain unchanged.
2. Reject out-of-order flush and accept a **synthetic** transfer
   acknowledgement. A second guarded reap still fails with the exact
   `ClosingTransferred` surface state.
3. Accept the synthetic flush acknowledgement; guarded reap still refuses
   while the closed handle has not yet been explicitly released.
4. Release the logical surface metadata and invoke `reap_counted_guarded`
   again, this time actually returning the precise counted process-owned
   seven-frame lease and exit status. CPU/PMM cleanup then follows the
   original owner-reclaim sequence, including full zero-leak verification.

Both real hardware execution and the simulated-GPU boundary are encoded
in mandatory, exact-order serial proof markers. The host harness verifies
one `WOLFOS_RING3_SURFACE_OPEN_OK` before genuine user IRET and one
`WOLFOS_RING3_SURFACE_EXIT_GUARD_OK` after actual user exit but before
`WOLFOS_ELF_CLEANUP_OK`. All prior ELF64 frame plan, launch and
terminal-retirement markers are retained.

## What is and is not proven

**Proven, if exact-head P0 passes:** a genuine x86-64 Ring3 -> INT80 ->
supervisor CR3 -> surface-guarded counted process reap -> physical PMM
retirement chain, in a single BSP QEMU process test.

**Not proven:** user-authored graphics buffers, real GPU transfer/flush
hardware acknowledgements, DMA page pinning, SMP shared surface locking,
real GUI syscalls or safe integration of every legacy production retirement
entry point. The two GPU acknowledgements are deliberately synthetic policy
inputs and the QEMU guest does not touch VirtIO's GPU queue in this flavor.
The unsafe fixture is not a reusable general-purpose lock and must never
be exposed as a production multi-CPU surface database.

## Acceptance

Run `make user-surface-exit-smoke` in mandatory P0 without retries,
plus all legacy QEMU and Rust host regressions. A failed, skipped or
cancelled run is not a pass. Do not merge any stacked drafts into `main`
or touch physical disks.
