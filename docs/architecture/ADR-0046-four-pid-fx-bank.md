# ADR-0046 — Const-generic per-PID legacy FXSAVE64 bank

Date: 2026-10-16
Status: Proposed; CI pending.

## Rationale
#106 requires four genuinely independent user CPU contexts in QEMU.
The already proven two-user xAPIC path depends on `UserFxBank`, which held
exactly two 512-byte FXSAVE images. Generalize its ownership capacity
without changing its established two-user API or changing any IRQ code.

## Design
`FxBank<const CAPACITY: usize>` stores fixed, inline, 16-byte aligned 512B
per-PID legacy x87/SSE images with monotonic generations, stale token checks,
and an exclusive active slot; no heap or MMIO. `UserFxBank` remains an alias
to `FxBank<2>` so existing QEMU code continues using the verified interface
unchanged. `FourPidFxBank` is a candidate alias to `FxBank<4>`.

The existing host Rust suite tests four admitted PID images, capacity refusal,
isolated XMM0 sentinels, retirement wipes and safe generation-based reuse;
also a zero-capacity type. These are **host tests only**; they do not assert
that four Ring3 processes are currently running, or that four live CR3/TSS
hardware contexts have been constructed.

## Next hard gate
Bind this four-slot bank and the generation-safe four-PID ready queue to
four real independently owned CR3 roots, guarded high-half TSS.RSP0 stacks
and fully pinned GPR/IRET frames. Run a separate actual 4-ELF no-yield QEMU
test with fair hardware xAPIC switches, both stale-identity rejection and
full PMM/FX quiescent cleanup. Preserve the old two-PID QEMU gate, and
require exact-head push/PR and post-merge CI before closure.

This phase does not address AVX/XSAVE/XCR0 or SMP user migration.
