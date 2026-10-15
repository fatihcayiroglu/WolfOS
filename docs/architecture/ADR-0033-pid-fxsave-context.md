# ADR-0033 — PID-owned legacy x87/SSE state preflight

Date: 2026-10-15
Status: pending exact-head CI acceptance (BSP-only QEMU).

## Goal

Merged #86 proves two separate high-half guarded stack virtual ranges and
PMM page ownership but not the per-user architectural FPU/SIMD register
state that must be preserved during task changes. Existing `fx_state.rs`
exercises legacy FXSAVE64 only for kernel timer preemption in an isolated
smoke mode. Reusing its static *kernel task* buffer as per-user ownership
would allow PID confusion and stale-generation reuse.

## Decision

Introduce `UserFxBank` of precisely two per-PID, 16-byte-aligned,
512-byte legacy FXSAVE64 images with generation-bearing opaque tokens.
Every admission checks PID uniqueness and table capacity; every image
starts as a real hardware-valid BSP FXSAVE baseline with only XMM0 low
lane overwritten by a distinct test signature. Two different PIDs can
never borrow or retire one another's token. A stale handle is rejected
after image retirement and subsequent slot reuse.

`switch_to` uses real CPU `fxsave64` into the outgoing PID image and
`fxrstor64` from the incoming PID image. `suspend` captures the
last active image. No live image may be reseeded or retired. On process
end, `retire_quiescent` overwrites all 512 bytes with explicit volatile
zero stores and invalidates the owning PID generation; callers must
first verify process revocation and no active FPU ownership.

## Real QEMU evidence

Dedicated BSP-only `user-fx-smoke` creates two READY processes with
independently PMM-owned seven-frame private roots (14 real frames), reads
the real boot CR3 and checks that it never equals a user-owned root.
After CPUID FXSR/SSE/SSE2 validation and CR0/CR4 setup, it captures a
valid BSP baseline and seeds XMM0 independently for PID1/PID2.

On each of 64 rounds it changes the currently active CPU XMM0 value,
saves that value into the departing PID image by FXSAVE64, restores
the other PID via FXRSTOR64, and checks both the restored CPU register
and the saved outgoing image. It then suspends the final image, restores
the original BSP FX state and CR0/CR4 settings, revokes both ready PID
roots, scrubs both 512-byte images and frees all 14 PMM frames. The QEMU
test requires ordered proof markers and debug-exit 33 with no exception.

The negative host tests cover duplicate PIDs, full slots, bad handles,
stale generation, cross-PID token forgery and complete FX image scrubbing.

## Non-goals / safety boundary

- This is genuine **legacy FX CPU save/restore** on BSP, but the PIDs are
  READY metadata and never execute at CPL3 in this flavor.
- No user-CR3 switch, TSS.RSP0 handoff, user interrupt context switch,
  concurrent task scheduler or user fault recovery is provided.
- FXSAVE64 only covers x87/MMX and 16 XMM registers plus MXCSR. It does
  **NOT** save upper AVX/AVX-512 lanes or other XSAVE/xstate components.
  Production needs CPUID leaf 0xD/XGETBV/XSAVE policy, per-CPU xstate
  ownership, suitable alignment/size and explicit interrupt safety.
- Not usable on APs or with interrupts enabled. Caller is responsible
  for ensuring exclusive BSP FX use and restoring the original BSP
  state before releasing process ownership.

Next gate: integrate verified GPR/IRET frame, private CR3, guarded
high-half kernel stack and user FX state into one actual two-ELF
Ring3 return/re-entry sequence. Preserve all previously required tests.
