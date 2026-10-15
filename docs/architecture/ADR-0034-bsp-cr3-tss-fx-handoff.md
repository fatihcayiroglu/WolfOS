# ADR-0034 — Two ready PID hardware CR3/TSS.RSP0/legacy FX handoff

Date: 2026-10-15
Status: experimental single-BSP QEMU acceptance pending CI.

## Context

PRs #80–#87 independently proved owned process roots, complete saved
GPR/IRET context metadata, distinct high-canonical guarded supervisor
stacks, and actual CPU FXSAVE64 switching across two PID-owned images.
Those tests did NOT jointly write the actual CPU CR3 and loaded TSS.RSP0
while selecting the matching process's FX/GPR context.

## Decision

Feature-only `p2-handoff-preflight-smoke` adds a tightly serialized,
interrupts-disabled, one-BSP QEMU hardware experiment. It creates two
simultaneously READY processes with independently PMM-allocated seven-frame
leases per PID (14 frames); creates two high-half 16 KiB guarded stack
ranges (3 table + 8 leaf frames); copies the boot PML4 kernel half,
clearing U/S on both private roots. Each private PML4 has a single low
entry pointing to an empty PDPT: **no executable user pages** exist
and no user code is entered. The process user-frame RIPs are synthetic
metadata only, never an IRETQ authorization.

Each of 64 rounds:
1. Read active BOOT CR3 and choose the next PID through the already
   owner-checked UserContextBank; require the matching private root,
   synthetic GPR signature and reserved guarded high-half RSP0 top.
2. Write the actual initialized BSP TSS.RSP0 to that process's reserved
   high-half stack top, checking the field by an unaligned load from the
   actual loaded TSS (TR descriptor established during boot).
3. Write hardware CR3 to this PID's sanitized private root and read it
   back. The kernel function and HHDM must remain supervisor mapped.
4. Switch actual x87/SSE state via FXSAVE64/FXRSTOR64 between
   independently PID-owned 512-byte images; check XMM0 signatures.
5. Return hardware CR3 to the boot root before the next selection.

No CPL3 transition or interrupt landing on these RSP0 stacks occurs.
Before release, save the final FX image, restore original BSP FPU/CR0/CR4
and TSS.RSP0, revoke both process registrations, scrub both images,
unpublish the guarded PML4 subtree, flush 12 translations and reclaim
all 25 PMM frames. The QEMU verifier rejects exceptions, missing or
out-of-order markers and non-success exit. Every prior CI gate remains.

## Explicit limits

- This proves synchronization of **actual privileged register writes**
  while kernel-mode execution remains on its separate boot stack.
- **No two user ELF instruction streams, IRETQ resumption, user trap
  frames, actual interrupt entry on the guarded stacks, timer preemption
  or process scheduler are implemented by this test**.
- The seven-frame PID root leases have no mapped user ELF; roots are
  not runnable until text/data/stack PTEs, user pointer and fault paths
  are independently verified.
- The BSP-only test does not perform AP TLB shootdowns, validate xstate
  beyond legacy FX or test high-half stack faults on a live RSP0.
  A production scheduler needs per-core ownership, XSAVE/XCR0 policy,
  interrupt atomicity and a provably safe escape stack.

## Next hardware acceptance

Run two separately linked user ET_EXEC images with real CPL3 INT80
yield/resume on distinct CR3 and guarded per-PID RSP0, preserving all
15 GPRs, EFLAGS, private user mappings and appropriate FX/xstate.
Retain all existing QEMU and host gates without weakening any.
