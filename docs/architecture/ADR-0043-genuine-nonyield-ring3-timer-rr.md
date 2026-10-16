# ADR-0043 — Isolated real no-yield timer-driven two-ELF Ring3 acceptance

Date: 2026-10-16
Status: Proposed; real QEMU validation mandatory before merge.

## Purpose

Implement issue #96's **first** hardware proof of sustained BSP-only timer
round-robin without voluntary yields. Preserve the historical two hardware
switch + eight cooperative YIELD acceptance unchanged as a separate CI flavor.

## Design

A new Cargo feature `p2-ring3-timer-nonyield-smoke` inherits the proven
two-process private-CR3/guarded-TSS.RSP0/FXSAVE xAPIC plumbing. The dedicated
flavor maps the two statically independent, already opcode-audited
`user/timer_no_yield.S` native ELF64 images instead of the old yielding files.
Each image performs sixteen busy-loop workloads and exactly one `EXIT(0)`
INT80 after proving private data, PID sentinels and XMM0 continuity.

Validated xAPIC timer IRQs may hand off to the OTHER still-READY process
repeatedly in the exact linker-defined work loop. Each IRQ must prove source
frame, CR3, guarded RSP0, FPU owner, user selectors and expected GPR sentinel.
The existing hardware handoff preserves the complete GPR+IRET frame on its
own supervisor kernel stack, saves/restores FXSAVE64, updates CR3/TSS, issues
one xAPIC EOI and invokes the bounded round-robin policy. IRQs without a
second READY PID only EOI and resume the same process. A source's final
`EXIT` retires it and activates its peer; no fake YIELD is counted. The
last `EXIT` escapes to the original BSP stack and boot CR3 before reclaiming
all 28 real PMM frames and original interrupt/FPU state.

## Fail-closed acceptance

The new mandatory QEMU gate requires an actual kernel debug-exit (33),
exactly two genuine user `EXIT` traps with progress=16, **at least eight**
genuine timer-origin IRQ cross-PID switches, **at least four per PID** with
absolute disparity at most one, zero yields, no unexpected exception,
a consistent policy/IRQ frame ledger, explicit lifecycle/cleanup evidence,
and no leaked memory. Previously mandatory checks remain untouched.
Counter wrap, invalid frames and interrupts after teardown fail closed.
An isolated QEMU ISO accesses no real disks.

## Boundaries

Still experimental BSP-only fixed two-user-task acceptance, not the
general-purpose WolfOS scheduler, arbitrary ELF launch, heterogeneous
hardware drivers, AVX/XSAVE policy, AP-local user migration or production
Windows compatibility. Hardware proof remains **unverified until exact-head
push and PR CI succeed**, followed by post-merge main verification.
