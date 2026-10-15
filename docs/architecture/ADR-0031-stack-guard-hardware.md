# ADR-0031 — Hardware-enforced absence of stack guard virtual pages

Date: 2026-10-15
Status: experimental QEMU-only acceptance, production mapping pending.

## Objective

PR #82 introduced 16 KiB physically contiguous PMM stack leases with
software canaries on a shared HHDM mapping. Those canaries are not a
hardware guard page and do not stop a stack overflow in x86-64. This
feature demonstrates REAL x86-64 non-present PTEs for both ends of a
four-page supervisor stack mapping, with independent physical frames.

## Isolation and invariants

An opt-in, disposable one-vCPU QEMU mode reserves the otherwise-unmapped
lower-half virtual slot `0x0000500000000000`, distinct from the P1
temporary paging slot. It PMM-allocates 7 exclusive physical frames:
one PDPT, one PD, one PT and FOUR independently allocated data frames.
There is no requirement that the data pages be physically adjacent.

Four consecutive stack virtual leaves are mapped as PRESENT|WRITABLE
with U/S=0 on every new level. At the exact adjoining lower/upper
virtual addresses, PT[0] and PT[5] remain ZERO/non-present. Every
child-table PTE and leaf ownership is checked by a pure host-tested
`GuardPlan`. The live boot PML4 is modified only at a previously
verified empty low-half entry; other entries remain unchanged.

The normal `kernel-stack-guard-smoke` QEMU mode writes edge canaries
through stack virtual addresses, checks the same bytes via HHDM
physical aliases, unpublishes the PML4 entry, invalidates all leaf
TLB entries, returns all seven physical frames, confirms baseline PMM
counts and boot CR3, and exits through QEMU debug-exit 33.

Two OTHER isolated negative QEMU boots touch the actual lower and upper
unmapped guard VA via assembly, NOT a Rust pointer dereference. The BSP
page-fault IDT handler admits expected success only when armed AND CR2
matches the requested guard AND exception error code is exactly 0
(supervisor read from non-present mapping) AND RIP is kernel high-half.
Any other fault fails closed.

## Limitations / production requirements

- The temporary virtual mapping is *lower canonical but supervisor-only*.
  A production stack arena must reserve **upper-half, disjoint, guarded
  virtual ranges** in a proper VMM before such stacks can be used as TSS.RSP0.
- The bootloader HHDM retains a physical alias of each owned data page.
  The test proves the *dedicated guard virtual addresses* are absent,
  not that no alternative alias exists. A full production design must
  reason about all accessible mappings and CPU cache/TLB interactions.
- The negative flavors immediately shut down QEMU on successful #PF,
  therefore intentionally do not reclaim their seven frames in the
  dying VM. Reclaim is exercised exhaustively in the separate positive
  mapping mode.
- No actual CPU RSP/TSS, user CR3, saved FPU/SSE, user scheduler or
  live stack context switch is performed by this feature.
- PMM allocation errors, HHDM invalidity, root slot collisions,
  unexpected aliasing and forbidden page flags halt the test. No
  existing hardware or host CI gates may be skipped.

## Next implementation step

Introduce an isolated high-half kernel virtual region allocator that
owns page-table frames, page mapping lifetime and TLB invalidation.
Then bind these guarded mappings to PID leases and independently prove
real interrupt entry on the new RSP0 stack, plus fault-safe recovery
on supervisor stack overflow. A real two-user task scheduler still
requires coordinated xstate/CR3/TSS transitions.
