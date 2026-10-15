# ADR-0025 — Bounded native file syscall bridge, contract stage

Date: 2026-10-15

## Motivation

PR #76 merged a genuine CPL3 `WRITE_PTR=5` probe with strict 4-level
`user_copy` and a seven-frame owned-physical allowlist. Experimental PR
#77 attempted user OPEN/READ/CLOSE but failed actual path pointer admission
in QEMU and reused syscall #5, conflicting with the verified WRITE contract.
PR #77 is closed without merge; no part of its guest result is accepted.

## Current decision

Keep #76's WRITE=5 unchanged. Reserve distinct number 6 for `OPEN_RO`,
7 for `READ`, and 8 for `CLOSE`. This is a **feature-gated experimental
ABI plan**, not a general syscall ABI that user programs may rely on yet.

- OPEN_RO: RAX=6, RDI=user pathname VA, RSI=exact pathname byte length.
  Copy <=63 bytes through `user_copy::copy_from`, deny zero/oversize/invalid
  pointers; use the existing strict RamFS/VFS absolute-path grammar.
  Returns opaque generation-tagged PID-owned descriptor or negative errno.
- READ: RAX=7, RDI=descriptor, RSI=user destination VA, RDX=length.
  Limit to 256 bytes; read to kernel staging memory, then use checked
  `user_copy::copy_to`. On copy failure restore VFS cursor; do not use
  raw user virtual pointers. Zero-length read checks descriptor ownership.
- CLOSE: RAX=8, RDI=descriptor; planned syscall gate will insist
  that RSI=RDX=0. The VFS validates descriptor generation and owning PID.
  PID exit still requires `close_all`.

The adapter is pure no_std Rust, compiled as part of the existing isolated
VFS kernel build. Host tests construct real four-level PTE fixtures and
exercise the same `user_copy` and `Vfs` implementation through this adapter.
The physical callbacks MUST restrict access to the active process's
independently owned page-table and leaf frames. They must run with mapping
mutation excluded (single BSP/interrupts off for current QEMU stages).
These assumptions are not generalized into production concurrency.

## Non-goals and merge honesty

This change DOES NOT connect syscall numbers 6/7/8 to the INT80 assembly
dispatcher and DOES NOT add a passing CPL3 hardware OPEN/READ/CLOSE gate.
It creates a regression-tested safe implementation seam for that next PR.
No claim of generic file access, arbitrary ELF apps, process-level
simultaneity, disk persistence, input console, graphical desktop, or
Windows/Steam execution is justified by this change.

## Hardware acceptance gate for follow-up

1. Add a separately selected ELF fixture that issues 6/7/8 with RDI/RSI/RDX
   from actual user registers, and validate the genuine symbol-derived
   return RIPs instead of guessing instruction lengths.
2. Import this module's adapter with an owned-frame HHDM provider and
   explicit live CR3 / PID checks; no untrusted user pointer dereference.
3. Prove positive OPEN -> READ -> CLOSE -> EXIT and negative bad path,
   supervisor/RX destination, foreign/stale descriptor and oversized read.
4. Require exact serial markers, complete CR3 restoration, all owned-frame
   reclamation, and two complete exact-head CI runs including every existing
   isolated QEMU test before merge. Never skip existing tests to get green.
