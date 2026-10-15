# ADR-0029 — PMM-backed per-PID supervisor stack leases

Date: 2026-10-15
Status: PR acceptance pending

## Why

PR #81 stores per-PID 15-GPR + IRETQ frames and checks distinct 16 KiB
kernel RSP0 *ranges*, but its QEMU test still uses statically allocated
arrays in kernel .bss rather than independently PMM-owned stack frames.

## Decision

Provide a no_std fixed-slot `StackLeaseTable` whose caller supplies exactly
four PMM-owned, aligned, **physically consecutive** 4096-byte frames.
The verified Limine HHDM maps these four frames into a contiguous,
supervisor high-half 16 KiB kernel virtual range.

The table transactionally verifies alignment, contiguity, upper physical
range, checked virtual address arithmetic, PID uniqueness, stale slot
generation, cross-lease physical aliasing, and virtual overlap.

Stack data is distinct from any user's seven-frame private CR3 lease.
Per-PID stacks are exposed to `UserContextBank` only as a bounded
`KernelStack` range. Each stack carries canaries at its low/high edge
in the dedicated QEMU test; these are **detectors** of corruption, not
hardware-enforced unmapped guard pages.

A lease can be retired only when its caller proves: interrupts disabled,
scheduler stopped, current BSP running on a separate stack, no borrowed
trap frame, owning PID no longer live, and owning user CR3 inactive.
A retired handle cannot release or access a future occupant; generation
does not decrease. The table returns *exact* PMM frame ownership rather
than secretly freeing pages while they could still be referenced.

## Hardware proof

The isolated `kernel-stack-lease-smoke` boot obtains the real Limine HHDM
and live boot CR3, allocates 14 independent PMM pages for two synthetic
READY process roots plus 8 independent PMM pages for two contiguous
four-frame kernel stacks, checks their HHDM canaries without activating
them as RSP0, binds each to a complete user frame, verifies 64 alternating
metadata plans, then cancels both PIDs, retires frames, validates actual
supervisor RSP/CR3 evidence, and frees precisely 22 pages. PMM allocation
count must equal the initial baseline before clean QEMU exit 33.

CI runs *all* existing actual Ring3 ELF, INT80, VFS and SMP regressions,
as well as the newly added host and hardware stage.

## Limitations and next dependency

This is NOT yet a production stack allocator. Requiring contiguous PMM
frames can reject usable fragmented memory; proper virtual stack regions
will eventually map independent physical pages, with deliberately unmapped
guard pages, huge-stack limits and fault detection. HHDM mappings remain
available and **do not** furnish guard-page protection.

No CPU RSP0/CR3/TSS change, no real alternating CPL3 user execution, no
FPU/SSE/xstate preservation, no scheduler or asynchronous user faults are
claimed here. The QEMU stack images are intentionally unused as live CPU
stacks in this stage. A production handoff must first audit guard mappings,
interrupt entry/exit and xstate restore.
