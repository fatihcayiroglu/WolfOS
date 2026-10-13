# ADR-0019: Real per-CPU saved-context switching on all active boot CPUs

Status: Proposed until branch, PR and merged-main QEMU CI pass.

## Context
PR #20 proved 256 distinct real saved contexts on the boot processor only.
Limine has already started APs, installed private GDT/TSS/IST/IDT, and run
per-CPU state machines. We must first demonstrate that APs can safely
switch to private suspended Rust stacks before integrating the 256-context
bank with all per-CPU runqueues.

## Decision
- Keep the previous BSP-only 256-context stack bank and its QEMU check.
- Add a **separate per-CPU proof**: two private 8 KiB stack-backed Rust
  TCBs for each active CPU, indexed by the verified Limine CPU-directory
  index, up to the existing 256-CPU bootstrap limit.
- Compile-time enforce a 4 MiB aggregate stack-bank ceiling for this
  per-CPU test. Only the active CPUs run; unused slots remain dormant.
- Each CPU exclusively owns its TCB pair, scheduler RSP, ready FIFO and
  state transitions; no cross-CPU migration or remote queue mutation.
- Reuse the ABI-tested x86-64 callee-preserved GPR/RSP switching routine,
  with a generic trampoline passing the CPU index (R12) and TCB index
  (R13) into one Rust function.
- On each CPU, execute six real task dispatches and twelve context
  switches, three cooperative yields, one block/wake and two finishes.
  Verify each checksum, event order [0,1,0,0,1,1], RSP ownership and
  stack-bottom canary.
- APs publish existing AP_DONE Release token *after* context verification
  and park. BSP reads tokens with Acquire before inspecting AP-owned
  non-atomic state. BSP is the only serial logger.
- Normal 1-CPU boot requires 2 contexts / 12 switches. A four-CPU QEMU
  boot requires 8 contexts / 48 switches (12 on each CPU). Preserve the
  existing separate 256 BSP context test after SMP work has finished.

## Exclusions and limitations
- This is NOT 256 real threads distributed across the CPU runqueues:
  the existing 256 BSP contexts and 256 SMP state-machine tasks remain
  distinct tested systems. Their unification is a later milestone.
- Static 256x2x8 KiB bank is a prototype bound. Stacks have canaries,
  but no guard pages, reclaim, NUMA placement or dynamic growth.
- External interrupts remain disabled; no preemption, APIC timer, IPI
  rescheduling, FPU/SIMD/XSAVE, TLS/GS, CR3 or Ring 3 transitions.
- No thread migration or work stealing; all ownership is local.
- No physical host disk access; QEMU/ISO only.

## Merge gate
Both push and PR Actions must pass host Rust/source contracts,
single-vCPU QEMU, #UD, #PF and four-vCPU QEMU. After merge, require
the merged main workflow to pass before marking complete.
