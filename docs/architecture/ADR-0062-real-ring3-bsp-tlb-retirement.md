# ADR-0062: Terminal real CPL3 exits publish an owner-bound BSP TLB round

Status: QEMU-only proof for one-CPU, IF=0, PCID-off ELF process flavors.

## Motivation

The original real Ring3 ELF launcher already restored the supervisor CR3,
reaped the exact exited PID, revoked cached user pointers and returned all
privately owned PMM frames. The owner bookkeeping could still transition to
Retired through its legacy close path without publishing a TLB shootdown round.
ADR-0061 established an owner-pinned round closing API but had only exercised it
in a synthetic CPL0 four-CPU ownership harness.

## Decision

For the actual ELF64 CPL3 EXIT(0), EXIT(42), #UD and #PF terminal paths:

1. Authenticate current private CR3 and the exited PID's exact frame lease.
2. Begin retirement, refuse an early private-CR3 quiescence acknowledgement,
   restore boot CR3, then authenticate the BSP's quiescence acknowledgement.
3. Reap the exact PID generation, clear all bounded user-root/return caches,
   and check that no saved resumable context remains.
4. Publish a `ShootdownBarrier<1>` through the move-only active frame owner.
   Assert the barrier has the sole BSP bit pending, that legacy retirement
   finish refuses with `OutstandingShootdown`, and that all PMM frames remain
   held.
5. Reload the genuine resident supervisor CR3 again **after publication**,
   with interrupts and PCID off. Authenticated BSP then acknowledges its
   exact generation/instance/epoch round and only then invokes
   `finish_retirement_after_shootdown`.
6. Emit `WOLFOS_ELF_TX_TLB_OK` before the existing unsafe, separately
   justified exact frame reclamation. The shared strict QEMU transcript parser
   requires this event for every launch, including sequential PID1/PID2 and
   fault recovery, and rejects missing/duplicate/reordered rows.

Host parser tests are synthetic input validation, not proof of executed x86.
The QEMU tests must observe real linked ELF user instructions, system calls or
faults, authentic CR3 writes and a correct exact PMM release report.

## Scope / non-goals

This is **real Ring3** retirement, but **single BSP only**, with IF=0 and PCID
disabled. The fixed ELF fixtures are not general untrusted programs. No AP can
ever reserve/load this root, and private translations are non-global. It does
not implement IPI-backed multicore Ring3 TLB shootdowns, PCID/global flushing,
device DMA retirement, global scheduler synchronization, or arbitrary paging
reclamation. Each remains a prerequisite for general consumer workloads.

The move-only owner retains unsafe `reclaim()` preconditions. The owner-bound
barrier is not itself proof of no device/walker/future hardware users. Failures
halt the isolated QEMU test with frames retained, never treating timeouts or
missing acknowledgements as success.

No physical disks or existing partitions are accessed.
