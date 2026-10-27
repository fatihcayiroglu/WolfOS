# ADR-0064: PMM local interrupt-state exclusion

Status: independent candidate, based on `main`.

## Failure mode

The PMM uses one global spin lock. Previously, if a CPU held that lock
with maskable interrupts enabled and its interrupt handler attempted a
PMM operation on the **same CPU**, the handler could spin indefinitely:
the interrupted owner cannot run to release the lock.

## Decision

- Use the already-pinned `x86_64::instructions::interrupts::without_interrupts`
  around **both the lock acquisition and the full PMM critical section**.
- Preserve the caller's IF bit. IF=0 callers stay disabled; IF=1 callers
  re-enable only after the PMM lock release guard has run.
- Leave the existing Acquire/Release lock and SMP mutual exclusion intact.
  Other CPUs can still contend for this lock; local IF masking alone
  does not replace cross-CPU synchronization.
- Check that the boot PMM allocation/free regression keeps its incoming
  interrupt state unchanged.
- Run the full mandatory host tests plus BIOS/UEFI and 1-/4-vCPU QEMU P0
  regression, not merely a model test.

## Risks and limits

Masking interrupts during lock acquisition also masks them while waiting
for another CPU; this makes a heavily contended PMM a potential IRQ-latency
source. Long-term production work needs a measured lock-hold bound, IRQ
latency tracing, and potentially per-CPU allocation caches.

This does **not** make the lock NMI-safe, recursively reentrant, or
safe against a fault handler that itself calls PMM while the same thread
holds the lock. It does not implement a complete interrupt-capable
allocator or a general Ring3 process retirement protocol.

The existing boot self-test normally begins with IF=0. Additionally the
4-vCPU AP-local xAPIC timer QEMU smoke exercises 64 real PMM allocate/free
roundtrips on each of three APs while each AP's timer is armed and IF=1.
Every operation verifies IF was restored and the frame was released, and
the coordinator checks exactly 192 successful probes alongside real timer
IRQ delivery. This proves the IF=1 call path, but **does not** deterministically
force an IRQ in the middle of a PMM critical section or bound lock latency.
No real disks or hardware are accessed.
