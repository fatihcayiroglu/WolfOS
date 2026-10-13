# ADR-0021: Timer-gated Rust context dispatch at safe points

Status: Proposed pending QEMU acceptance in CI.

## Decision
- Retain PR #22's validated PIT IRQ0 delivery and PIC EOI.
- Only in the isolated one-vCPU timer-smoke image, after all prior
  kernel tasks and AP work are complete, run two new private 16-KiB
  stack-backed Rust TCB contexts for three rounds each.
- An IRQ handler touches only its AtomicU64 tick counter and sends EOI.
- While a worker is running on its own stack, the IRQ can fire and
  advance the counter. The worker explicitly observes a fresh later
  tick, masks IRQs, records its event/epoch, and voluntarily yields
  to a BSP scheduler context through WolfOS's saved-GPR/RSP routine.
- The scheduler dispatches alternating workers at ABI-safe switch points.
- Verify six real Rust dispatches and 12 saved-register/RSP switches,
  [0,1,0,1,0,1] event order, strictly increasing real IRQ epochs,
  saved RSP bounds, both worker stack canaries, and QEMU debug exit.

## Explicit limitations
- **NOT preemptive scheduling.** An uncooperative busy loop will not yield:
  the worker voluntarily switches at a safe point after noticing the tick.
- Not a local APIC timer, HPET, accurate clock, scheduler integration,
  FPU/XSAVE save, page-table isolation, Ring 3, IRQ-safe heap, thread
  migration, or multithreaded time accounting.
- BSP only, APs parked with IF=0, maskable IRQs enabled solely during
  the worker's tick wait. The assembly context switch runs only at IF=0.
- No code writes to real disks; QEMU ISO and legacy PIC/PIT ports only.

## CI gate
Source tests plus existing one- and four-CPU/QEMU, CPU exceptions,
paging smoke, and real PIT timer smoke asserting both timer markers.
