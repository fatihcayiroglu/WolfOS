# ADR-0038 — First genuine involuntary xAPIC Ring3-to-Ring3 switch

Date: 2026-10-15
Status: experimental BSP-only, pending complete QEMU CI acceptance.

## From hardware observation to actual preemption

PR #92 proved real local xAPIC timer IRQ arrivals during non-yielding
CPL3 instructions from two independently linked native ELF64 programs;
each IRQ previously returned to the SAME process. This feature adds a
separate opt-in `p2-ring3-timer-preempt-smoke` mode, preserving #92's
observation mode and all previous CI gates unchanged.

The single-BSP xAPIC LVT timer is programmed, both legacy PIC sources
masked, and the timer's supervisor-only uncached high-half MMIO alias is
shared by two independently sanitized user CR3 roots. Each ELF has its
own private executable code, writable data and user stack physical
frames, one guarded kernel RSP0 stack, and independently-owned 512-byte
legacy FXSAVE64 state. Both run with CPL3 IF=1.

During a **real hardware timer interrupt from inside the precisely
linked no-syscall CPU-bound assembly interval**, the IRQ entry saves
all 15 GPRs plus actual five-word CPL3 IRET frame on the current
process's guarded TSS.RSP0. With BSP IF automatically masked by the
DPL0 interrupt gate, the callback validates PID, the currently loaded
CR3/TSS, frame pointer, selectors, user IF/IOPL, user RIP/RSP and
x87/SSE owner. On the first eligible busy-window timer IRQ per PID:

1. Check that the alternate PID is READY, not exited, its alternate
   saved full hardware frame lies at the top of its private mapped
   guarded kernel stack, and that the destination CR3 is its own.
2. Save the interrupted *real* frame pointer in its PID record, park
   the source PID RUNNING -> READY using its actual source CR3.
3. FXSAVE64 the outgoing real XMM state, FXRSTOR64 the incoming
   PID-owned image; verify saved per-PID XMM0 signatures.
4. Write and validate the actual TSS.RSP0 for the target's protected
   kernel stack, then EOI the genuine xAPIC in-service timer IRQ
   **exactly once** via the CURRENT supervisor-only UC device alias.
5. Write the target's private CR3, mark exactly that PID RUNNING,
   update the current PID and return the target's saved 15-GPR +
   five-word hardware frame pointer. The existing assembly consumes
   that frame and IRETQs into a DIFFERENT real ELF on a DIFFERENT CR3.

The bounded acceptance gate requires **two involuntary timer-driven
switches** (PID1 -> PID2, then PID2 -> PID1), both from non-syscall
busy instructions. Each process then continues the existing eight
voluntary INT80 yields, its own private data and XMM/GPR checks, and
eventually the two genuine user EXITs; this simultaneously proves
that the timer-saved interrupted instruction stream was resumable.

On the final EXIT, the kernel restores original BSP CR3/TSS/FPU,
escapes onto the original boot stack, masks timer LVT and restores
SVR/PIC masks, unpublishes high MMIO and guarded stack mappings,
invalidates virtual TLB leaves, zero-wipes both FXSAVE images and
reclaims all 28 physical PMM frames. The QEMU verifier rejects
missing/extra markers, exceptions, wrong yields or exits, and non-33
exit status. The historical IF=0, IF=1-cooperative, and same-frame
timer observation hardware gates remain separately mandatory.

## Safety limits

- This is a single-BSP, two-PID, 2-switch controlled proof. It is NOT
  arbitrary-process scheduling, user SMP migration, general preemption
  policy, nested IRQ support, or a production local APIC driver.
- The IRQ hardware path cannot allocate, serial-log or acquire a
  blocking lock. Rust code runs with IRQ-gate-masked IF, and the
  architectural x87/SSE bank is controlled by this test exclusively.
- FXSAVE64 only covers legacy x87/SSE, not XSAVE/XCR0/AVX/AVX-512.
  Production must manage CPU feature negotiation and xstate ownership.
- The 8259 PIC remains masked while user IF=1; TSS, all guarded
  mappings, and high-half UC APIC alias stay pinned until all IRQs
  and user tasks are quiescent. No AP is running a userspace task.
- Future generalized scheduling requires proper run queues, clocks,
  robust fault recovery and AP-wide TLB shootdowns.
