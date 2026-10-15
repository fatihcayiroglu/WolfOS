# ADR-0036 — Interruptible Ring3 admission contract before timer preemption

Date: 2026-10-15
Status: isolated BSP QEMU hardware feature, gated before merge

## Motivation

PR #89 proved **real** two-ELF cooperative CPL3 context switching with
separate private CR3, four-page guarded supervisor RSP0 stacks, actual
FXSAVE64 state, eight INT 0x80 yields, nine cross-PID IRETQ paths, and
exact 25-frame PMM cleanup. It intentionally executed userspace with
IF=0. Such users cannot be preempted by ordinary maskable xAPIC timer
interrupts even while the local timer is enabled. Simply changing IF to
1 without checking the user trap's saved flags and owner could return
via IRETQ into the wrong task.

## Design

Add an independent feature `p2-ring3-irq-ready-smoke`, preserving the
previous IF=0 feature unchanged.

1. Mask both legacy 8259 PIC interrupt-mask ports (0x21 and 0xa1)
   before entering CPL3, saving their original masks for later
   restoration. The local xAPIC timer remains **UNARMED** here.
2. IRETQ into each independently linked ET_EXEC ELF with IF=1,
   IOPL=0 and safe reserved flags. All ten actual CPL3 INT80 trap
   frames (eight yields, two exits) must carry the resumed user IF=1.
3. Validate each captured actual 160-byte 15-GPR plus hardware-frame
   pointer against exactly the owning kernel stack top minus 160.
   Validate PID, current hardware CR3, owner CR3, live TSS.RSP0, GDT
   CPL3 selectors, safe canonical userspace RIP/RSP, IF and x87/SSE
   owner PID on EVERY hardware trap, before switching the task.
4. Restore original boot CR3, TSS, FX, and maskable interrupt state
   before reaping and releasing all 25 PMM frames. PIC original masks
   must be restored only with kernel IF=0, then read back.
5. Add adversarial pure host unit tests for wrong PID, root, frame
   position, guard-stack size, TSS owner, ring-0 selectors, kernel
   pointers, IF=0 or privileged IOPL/TF/etc flags, and cross-PID FPU
   ownership. Old `valid_user_rflags` and earlier QEMU test cases
   retain their original IF=0 behavior; only the new isolated feature
   explicitly allows user IF=1.

## Honest evidence boundary

This milestone proves that TWO real Ring3 ELF processes can cooperate
with IF=1 and can return through the actual INT80 hardware privilege
transition while the full user interrupt-return frame is checked,
with legacy PIC interrupts blocked and full cleanup.

It **does not deliver an involuntary local APIC timer IRQ to CPL3**,
does not save a timer IRQ frame from a non-yielding user program,
does not preempt without INT80, and does not claim production SMP user
scheduling or XSAVE/AVX. That must be a separate QEMU experiment with
new dedicated xAPIC LVT/EOI register ownership, validated timer IRQ
vector, atomic FPU/CR3/TSS handoff and protected teardown.

Do not merge until all prior P0 gates and both IF=0 and IF=1 two-ELF
hardware acceptance modes pass on the exact same final SHA.
