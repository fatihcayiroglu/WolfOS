# ADR-0035 — Two separately linked ELF64 programs with actual CPL3 yield/IRETQ

Date: 2026-10-15
Status: experimental one-BSP QEMU acceptance until CI passes.

## First actually cooperative two-user hardware switching

Earlier #88 proved privileged CR3/TSS/FPU writes with READY metadata but
executed ZERO CPL3 instructions. This isolated `p2-ring3-yield-smoke`
uses **two independently assembled and linked** native ELF64 ET_EXEC
files from `user/yield.S`, each with a distinct immediate PID and XMM
signature, independently ELF-preflighted PT_LOAD pages and independent
seven-frame PMM-owned process roots (14 physical frames total). Each
program has its own RX text, RW/NX data and RW/NX user stack at the
SAME virtual addresses but backed by DISTINCT physical pages.

Two guarded upper-canonical kernel RSP0 stacks are mapped in the boot
CR3 and inherited into both sanitized private roots (three table
frames, eight stack data frames). Four PTEs are genuinely nonpresent,
two surrounding each 16 KiB kernel stack. An independent double-fault
IST remains installed. Every active CPU TSS.RSP0 is set to the owner
PID's guarded stack TOP. The actual interrupt trap frame is required
to land at the exact hardware stack end minus 160 saved bytes.

The bootstrap PID2 IRETQ frame is constructed in its own guarded
supervisor kernel stack. PID1 enters Ring3 via genuine IRETQ under its
own CR3; its first test-only INT80 #9 traps onto its own TSS.RSP0.
The existing 15-GPR INT80 entry saves all registers and hands the
kernel a physical-ownership-checked supervisor frame. The scheduler:
1. Validates live CR3, PID RUNNING state, selectors, user RIP/RSP,
   immutable PID registers and incremented user-data memory.
2. Makes one RUNNING PID READY under its actual CR3 (or EXITED only
   after four completed yields); stores the real frame pointer.
3. FXSAVEs its real XMM state, FXRSTORs the next process's 512-byte
   PID-owned legacy state, sets the new TSS.RSP0 and writes the new CR3.
4. Marks exactly ONE next PID RUNNING, returns the other stack's full
   saved GPR/IRET frame address; existing assembly executes a real IRETQ
   into the other user's *independent* ELF, not the first PID again.

Each user process checks its private RW data count, preserved R12,
R13, R14 and XMM0 on every return. Precisely eight real voluntary
yields, nine cross-process IRETQ paths, two real CPL3 EXIT(0)
syscalls and 10 real syscall traps must occur. On final EXIT no IRETQ
takes place: the kernel restores boot CR3, original TSS.RSP0, original
BSP FX state, then jumps (rather than returning) onto the safe old
BSP supervisor stack. Only there may it revoke and reap both process
roots, scrub both FX images, unmap the guard arena, flush 12 TLB
translations and free all 25 PMM frames.

## Limitations

- The syscall number 9 is **feature-isolated experimental** and is
  **NOT** promised as stable production ABI.
- This demonstrates genuine cooperative scheduling on one BSP under
  IF=0, not timer-based involuntary preemption, multi-core user tasks,
  a general VMM, safe arbitrary ELF execution, or portable XSAVE.
- Production must introduce AP TLB shootdowns, current-CPU ownership,
  fault recovery, XSAVE/XCR0 policy, robust process teardown on
  abnormal exit and ABI security review. The bootloader HHDM physical
  aliases remain as before.
- Never convert a failed test into a skipped check. Merge only if
  complete exact-final-head CI and post-merge main pass with the new
  mandatory QEMU assertion still enabled.
