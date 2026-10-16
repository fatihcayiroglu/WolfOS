# ADR-0047 — Generalize guarded supervisor high-half stacks to four PIDs

Date: 2026-10-16
Status: Proposed, exact-head CI required.

The historical, hardware-proven `GuardedArena` API remains a strict
two-slot alias to `GuardedArenaN<2>`. The next #106 candidate,
`FourPidGuardedArena = GuardedArenaN<4>`, uses the same exclusively
owned supervisor PML4/PDPT/PD/PT chain and guard layout: four 16 KiB
nonadjacent physical stack frames per PID, two nonpresent guard pages
per PID, one verified PML4 high-half slot. A checked maximum N of 85
prevents any PT index out of bounds. All invalid or incomplete reservation
attempts leave page tables unpublished. Retirement is allowed only after
unpublication, TLB invalidation and externally proved task quiescence.

The existing mandatory `rustc --test kernel/src/high_half_stack_arena.rs`
suite now verifies four-PID mapping, guards, capacity, ownership, failures,
PTE privilege tampering and stale-generation rejection, without disabling
any historical QEMU checks.

**Not four-user runtime yet:** this candidate is host-tested only. The
existing two-PID QEMU path remains untouched. A real four-CPL3 test still
must install four exclusive CR3 roots, TSS.RSP0 pointers, 15-GPR/IRET
trap frames, four FX images and a fair xAPIC timer dispatcher; prove
four distinct actual ELF users, graceful out-of-order EXITs and PMM cleanup.
