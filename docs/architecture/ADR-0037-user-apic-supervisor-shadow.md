# ADR-0037 — A supervisor-only high-half xAPIC alias shared by private CR3 roots

Date: 2026-10-15
Status: design and host-test admission only; hardware IRQ integration deferred.

## Why this gate is necessary

PR #90 proved two real ELF64 processes execute at CPL3 with IF=1
while the legacy PIC is masked, but it intentionally kept the xAPIC
timer UNARMED. Existing xAPIC test MMIO VA
`0x0000_4000_0000_2000` belongs to the **lower** PML4 half of the boot
CR3; neither process inherits this range after the sanitized kernel-half
PML4 graft. Simply calling the existing timer MMIO driver from private
CR3 would cause an inaccessible MMIO access or incorrectly expose
privileged device memory in userspace.

## Decision and acceptance contract

Add `user_apic_mmio_shadow.rs`: pure no_std fixed mapping policy,
deliberately separate from the existing live MMIO driver.

- One dedicated canonical high-half PML4 slot, distinct from both the
  lower-half user mappings and the high-half guarded RSP0 stack slot.
- PMM-owned, unique PDPT/PD/PT frames, disjoint from private root and
  user-page frames; separately verified physical IA32_APIC_BASE frame
  must lie OUTSIDE PMM-managed RAM.
- Exact four-level path, with PRESENT|RW and never USER at the PML4,
  PDPT, PD and PT. The MMIO leaf MUST also set PCD|PWT and NX (no
  caching, no Ring3 access, no execution).
- Each private root must inherit the exact kernel-owned supervisor
  PML4 slot; no foreign root and no extra present device aliases.
  CPU A/D bits are audited as the only hardware-legal changes.
- Mapping admission is non-mutating until all preconditions pass.
  Teardown must happen only after timer LVT masked, in-service IRQs
  EOI'd, APs quiesced, all private user roots retired and TLB entries
  invalidated. This module does **not** perform that teardown.
- The fixed map resides in a different high-half PML4 slot from the
  guarded user TSS.RSP0 arena, so both are accessible in user CR3
  without making the device reachable from CPL3.

## Tests and non-goals

Adversarial `make test` host tests prove exact flags, slot collision
avoidance, rejection of dirty tables, duplicate/aliased PMM ownership,
missing NX, missing PCD, USER bits at any level, wrong private root and
clean unpublication.

This milestone is **NOT a live MMIO mapping**, not a QEMU interrupt
gate, not actual timer firing, and not user-mode preemption. Live
hardware publication and involuntary timer-driven Ring3 switches
remain the explicit acceptance criteria of Issue #91. Until then
no finished preemptive-userspace claim is appropriate.
