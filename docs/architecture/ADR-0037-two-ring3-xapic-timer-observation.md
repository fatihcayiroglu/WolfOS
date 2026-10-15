# ADR-0037 — Real xAPIC timer IRQ from two native CPL3 ELF busy loops

Date: 2026-10-15
Status: isolated hardware experiment until full CI gate passes.

## Why the existing kernel timer driver cannot simply be reused

The existing single-BSP xAPIC smoke uses a non-user lower-half UC alias
at VA 0x0000400000002000 for EOI. The two private ELF64 processes each
replace PML4[0] with a separate private PDPT. Consequently, blindly
using that low alias in the timer IRQ handler would #PF in user CR3.

This PR introduces an independent high-canonical supervisor-only UC
xAPIC MMIO mapping in a formerly empty boot PML4 slot. It is
automatically grafted into both sanitized private CR3 roots, yet
neither executable nor USER_ACCESSIBLE; each mapping is pinned until
the timer LVT has been masked and both user processes quiesced. Three
PMM frames provide its PML4 subtrees; 28 frames total are reclaimed.

## Observable real hardware proof

The existing xAPIC timer smoke first validates BSP MSR/ID/MMIO region,
enables the software-enabled spurious vector, programs the periodic LVT
vector 0xe0 with the installed DPL0 interrupt gate, and masks both
legacy PIC controllers. Instead of synthetic invoking its handler, it
enters two separately linked native ELF64 programs via actual CPL3
IRETQ with IF=1, each with a distinct private user CR3, supervisor
guarded TSS.RSP0 and FXSAVE64 state.

In a separately assembly-selected ELF build flavor each program runs
**six million non-yielding loop iterations** before each of its four
INT80 yields. The real xAPIC interrupt entry captures 15 GPRs plus the
five-word hardware CPL3 trap. A dedicated callback verifies:

- actual CR3/TSS.RSP0 belongs to the only RUNNING PID;
- the exact trapped 160-byte frame lies at its private RSP0 top-160;
- the CPU FPU owner, PID GPR signature and actual user RIP/RSP and
  privilege selectors are valid; user IF=1, IOPL=0;
- actual saved user RIP is within that PID's independent ELF RX page;
- at least one timer IRQ per PID has hardware RIP within its exact
  non-yielding assembly busy window;
- issue exactly one EOI through the inherited, **high supervisor-only**
  xAPIC MMIO alias while under the actual private CR3.

This milestone deliberately returns the SAME saved frame from timer
IRQ, rather than switching to the other PID. The existing voluntary
INT80 yield path continues switching contexts between processes.
On completion, timer LVT masked/count zero, SVR restored, original PIC
masks restored, high MMIO subtree unpublished, 28 frames freed, original
TSS/FPU/CR3 restored. QEMU assertions require exact markers and
same 8 yields, 9 user cross-PID IRETQs and 2 exits.

## Important limitation

This demonstrates **genuine involuntary local-APIC timer IRQ entry and
return in both real Ring3 programs** during syscall-free CPU work, but
not yet **involuntary cross-PID scheduling**. The timer interrupts
currently resume the interrupted same PID. The next PR must save the
preempted frame/FX image and restore a DIFFERENT runnable PID with an
actual CR3/TSS handoff, plus correct timer EOI and fully validated
state; retain all prior CI gates.


## Integration acceptance against main after #93 / #94

This ADR and its timer QEMU proof must be revalidated against the
updated main containing #93's independent supervisor high-half UC
xAPIC mapping contract and #94's publish-last-PML4 requirement.

The new `user_xapic_high::publish` routine fully initializes its
PMM-owned PDPT/PD/PT before its *final* PML4 publication store and
rejects an occupied root slot; it is NOT a substitute for the
#93/#94 pure contract on other root users. The timer high-half mapping
and the separately gated contract have distinct ownership/lifetime
requirements; neither bypasses the other's CI gate.

When the feature branch predates #93 and #94, require a complete
pull-request CI checkout against the NEW merge base and green tests
on the exact changed head SHA. A successful earlier branch-only
run against the older base is insufficient evidence of integration.
Do not close issue #91; all timer IRQs still resume the same PID.
