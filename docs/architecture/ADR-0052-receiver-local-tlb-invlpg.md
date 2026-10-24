# ADR-0052: Isolated recipient-local TLB invalidation before an IPI acknowledgement

Status: Accepted for **QEMU smoke evidence only**, not general-purpose Ring3 reclamation.

## Context

ADR-0051 introduced `ShootdownBarrier` as epoch-tagged metadata. Host unit tests
cannot prove that an actual AP ran an architectural TLB invalidation before
acknowledging its own bit. The earlier xAPIC IPI smoke proves delivery and EOI,
not translation invalidation.

## Decision

A dedicated build feature, `tlb-shootdown-hardware-smoke`, boots exactly four
x86-64 CPUs in QEMU q35. The BSP maps an uncached supervisor xAPIC page at
`0x0000_4000_0000_3000` **before** AP startup; it never unmaps or frees it.

The BSP verifies its own CR3 and that PCID is disabled, installs a unique
address-space barrier generation, starts one epoch targeting exactly the
three AP indices, and sends three directed fixed xAPIC IPIs. The hardware
interrupt handler on each recipient:

1. Reads the **local APIC ID** to authenticate its CPU index (not BSP data).
2. Checks the expected CR3 and that PCID is disabled.
3. Executes a real `INVLPG` on the resident APIC alias **on that AP**.
4. Under a single acquire/release coordinator lock, acknowledges **its own
   bit** for the current opaque barrier round.
5. Issues its local xAPIC EOI and returns from its private IDT handler.

The BSP does not hold that lock while awaiting APs, waits for each EOI,
checks the barrier cannot complete while any AP is missing, then requires
completion by the last AP. Two initial epochs each complete normally.

In a **third** epoch the BSP intentionally withholds the final recipient's
IPI after the first two real recipient-local invalidations/acknowledgements.
It verifies that exactly that CPU's bit remains pending, that a new epoch
cannot begin, and that the attempted premature begin changes no state.
Only after these negative observations does the BSP send the withheld
IPI and require the third epoch to complete. This is a deliberately
unsent IPI, **not evidence that hardware dropped an IPI** or that
production timeout/retry handling exists. Altogether nine hardware
IPIs, nine local INVLPG instructions and nine acknowledgements are
required. The check also requires three APs parked with interrupts
disabled, no unexpected interrupts, and no panic. A failure never
authorizes frame reuse.

`make tlb-shootdown-hardware-smoke` enforces a strict serial signature
and QEMU ISA debug-exit status. P0 CI runs this in addition to the
unaltered original AP-IPI and retirement smoke gates.

## Safety boundary and excluded guarantees

- This validates **one supervisor 4-KiB translation**, not unmapping,
  shootdown of stale *user* translations or executable Ring3 contexts.
- No PCID, global-page invalidation, INVPCID, x2APIC, or >4-CPU proof.
- No scheduler/runtime target-set discovery, IPI timeout recovery, retired
  context prohibition, frame ownership transfer, or safe reclaim capability.
- A software ack is never a stand-in for an actual local invalidation.
- The MMIO alias, AP stacks, page tables and referenced physical frames
  remain alive throughout the test.

A future production TLB shootdown must define per-ASID targets and flush
scope, prevent old-context re-entry, handle CPU online/offline transitions
and lost IPIs, and join physical-frame ownership only after every required
quiescence and invalidation proof.
