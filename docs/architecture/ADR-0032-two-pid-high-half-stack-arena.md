# ADR-0032 — Two-PID high-half guarded kernel stack arena

Date: 2026-10-15
Status: experimental single-BSP QEMU; not production TSS/scheduler.

## Change

Where ADR-0031 checked two hardware guard pages around one
*lower-canonical* supervisor test stack, this milestone reserves a
fresh independent **high-canonical** PML4 slot
`0xffff_d000_0000_0000` (index 416), and represents two separate
PID-owned supervisor stack ranges in one 4-level page-table subtree.

Each PID's interval contains [absent guard][four present supervisor
writable 4-KiB leaves][absent guard], for a total of FOUR true
unmapped guard PTEs, eight data leaves and three independently PMM-owned
table frames. Physical leaves are independently allocated; they need
not form a physically contiguous 16 KiB range.

The metadata registry refuses duplicate PIDs, physical aliases,
bad/already-owned table roots, malformed or duplicate frames, full
capacity, and stale slot generations. Nothing publishes the PML4 entry
until all two stacks' leaf PTEs are prepared. The audit accepts only
hardware-set A/D bits; it rejects any U/S escalation, wrong physical
address, or formerly absent guard PTE.

## Hardware acceptance

The map/cleanup flavor checks two distinct real PID stack VAs and
HHDM-backed physical canaries, audits CPU-modified PTE A/D bits,
unpublishes the entire reserved PML4 slot, explicitly invalidates
all twelve leaf/guard VAs from BSP TLB, verifies the stale tokens are
inert and returns EXACTLY 11 frames to PMM baseline, all under the
original boot CR3.

Two additional isolated QEMU boots probe the lower guard of PID 1
and upper guard of PID 2 using an assembly read instruction and demand
an actual supervisor non-present `#PF` with exact CR2, error bits
(P=0 W/R=0 U/S=0), kernel RIP and single-use ordered serial marker.
Their disposable negative guests exit before any PMM cleanup, by
design. The positive mapping guest tests PMM cleanup independently.

Every existing test remains required by CI. A green test here DOES
NOT mean two tasks executed or saved their CPU state concurrently.

## Scope and remaining risks

- This is a bounded test region and metadata model, not a general VMM.
- There are still HHDM aliases to the stack's data physical pages.
  The four protected *virtual* guard VAs are not aliases.
- No TSS.RSP0 or RSP uses these pages yet. No timer/interrupt/user
  handoff, fault recovery, FPU/SSE/XSAVE, scheduler or simultaneous
  Ring3 execution is claimed. Runtime pinning and virtual-range
  lifetime must be addressed before use as a live kernel stack.
- A later production mapper must manage a large high-half range,
  preserve kernel page mappings across every private user CR3,
  reserve independent guarded stacks per PID, handle AP TLB shootdowns,
  and support guarded recycling while task ownership is quiescent.

The next genuine multi-user scheduling test must simultaneously prove
separate user private CR3, RSP0/TSS, saved GPR/FXSTATE and two distinct
Ring3 ELF instruction streams, rather than inferring that from these
preflight checks.
