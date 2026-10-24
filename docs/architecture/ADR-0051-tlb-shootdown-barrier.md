# ADR-0051: Generation-tagged TLB shootdown acknowledgement barrier

Status: experimental host-tested coordinator protocol (not hardware-enabled)

## Context

ADR-0048 through ADR-0050 established serialized CR3 reservation and
move-only ownership of PMM frames that must never be returned while a
participating CPU can use them. The current safety boundary explicitly
does not implement general Ring3 teardown, saved-context invalidation,
PCID/global-translation invalidation or IPI TLB shootdown.

## Decision

Add `kernel/src/tlb_shootdown.rs` as an allocation-free, bounded
(1–64 CPU) metadata barrier. Each round has an address-space generation
and monotonically increasing epoch. Its nonzero participant mask cannot
change mid-flight; every targeted CPU needs one local authenticated
acknowledgement. Old rounds, duplicate acks, untargeted CPUs, invalid
CPU indexes and new-round attempts while outstanding are rejected.
Epoch overflow fails closed.

`acknowledge_after_local_flush` is **unsafe**: only a participant
executing on its authenticated CPU after actual architectural
invalidation and ordering may call it. The coordinator must use
an exclusive lock for all barrier mutations but must never hold a lock
that the remote interrupt/acknowledgement path needs while waiting.
The barrier itself never emits IPIs or invalidates a TLB.

A completed round is only coordinator bookkeeping; it does not
authorize `ActiveAddressSpace::reclaim`, replace the retirement
ledger, or prove that saved Ring3 contexts, shared mappings,
PCID-tagged translations, global mappings or devices are quiescent.
Timeouts and lost metadata must retain allocations, not free them.

## Verification

- Standalone Rust host tests cover all 24 acknowledgement permutations
  for four CPUs, stale rounds, invalid/duplicate/untargeted CPU
  acknowledgements, 64th-bit target handling and epoch exhaustion.
- The host tests are included in `make test` and the module is wired
  into the kernel compilation.
- QEMU and GitHub CI still need to validate the exact PR head. These
  tests simulate the acknowledgements, not actual TLB invalidations.

## Follow-up required before reclaim is safe

1. Choose correct xAPIC/x2APIC IPI transport and per-CPU handler
   registration; authenticate CPU identity at the trap boundary.
2. Publish the target round with correct memory ordering and verify
   actual invalidation on every target CPU (including PCID/global rules).
3. Block untracked CR3 reloads and retire every saved Ring3 context.
4. Integrate the barrier with address-space ownership and release only
   after **all** external invariants have independently been proven.
5. Add real four-vCPU QEMU fault-injection gates before claiming
   general Ring3 memory reclamation.
