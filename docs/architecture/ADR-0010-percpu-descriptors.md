# ADR-0010: Processor-local GDT/TSS/IST bootstrap

Status: Proposed until QEMU CI passes with 1 and 4 virtual CPUs.

Each secondary processor needs its own TSS and unique GDT descriptors:
the x86 hardware marks a TSS descriptor busy when load_tss is called.
Sharing the BSP's TSS descriptor across CPUs is not allowed.

## Decision
- Keep a permanently mapped, immutable shared IDT installed by the BSP.
  Publish the IDT_READY state using Release ordering, read by APs with Acquire.
- Each AP gets an exclusive static GDT, TSS and 20 KiB double-fault IST.
  Per-core resources are indexed by their unique Limine MP directory index.
- AP entry disables external interrupts and loads code/data selectors, then
  its own TSS, followed by the shared IDT. No shared serial/PMM access.
- An AP publishes its handshake only after per-core tables initialize.
  BSP verifies all AP handshakes and emits SMP_PERCPU_OK marker.

## Limits
- 256 boot CPU slots with ~5 MiB reserved total IST storage, to be refined.
- The bootloader's separate AP kernel stacks remain in use while APs park.
- No per-core kernel runtime stack switching, AP exceptions in negative tests,
  IRQ/IPI delivery, timers, running tasks, process scheduler or AP allocator.
- All shared interrupt handlers still use BSP-oriented serial diagnostics:
  not production-safe concurrent exception paths.
- Never write to physical storage.

## Acceptance
- make smoke: 1 CPU, no AP descriptors initialized.
- make topology-smoke: 4 QEMU CPUs and exactly 3 successfully initialized
  AP-specific GDT/TSS/IST sets plus the shared IDT.
- Existing #UD, #PF and PMM tests must continue to pass.
