# ADR-0020: Isolated single-CPU timer IRQ acceptance

Status: Proposed until actual push and PR QEMU CI pass.

## Decision
- Use an additional cargo timer-smoke feature/ISO, separate from the normal
  kernel and existing single/four-vCPU smoke tests.
- The BSP enables interrupts only AFTER all SMP work/context-switch proofs
  have completed and APs are parked with maskable interrupts disabled.
- Remap legacy 8259 PIC to 0x20/0x28, mask all lines except IRQ0,
  configure PIT channel 0 in rate-generator mode at nominal 100 Hz.
- Install BSP IDT vector 32, increment an AtomicU64 and acknowledge PIC
  with a master EOI (0x20) in the x86-interrupt ABI handler.
- Verify at least eight hardware IRQs, then disable interrupts and mask PIC
  lines again before returning to boot completion.

## Limits
- QEMU q35 BIOS/legacy PIC path only; not universal PC or UEFI support.
- Not local APIC timer, HPET or stable wall-clock measurement. The tick count
  is an experimental counter and not an accurate monotonic time API.
- No preemptive context switching, AP interrupts, FPU/SIMD save, IRQ-safe
  allocator, scheduler locks or concurrency from interrupt context.
- If IRQ delivery is broken, timeout/fail; never silently skip.
- No real disk access; QEMU ISO only.

## Acceptance
make test, make smoke, make exception-smoke, make paging-fault-smoke,
make topology-smoke and make timer-smoke all pass in PR/push CI.
