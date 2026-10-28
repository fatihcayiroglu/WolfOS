# ADR-0022: Per-CPU local APIC identity (read-only)

Status: Under review; accept only after all branch, PR, and main QEMU tests.

## Decision
- Each boot CPU independently samples CPUID and IA32_APIC_BASE (MSR 0x1B).
- Guard RDMSR behind CPUID.MSR and CPUID.APIC feature bits.
- Use leaf 0xB x2APIC topology ID if supported; otherwise CPUID.1
  initial APIC ID. Compare with Limine's own LAPIC ID directory.
- Interpret bit 11 (global local APIC enable), bit 10 (x2APIC mode),
  bit 8 (BSP identification), and the physical base address.
- Require enabled APIC, unique BSP bit, matching per-CPU APIC IDs,
  nonzero base and the same base reported by every active CPU.
- Each AP writes only its own atomic slot, BEFORE publishing the AP_READY
  Release token. BSP observes AP_READY with Acquire before verifying.
- No IRQ handlers, allocations or serial I/O run on APs.

## Constraints
- Only x86-64 early boot, with Limine SMP ownership, interrupts disabled,
  and QEMU regression tests for one and four virtual CPUs.
- This reads an MSR; it does not map APIC MMIO, program its timer,
  change APIC mode, send IPIs or implement preemptive scheduling.
- CPUID leaf 0xB can be absent, so fall back to CPUID leaf 1
  (sufficient for QEMU's <=4 test CPUs, not arbitrary large systems).
- Firmware address discovery does not mean APIC MMIO is already mapped
  as safe writable memory. That is a separate engineering decision.
- Never write real disks; tests use a virtual ISO under QEMU.

## Acceptance
- Standalone host unit tests for IA32_APIC_BASE parsing and invalid bits.
- Single CPU QEMU: WOLFOS_LAPIC_ID_OK cpus=1 verified=1.
- Four CPU QEMU: WOLFOS_LAPIC_ID_OK cpus=4 verified=4.
- All existing exception, paging, timer, scheduler, and SMP tests stay green.
