# ADR-0023: Explicit uncached xAPIC MMIO read-only bootstrap probe

Status: Proposed until push/PR and merged-main CI pass.

## Decision
- Keep independent per-CPU IA32_APIC_BASE MSR/CPUID verification from #24.
- On BSP, before releasing APs, read its own validated CPUID and MSR to
  obtain the legacy xAPIC base; refuse x2APIC mode (MSR-only registers).
- Refuse MMIO physical ranges overlapping RAM/ACPI/kernel/bootloader-memory
  types from the Limine memory map. The APIC base must be page-aligned.
- Map one page with Present, PCD and PWT flags; no Writable or User flag.
  Explicit page table mapping is required: HHDM coverage of MMIO is *not*
  presumed. Read local xAPIC ID and Version registers at offsets 0x20/0x30
  using volatile 32-bit loads.
- Verify xAPIC ID matches BSP's Limine LAPIC ID and version is plausible;
  always unmap and flush TLB before reporting any success.
- New page-table frames remain PMM-owned and retained in active CR3.
- Host unit tests cover register decoding, mismatched IDs and corruption.
- Single-CPU and four-CPU QEMU boot smoke checks require the read-only marker.

## Explicit limits
- This is NOT APIC timer programming, IPIs, SMP interrupt delivery, NMI
  routing, clock calibration, tick-driven preemption or production MMIO API.
- Only BSP reads registers; APs still have independent MSR/CPUID checks.
- No cache-type MTRR/PAT audit; PCD/PWT is a conservative interim mapping.
- No physical host disk reads or writes; virtual ISO/QEMU only.
- The shared page tables are changed only before AP start and with IRQs
  masked; no SMP TLB shootdown is needed for this isolated mapping.
