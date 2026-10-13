# ADR-0007: RSDT/XSDT and MADT read-only discovery

Status: Under review; CI tests passing.

## Decision
- Require Limine base revision 4 for HHDM mapping of ACPI firmware regions.
- Root: use XSDT when RSDP revision 2+ supplies nonzero XSDT,
  otherwise RSDT. Validate standard SDT 36-byte headers, bounded total
  lengths and full ACPI checksums before parsing entry pointers.
- Validate firmware physical address ranges against Limine memory map;
  only ACPI_RECLAIMABLE, ACPI_NVS or MAPPED_RESERVED regions are read.
  Use the Limine HHDM mapping but never assume a firmware physical
  address is itself a Rust pointer.
- Restrict each SDT to 1 MiB and root directory to 256 entries; fail
  closed on untrusted lengths, invalid checksums and duplicates.
- Recognize MADT (APIC) and safely walk variable-size local APIC,
  x2APIC and I/O APIC records. Count enabled logical processors,
  online-capable processors and I/O APICs. No actual AP startup.
- Unknown MADT record types are skipped by bounded record lengths.

## Scope and limits
- Only platform enumeration: no SMP, I/O APIC programming, interrupt
  routing, timers, ACPI AML, power management, or actual device drivers.
- Assumes single boot CPU, IRQs disabled, Limine HHDM still installed
  and ACPI firmware memory remains reserved.
- Counts may not match CPUs allowed by later policy or hotplug.
- Does not write physical disks, PCI config, or ACPI firmware memory.

## CI acceptance
- make test includes host Rust checks for RSDT/XSDT, MADT and corruption.
- make smoke boots a QEMU machine and requires ACPI_ROOT_OK, ACPI_MADT_OK.
- make exception-smoke and make paging-fault-smoke must remain green.
