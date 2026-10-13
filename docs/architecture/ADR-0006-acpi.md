# ADR-0006: Read-only RSDP discovery as the entry point to ACPI

Status: Proposed pending QEMU boot tests.

- Request RSDP from Limine. Base revision 0 returns a kernel virtual pointer.
- Validate the ACPI signature, 20-byte checksum and, if revision >=2,
  bounded extended length and extended checksum.
- Report revision, OEM ID and RSDT/XSDT physical addresses.
- Do not dereference RSDT/XSDT/MADT in this PR; physical addresses are NOT
  automatically valid Rust pointers. Later ACPI table walker must validate
  mapping lengths and table checksums.
- No firmware writes, device config writes, ACPI method execution or host
  storage access.

Limits: RSDP lengths above 4096 bytes are rejected; source pointer is trusted
only under the Limine bootloader contract. It is not a secure firmware
attestation mechanism. The next milestone validates RSDT/XSDT/MADT tables.

Acceptance: `make test` passes parser unit tests, including corrupted
checksums. `make smoke` checks WOLFOS_ACPI_RSDP_OK from actual QEMU.
Existing exception/paging smoke tests remain green.
