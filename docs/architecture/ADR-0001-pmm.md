# ADR-0001: Bootstrap physical frame allocator (P1)

Status: Proposed, pending actual QEMU acceptance in GitHub Actions.

## Decision

A bounded static bitmap allocator in the Rust kernel:
- Accept only Limine MEMMAP_USABLE pages after 4 KiB alignment.
- Reject overlapping memory ranges and arithmetic overflow.
- Store metadata in kernel BSS, with no heap or disk dependencies.
- Return page-aligned physical addresses, NOT mapped virtual pointers.
- Detect invalid and double frees.
- Refuse to initialize for more than 128 usable ranges or 64 GiB usable RAM.
- Single-core bootstrap context. Do not call from interrupt handlers.

## Safety scope

This manages physical addresses only: it does not write through returned addresses,
map pages, initialize heap allocation, handle DMA or use physical disks. The
kernel BSS bitmap is reserved by the bootloader, not managed as usable RAM.
This bootstrap allocator must be redesigned for dynamic metadata, SMP and
interrupt-safe use before production readiness.

## Validation

make test: source-level contracts only.
make smoke: Rust build and actual QEMU boot, requiring
WOLFOS_PMM_OK, WOLFOS_PMM_TEST_OK iterations=10000 unique=128,
and WOLFOS_BOOT_OK.

No completion claim until CI QEMU smoke passes.
