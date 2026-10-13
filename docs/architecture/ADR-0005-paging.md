# ADR-0005: First active page-table mapping and page-fault test

Status: Proposed pending actual QEMU CI, not production virtual memory.

## Decision
- Retain Limine's current CR3 and Higher-Half Direct Map (HHDM).
- Use the Rust x86_64 crate to inspect PML4 and map one 4-KiB RAM frame
  at reserved lower-half test address 0x0000400000000000.
- PMM owns data and any newly allocated page-table frames.
- Verify translation, volatile write/read, unmap and TLB flush.
- Return the data page only; retain intermediate tables in active CR3.
- Build a separate smoke ISO that deliberately accesses the unmapped page
  via assembly and requires #PF vector 14 and CR2=the test address.

## Limits
- Single boot CPU, IRQs disabled. Not an independent address space, user mode,
  general-purpose allocator, COW, page-table reclamation or safe process
  isolation. NX and RO permissions are not yet verified.
- Test slot must be unmapped at start. Boot fails closed if already mapped.
- Failed mapping may retain allocated frames; the boot caller halts.
- This build never accesses physical disks.

## CI acceptance
- make smoke
- make exception-smoke (existing #UD regression)
- make paging-fault-smoke (new #PF)
- make test (static and host Rust layout tests)

No completion claim before actual GitHub Actions QEMU test passes.
