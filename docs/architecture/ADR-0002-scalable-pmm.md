# ADR-0002: Scalable physical frame allocator metadata

Status: Proposed until actual QEMU CI passes.

## Problem
P1 started with a static 2 MiB bitmap in kernel BSS: 2 MiB * 8 * 4 KiB = 64 GiB.
That was a bootstrap implementation limit, not a legitimate target OS RAM limit.

## Decision
Use Limine's Higher-Half Direct Map (HHDM) and reserve bitmap backing pages
inside a contiguous MEMMAP_USABLE physical range at boot. Track all usable
4 KiB frames with one bit each; memory overhead is approximately 1/32768
of usable RAM. The bitmap itself remains permanently reserved.

Examples (usable memory, idealized):
- 64 GiB: 2 MiB bitmap
- 128 GiB: 4 MiB
- 256 GiB: 8 MiB
- 1 TiB: 32 MiB
- 4 TiB: 128 MiB

No fixed 64-GiB page capacity is coded. Limits remain:
- This bootstrap implementation stores at most 256 usable regions in BSS.
- One contiguous usable region must fit the bitmap metadata. A fragmented
  topology may require later multi-segment metadata.
- Bootloader HHDM access must remain mapped for the allocator lifetime.
- x86-64 pointer/address-space bounds, CPU/firmware support, and available
  physical memory are practical limitations.
- Interrupt reentry, NUMA, page hotplug, page reclaim and SMP are not supported.

## Correctness requirements
- Validate all usable region bounds and overlaps before writing metadata.
- Reject integer overflow or missing HHDM.
- Never allocate firmware, kernel, bootloader, framebuffer or metadata pages.
- Reject freeing metadata addresses, invalid alignment or unallocated frames.
- Keep page pointers distinct from virtual-mapped pointers.

## Verification
- Host Rust tests exercise the layout calculation for 64, 128, 256 GiB,
  1 TiB, and 4 TiB; no huge physical RAM allocation is required.
- Real QEMU smoke on 512 MiB checks HHDM-backed 10,000 allocation cycles,
  unique pages, bitmap metadata protection and standard boot markers.
- Tests for 1 TiB / 4 TiB are math-only until an appropriate VM or machine
  actually validates full-capacity use.

Never write to a real disk during this milestone.
