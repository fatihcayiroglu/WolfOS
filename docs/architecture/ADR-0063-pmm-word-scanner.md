# ADR-0063: Word-granular PMM bitmap search for high-memory systems

Status: independent optimization candidate, based on `main` (not the unmerged Ring3 PR stack).

## Motivation

WolfOS already sizes its PMM bitmap mathematically beyond 64 GiB. However,
`FrameState::allocate` searched each 4-KiB frame's bit in order, meaning a
mostly allocated 64-GiB arena (16,777,216 bits) required potentially millions
of per-bit tests before finding the last free page.

## Decision

- Extract a pure no-heap/no_std `first_clear_bit(bitmap, start, end)` operation.
- Probe one 64-bit word at a time in little-endian byte order, safely masking
  unaligned begin/end bounds and handling a final short word without reading
  past the bitmap. Return `None` for invalid ranges or capacity overflow.
- Preserve the exact allocator cursor, wraparound, PMM lock, metadata
  reservations and physical-region address translation. The lookup returns
  only a candidate bit: `FrameState` still owns its mutation and records the
  allocation before returning it.
- Keep the temporary bitmap shared slice scoped so its reference ends before
  a raw bitmap bit write, respecting aliasing requirements.
- Add host tests for boundary bits, scanner immutability, short trailing word,
  first-half wrap, invalid ranges, exhaustive deterministic reference
  comparison, and a virtual 64-GiB bitmap filled except for the final frame.
- Keep all existing 64-GiB-to-4-TiB bitmap sizing tests and actual QEMU PMM
  allocation/free/double-free/no-leak checks.

## Limitations

This is a search-loop performance improvement. It does not claim actual
64-GiB physical RAM boot validation, NUMA, memory hotplug, concurrent
interrupt-safe allocation, a general virtual-memory manager, or a desktop.
The 64-GiB regression allocates **2 MiB of host metadata**, not 64 GiB of
physical memory. Real hardware/disk access is never required.

The algorithm has no allocator side effects outside the existing lock.
If bitmap state is inconsistent or capacity invalid, it refuses allocation
rather than returning an unchecked frame.
