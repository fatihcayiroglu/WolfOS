# ADR-0072 — Prefer-first VirtIO PCI capability alternatives

Status: draft, stacked on ADR-0071 / PR #303.

## Decision

The VirtIO 1.2 PCI mapping specification permits **multiple vendor capability
instances of the same configuration type**. A driver should generally select
the first instance in the PCI capability-list order, which indicates device
preference. The original strict QEMU parser rejected every duplicate as an
error, so it was not valid as a generalizable VirtIO transport boundary.

This change:
- Preserves the first valid common/notify/ISR/device region for each type;
  records the number of well-formed alternatives, never overwrites the
  first notification offset multiplier or BAR.
- Validates *every* recognized alternative's length, BAR index, region
  arithmetic and notify multiplier before accepting the chain, so malformed
  trailing alternatives still fail closed.
- Requires common and GPU device offsets aligned to 4 bytes, notify
  aligned to 2 bytes, ISR byte-aligned. All other previous pointer,
  overlap and loop checks remain in force.
- Changes the genuine QEMU capability gate from exactly four recognized
  capabilities to **at least four**, while retaining the two existing
  real-QEMU 1af4:1050 ISO tests. Adds four host parser tests.

Specification: https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html
(section 4.1.4 and preference order for duplicated vendor capabilities).

## Limits

No physical GPU or disk, no BAR-size probing, MMIO mapping or DMA.
The parser intentionally continues to handle only the required basic
32-bit capability offset/length representation; optional extended 64-bit
region offsets, full resource allocator and true VirtIO device transport
are future work. This change does not claim accelerated graphics,
physical monitor refresh or EDID negotiation.
