# ADR-0080 — Three real PMM-owned VirtIO controlq frames, no DMA

Status: **proposed**. QEMU-only draft stacked after #311. No production merge authorization.

## Context

PR #311 verifies the real QEMU VirtIO-GPU controlq is reset with zero
descriptor/driver/device addresses. A bounded 256-descriptor split ring uses
three independent physical regions, each fitting within one 4096-byte page.
The existing WolfOS bootstrap PMM exposes single-page allocate/free, not an
unverified contiguous multi-page allocator.

## Decision

- A new isolated `qemu-virtio-gpu-controlq-pmm-smoke` feature runs only
  after the full PCI/MMIO, feature negotiation/reset, and read-only QEMU
  queue0 proofs. Normal OS boots and physical GPUs do not enter this code.
- Pass the **observed** read-only queue0 layout to the PMM test; no guessed
  hardware queue size.
- On the BSP, with interrupts disabled, require three one-page split-ring
  areas. Acquire three unique, aligned PMM frames for descriptor, available
  and used regions; use the checked disjoint-region contract of ADR-0079.
- Access only the three exclusively owned **usable RAM** frames through
  Limine HHDM. Zero all 4096 bytes of each frame and confirm all bytes are
  zero using volatile reads.
- Whatever happens after the first allocation, release **every** acquired
  frame in reverse order. Require pre/post `allocated_frames` equality,
  peak increase exactly 3, three successful releases, and no overlap.
- Real QEMU CI validates an exact serial proof marker, correct ordering and
  strict rejection of duplicate, missing, altered, leaked, partial or
  faked PMM evidence. The error-artifact-only step is conditional and not a
  skipped test. No retries.
- The allocated physical addresses are **never registered with the device**,
  no queue registers or PCI configuration are written, no `DRIVER_OK`,
  no queue-enable, no descriptor submission, no DMA, notifications,
  display changes or real disk writes.

## Not complete

No persistent PMM queue lease, queue enable or GPU command exchange exists yet.
Next isolate durable queue ownership and reset-failure cleanup, then register
the queue in a bounded QEMU-only test (without DRIVER_OK), before the first
real `GET_DISPLAY_INFO` or `GET_EDID` request. Resolution/refresh auto policy
and user overrides remain future work.
