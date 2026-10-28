# ADR-0066: Bounded software GPU command queue and synchronous fence baseline

Status: QEMU-only verified reference backend required; physical GPU acceleration pending.

## Purpose
WolfOS needs original, safe command submission and surface-management
interfaces before it can implement independent Intel/AMD/NVIDIA drivers.
The first reference backend executes two operations on a known, mapped
32-bit pixel surface: FillRect and overlapping CopyRect (memmove semantics).
This is a **CPU software executor**, not a native GPU command queue.

## Safety contract
- A Layout has checked dimensions, 32bpp byte pitch, backing length and
  overflow-safe footprint. No bogus/partial-pixel stride or short backing.
- Rectangles and copy destinations are checked for zero size, overflow,
  clipping and bounds before enqueuing. Entire batches are validated before
  queue state/fence changes; bad batches fail atomically at submission.
- Queue capacity = 8 without heap allocations. Busy/pending batches cannot
  be overwritten; a new fence ID is monotonic, never wraps.
- Each execute verifies identical staged layout, required backing length and
  pending commands before any framebuffer modification. The CPU uses
  volatile byte loads/stores to handle MMIO-like framebuffer mapping safely.
- Command execution is synchronous. The completed fence advances only
  after all command writes; no hardware GPU fence, DMA or asynchronous
  acceleration is implied.
- CopyRect handles overlapping horizontal or vertical regions in safe
  row/column order, preserving pre-copy source pixel semantics.

## Actual QEMU-only smoke
An opt-in feature qemu-stdvga-software-queue-smoke inherits the genuine
PCI 1234:1111 Bochs VBE probes, Limine scanout attestations, two real
ENABLE writes, full-state equality and 11-write mode rollback from
ADR-0060 through ADR-0064. On a separate disposable QEMU -smp 1 ISO:
1. Save the first five original framebuffer words.
2. Stage and execute three different one-pixel Fill commands (fence 1).
3. Stage and execute one overlapping right-shift Copy (fence 2).
4. Verify destination [A,A,B,C], untouched fifth pixel, queues empty,
   sequential completed fences 1 and 2; restore ALL original pixel words.
5. Verify the original five pixels and print one strict evidence marker.
   On any failure, still restore the pixel words and fail closed.

Host Rust tests prove validation/fences/overlap; adversarial Python evidence
tests reject missing/reordered/forged serial messages, GPU acceleration
claims or missing previously required QEMU proofs.

## Remaining work
The software queue is a small architectural starting point, not the
hardware GPU. Future drivers need PCI BAR access and safe MMIO mappings,
GPU resource memory allocation and lifetime tracking, vendor command
encoding, real fences/interrupts, command buffer validation, GPU context
isolation, GPU resets, shader execution and accelerated graphics backends.
No physical hardware is addressed by the QEMU-only flavor.
