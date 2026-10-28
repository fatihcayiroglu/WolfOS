# ADR-0061: Match QEMU standard-VGA scanout to the Limine framebuffer before painting

Status: proposed, isolated draft stacked on ADR-0060 / PR #292.

## Decision

The first WolfOS display device probe is deliberately **read-only**. Bochs VBE
`0x1ce` selects registers and `0x1cf` is read, never written. The original
selector is restored and checked. A detected PCI display function is **not**
a permission to initialize an arbitrary vendor driver.

The feature-isolated `qemu-stdvga-dispi-smoke` next requires the **enabled**
QEMU VBE scanout to match the bootloader-owned RGB framebuffer before any
WolfOS framebuffer stores:

- An exact 1:1 match of VBE X/Y geometry to Limine width/height.
- VBE BPP = Limine BPP = 32; RGB packed-channel assumptions separately checked.
- Stride must be 4-byte aligned and at least 4 bytes per horizontal pixel.
- Checked stride × height must fit the VBE-reported VRAM and isize pointer span.
- VBE ID and selector restoration already pass ADR-0060's observation contract.
- The early static color-band fill moves after complete framebuffer geometry and
  pointer-alignment validation, even for ordinary non-smoke boots.

Failures are terminal and emit `WOLFOS_QEMU_DISPLAY_ATTEST_FAILED` before
painting. The proof marker `WOLFOS_QEMU_DISPLAY_ATTEST_OK` is printed only
after success. Strict serial evidence tests require probe → attestation →
framebuffer pixel readback → boot completion in order.

## What this does NOT establish

The framebuffer remains mapped and configured **by Limine**, not WolfOS's own
GPU driver. This is a single tested QEMU standard-VGA contract; it is **not**
AMD, NVIDIA, Intel, physical hardware, a mode setter, DMA, BAR initialization,
interrupt handling, multi-GPU routing, or graphics acceleration. No real disks
are accessed. Keep the PR draft and validate on a single exact-head CI run
before proposing integration. Reject out-of-sync scanout rather than guessing.

Upstream specification: https://qemu.googlesource.com/qemu/+/4c2e5f8f46a17966dc45b5a3e07b97434c0eabdf/docs/specs/standard-vga.txt
