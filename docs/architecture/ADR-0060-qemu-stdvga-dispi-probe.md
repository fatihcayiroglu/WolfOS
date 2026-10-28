# ADR-0060 — QEMU Standard VGA Bochs VBE read-only hardware port proof

Status: Draft; exact-head QEMU CI required.

## Decision
- An independent, feature-isolated QEMU boot (`qemu-stdvga-dispi-smoke`)
  requires **exactly one** class-03 PCI function with vendor/device
  `1234:1111`. Never probe these legacy global ports on arbitrary GPUs.
- Only on BSP before SMP launch, read the Bochs VBE index selector at I/O
  port 0x1ce. For indexes 0 (ID), 1 (XRES), 2 (YRES), 3 (BPP), 4 (ENABLE)
  and 10 (VRAM / 64 KiB), write only the **index selector** and read data
  from port 0x1cf. Restore and read back the original selector.
- Validate the device ID in 0xB0C0..0xB0C5, mode dimensions/bpp when
  enabled, and that mode memory fits the reported VRAM.
- Do **not** write the data port, set a video mode, touch BARs/PCI command
  registers, map physical GPU memory, enable DMA, load firmware, access a
  real disk, or claim native GPU acceleration.
- Strict Python evidence must match actual QEMU serial logs, hardware
  selector-restoration proof, original VGA PCI identity, correct boot order
  and debug-exit code. Host Rust and Python negatives reject fabricated
  capabilities, insufficient VRAM and fake mode/acceleration claims.

## Scope
This is the first direct original WolfOS-to-emulated-GPU register handshake,
not a Windows/Linux/macOS GPU driver, and not a Bochs VBE accelerated GPU
backend. A later isolated PR may safely implement framebuffer mode
management and readback after mapping/ownership/recovery checks.

References (primary):
- QEMU Standard VGA: https://qemu.googlesource.com/qemu/+/4c2e5f8f46a17966dc45b5a3e07b97434c0eabdf/docs/specs/standard-vga.txt
- QEMU VBE source: https://github.com/qemu/qemu/blob/master/hw/display/vga.c
