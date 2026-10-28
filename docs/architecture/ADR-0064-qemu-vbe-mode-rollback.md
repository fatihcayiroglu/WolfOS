# ADR-0064: QEMU-only reversible Bochs VBE resolution transition

Status: experimental, draft stacked on ADR-0063; does **not** authorize production driver mode writes.

## Context
ADR-0060 validates a QEMU stdvga PCI 1234:1111 Bochs VBE port handshake.
ADR-0061 requires read-only DISPI mode to agree with Limine 32-bit RGB framebuffer.
ADR-0062 executes two real reversible NOCLEARMEM ENABLE writes and verifies pixel preservation.
ADR-0063 samples the BANK, VIRT_WIDTH, VIRT_HEIGHT, X_OFFSET and Y_OFFSET registers
before/after those writes. None of these tests actually changed resolution.

## Decision
Add isolated feature qemu-stdvga-mode-rollback-smoke, enabled only by
make qemu-stdvga-mode-rollback-smoke. It inherits all prior checks, requires
an exact 1280x800 32-bit VBE 0x0041 QEMU startup layout and safe initial
virtual plane, and runs under -M q35 -vga std -smp 1.

After saving a framebuffer pixel, it makes 11 *data-port* writes:
1. DISABLE=0, XRES=1024, YRES=768, BPP=32, ENABLE=0x00c1.
2. Capture the temporary geometry, virtual layout and selector readback.
3. **Unconditionally after step 1**, DISABLE=0, XRES=1280, YRES=800,
   BPP=32, ENABLE=0x00c1, ENABLE=0x0041, even when temporary evidence fails.
4. Restore original index selector. Capture all original mode and full
   virtual-plane registers; compare exact equality and pixel witness.
   Restore the saved pixel even on mismatch.
5. Only then print a unique success marker and proceed to the ordinary
   framebuffer drawing/boot smoke. Otherwise fail closed without claiming a pass.

The VBE ENABLE 0x0080 NOCLEARMEM bit is required on every disabled-to-enabled
transition so the framebuffer witness is not erased by the emulated device.
See QEMU hw/display/vga.c, vbe_ioport_write_data and vbe_fixup_regs:
https://qemu.googlesource.com/qemu/+/d6f8342a87d9b7a24819ba9a93bf9d3f1f583fe5/hw/display/vga.c

## Safety and remaining limitations
- No production default/feature, no physical AMD/Intel/NVIDIA binding,
  no BAR/PCI config writes, DMA, MMIO programming, vendor firmware or
  native GPU acceleration. The original Limine firmware framebuffer remains
  the only graphics interface used for drawing.
- 11 DATA writes are scoped strictly to one disposable QEMU virtual GPU.
  The test runs before interrupt/SMP execution; there are no disk writes.
- On unexpected intermediate results, the rollback still runs, but a QEMU
  hang or physical power loss cannot guarantee recovery; therefore this
  proof must never run against real hardware.
- Exact success requires real QEMU serial output, valid parent proofs,
  nonzero test exit (isa-debug-exit code 33), strict marker ordering,
  and no skipped/faked checks. Host policy/unit evidence cannot substitute
  for the live QEMU hardware-mode test.
- If the VBE virtual plane or 32-bit pixel is not conserved, fail the PR;
  do not weaken the contract, mark CI green, or merge to main.
