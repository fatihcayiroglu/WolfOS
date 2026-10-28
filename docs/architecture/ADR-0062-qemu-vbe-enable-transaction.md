# ADR-0062: Isolated Bochs VBE ENABLE-bit transaction with rollback proof

Status: proposed; opt-in QEMU-only draft stacked on ADR-0061 / PR #293.

## Scope and motivation

WolfOS has shown read-only PCI identity, genuine Bochs VBE register reads,
and an enabled scanout-to-Limine-framebuffer match before painting. This ADR
permits the **first two controlled GPU device-register writes** under a
narrower isolated QEMU smoke flavor. It is not a mode-set driver, third-party
GPU driver, DMA capability, a dynamic display service or hardware deployment.

The qemu-stdvga-enable-tx-smoke feature is disabled in production boot
and requires exactly one QEMU PCI stdvga display class function 1234:1111,
prior VBE ID b0c5, restored selector, enabled packed 32-bpp scanout,
and exact ENABLE value 0x0041 (enabled + linear framebuffer).

## Bounded reversible transaction

1. Run BSP only with interrupts disabled, before SMP startup.
2. Validate actual VBE mode equals Limine width/height, BPP, pitch/VRAM
   constraints and mapped/aligned framebuffer.
3. Save the index port selector and first framebuffer pixel, then
   write an XOR-pattern sentinel through an aligned volatile pointer.
4. Select DISPI ENABLE (index 4) and re-read the required original 0x0041.
5. Write 0x00c1 (**NOCLEARMEM** added) to the single DISPI data port.
   Read back 0x00c1.
6. **Always** restore original 0x0041 with a second data-port write even
   if the temporary readback differs. Read back the restored value.
7. Re-read all known ID/mode/VRAM fields and the original index selector.
   Verify sentinel survived. Restore the original pixel unconditionally.
8. Emit WOLFOS_QEMU_VBE_ENABLE_TX_OK only if original snapshot, mode,
   bit settings, selector and actual framebuffer sentinel all match.
   Failure is explicit and terminal.

The two writes alter only an already-enabled QEMU virtual VGA control flag;
resolution/stride/BPP stay unchanged. QEMU's open VGA emulator source clears
VRAM when changing from disabled to enabled, not during already-enabled
NOCLEARMEM toggle. Test confirms actual memory/pixel preservation.

## Strict exclusions

No write to geometry, PCI config space, BAR/MMIO or real GPU registers; no
firmware, PCI memory sizing probes, mode change, DMA, acceleration,
filesystem access, physical device boot, dynamic driver selection or install.
Do **not** label success as a native mode-setting driver or as GPU
comparable to dedicated NVIDIA/AMD/Intel hardware. If QEMU hardware
readback differs, do not retry to turn it green; inspect first failure.

Reference (QEMU upstream): https://qemu.googlesource.com/qemu/+/d6f8342a87d9b7a24819ba9a93bf9d3f1f583fe5/hw/display/vga.c
Bochs VBE register contract: https://github.com/bochs-emu/VGABIOS/blob/master/vgabios/vbe_display_api.txt
