# ADR-0063: Preserve the whole QEMU Bochs VBE virtual-display layout

Status: proposed, isolated draft stacked on ADR-0062 / PR #294.

## Why this extra proof is required

The first reversible VBE ENABLE transaction (ADR-0062) verified geometry,
device identity, memory size, selector and framebuffer pixel. That did
not yet establish that the virtual plane, bank and visible pan offset
were preserved. Those registers influence true mode-setting rollback.

QEMU's open VGA emulator calculates virtual width, maximum virtual
height from available VRAM, per-row pitch and panning offsets. Its VBE
register indexes 5..9 expose BANK, VIRT_WIDTH, VIRT_HEIGHT, X_OFFSET
and Y_OFFSET. In the reference 1280x800 32bpp / 16MiB mode, an actual
virtual height around 3276 rows is expected, despite only 800 visible.

## New QEMU-only opt-in proof

Feature: qemu-stdvga-full-state-smoke (implies existing controlled ENABLE
transaction). On a single pre-SMP bootstrap CPU with interrupts off:

1. Confirm exact PCI 1234:1111, Bochs ID b0c5, ENABLE 0x0041 and the
   firmware RGB framebuffer's size/stride/VRAM capacity.
2. Read indexes 5..9 via saved/restored port INDEX 0x1ce, **never**
   writing data port 0x1cf in the snapshot code.
3. Require BANK=0 and X/Y_OFFSET=0 (un-panned linear framebuffer).
4. Require VIRT_WIDTH >= XRES and VIRT_HEIGHT >= YRES and
   VIRT_WIDTH * VIRT_HEIGHT * 4 <= reported video RAM, with checks.
5. Execute the separate QEMU ENABLE NOCLEARMEM toggle and rollback with
   pixel sentinel preservation from ADR-0062.
6. Read indexes 5..9 again. Fail closed if any field or selector changed.
7. Only emit WOLFOS_QEMU_VBE_FULL_STATE_OK on exact equality, with
   separate BEFORE and AFTER observations tied to correct boot ordering.

## Non-goals

No physical GPU access, actual resolution switch, register programming
of X/Y/BPP, BAR sizing writes, DMA or vendor acceleration. Limine still
owns the framebuffer; this closes a rollback precondition only.
Independent real-QEMU smoke and strict negative parser tests gate CI.
No real disk writes, no merge to production main without review.

Primary QEMU implementation:
https://qemu.googlesource.com/qemu/+/d6f8342a87d9b7a24819ba9a93bf9d3f1f583fe5/hw/display/vga.c
