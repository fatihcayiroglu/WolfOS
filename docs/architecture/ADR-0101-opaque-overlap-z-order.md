# ADR-0101 — Opaque overlap and z-order proof on QEMU

Status: proposed. QEMU-only experiment stacked on ADR-0100 / draft PR #328.

## Goal and design

The prior verified scene contains two disjoint flat color windows and can
move the first without an occlusion case. This increment exercises a real
overlap in a single xRGB8888 VirtIO-GPU resource, with separate red and blue
opaque window pixels (different color channels) to expose incorrect clipping.

- Red logical window 1 starts at (11,19,16,16); blue logical window 2
  stays at (811,401,32,16).
- Move red to (819,401,16,16) fully inside the blue window, with red
  initially topmost. Old red rectangle is repainted as background, new red
  rectangle replaces blue's pixels rather than XOR mixing colors.
- Raise blue: repaint only its own 32x16 rectangle (covering hidden red).
- Raise red again: repaint only its overlapping 16x16 rectangle.
- Erase the scene: repaint blue's 32x16 rectangle to baseline; this covers
  the entire formerly red overlay. Verify original background digest.

All moves and raise operations use the bounded OpaqueScene logical
transaction contract. Neither logical geometry nor z-order is committed
before the GPU fences and host QMP screenshot capture have been confirmed.

## Real QEMU pixel authority

Five newly required, COM1-synchronized full-screen 1024x768 QMP captures:
opaque_initial, opaque_overlap, opaque_blue_front, opaque_red_front,
opaque_restored. The host checks every RGB pixel for each frame, including
the overlap, old position, fixed blue-only region and all untouched pixels.
The restore must be byte-for-byte equal to the baseline. Each of 7
partial dirty rectangles is sent with an independent 56-byte TRANSFER and
48-byte FLUSH; this adds 14 genuine control-queue used-ring completions
and five host capture acknowledgements (maximum 84 total controlq index,
including the existing full rollback path). No SET_SCANOUT or full-band
transfer is used during overlap/z-order stages.

Negative host unit fixtures must reject one-pixel corruption even outside
the visible windows, wrong z-order color combinations, missing/duplicated
captures, and forged fence/capture counts. Old QEMU one-rectangle, two-
rectangle, non-overlapping movement, real 15s rollback, Ring3, SMP and
timer gates remain mandatory and unchanged.

## Limits

This uses two hard-coded opaque rectangular test windows painted directly
into guest backing and a matched framebuffer. It does not establish
arbitrary application-owned pixel buffers, true UI widgets, z-order input
focus, alpha compositing, clipping for many windows, double-buffered frame
scheduling, vendor drivers or safe physical GPU/hotplug/refresh changes.
No test is skipped or rerun to invent a green outcome; PRs stay draft
and main is not modified without owner approval.
