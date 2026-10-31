# ADR-0100 — Transactional two-window move proof on QEMU VirtIO-GPU

Status: proposed. Independent experimental QEMU-only feature, stacked on ADR-0099.

## Contract

WolfOS needs a pathway from pixel-level damage regions to user-visible
window movement. This milestone introduces the allocation-free
\`virtio_gpu_window_scene\` logical layout with two named surfaces: window 1
(11,19,16,16) and window 2 (811,401,32,16). The first window may move
transactionally to (211,119,16,16) without modifying the second.

The scene rejects invalid, off-screen, resized or overlapping rectangles,
moves of an unknown surface, and concurrent move requests. The logical
window position changes only via \`confirm_move\`; the actual QEMU acceptance
driver invokes this after both separate GPU transfer+flush fences are
verified AND the host's full-screen pixel screenshot has been acknowledged.

## Real-device emulation acceptance

Three additional synchronized full-screen QMP screenshots are mandatory:

1. "windows": both disjoint windows rendered, 768 pixels changed; all
   785664 outside pixels remain equal to the baseline.
2. "window_moved": window 1 at its new position, old window rectangle
   restored to baseline, window 2 unchanged.
3. "windows_restored": both windows removed, all 786432 pixels identical
   to the original background.

Each transition transfers exactly two disjoint damage rectangles
(56-byte TRANSFER_TO_HOST_2D and 48-byte RESOURCE_FLUSH each) with separately
fenced real controlq completions, so this stage adds twelve commands and
three host capture acknowledgements. No full-band transfer or SET_SCANOUT
is issued during these changes. Only after full restoration can the
existing resolution-change/15-second rollback proof and reset-before-free
cleanup execute. The final full workflow must reclaim all 773 frames.

## Scope and next stages

These are two non-overlapping opaque colored rectangles serving as
logical window-surface stand-ins, not a complete desktop compositor. No
z-order, occlusion, alpha blending, actual application surface buffers,
multi-threaded synchronization, page flipping, dynamic sizing, hotplug,
hardware GPU support or refresh-rate programming is established. Even
success in all QEMU gates is not evidence of an everyday-use OS.

Keep older QEMU flavors unchanged and require exact-head full P0 CI,
pixel corruption negative tests, Ring3/SMP regressions, first-failure
preservation and no unapproved merges.
