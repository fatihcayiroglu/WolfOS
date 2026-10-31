# ADR-0099 — Two independent QEMU dirty rectangles

Status: proposed; experimental QEMU-only test stacked after ADR-0098.

## Goal

WolfOS must not upload one giant bounding rectangle every time two distant
surfaces are dirty. The earlier ADR-0098 proved a single 32x32 changed area
and exact full-screen host pixel equality.

This milestone uses one attached 1024x768 VirtIO-GPU resource with two
disjoint rectangles: (11,19,16,16) and (811,401,32,16).
Their 256+512=768 changed pixels must be independently transferred and
flushed, using exact full-resource stride, four distinct wire-completed
fenced requests (transfer/flush per rectangle), **without** sending a
bounding-region transfer or any intermediate SET_SCANOUT/RESET.
The QMP host judges every RGB pixel: 768 changed, 785664 unchanged.

The same two rectangles are restored via four *new* independently fenced
commands; another QMP host screenshot must match the original 1024x768
pixel-by-pixel. The guest must recover the exact original backing digest
before its previous desktop resolution change/15-second rollback tests.

## Memory safety and queue policy

The bounded Rust DamageQueue holds up to N distinct disjoint rectangles
without heap allocation. Overlap, duplicates, an oversized queue, and
new marks during an unresolved DMA request fail closed. A rectangle stays
in the queue until both its transfer and flush acknowledge their own
verified used-ring index, head, length, response type and fence. No
PMM-owned memory is released until the final GPU device reset confirms the
queue disabled; 773 frames must be reclaimed with no leaks.

This is intentionally a separate Cargo feature and QEMU acceptance gate:
normal boots, PR #326's existing damage tests and old scanout tests keep
their on-wire behavior.

## Limitations

This proof is *not* an installed compositor, an arbitrary surface tree,
a thread-safe dirty queue, multi-monitor support, page flip, real GPU
vendor driver or timing/refresh programming. It does not guarantee
performance advantage in every workload; for adjacent rectangles a union
may be more efficient, but that policy is outside this controlled proof.
No physical GPU access, no disk writes, and no PR is merged without owner
approval. First failures are preserved; full exact-head CI and real QMP
screenshots are mandatory.
