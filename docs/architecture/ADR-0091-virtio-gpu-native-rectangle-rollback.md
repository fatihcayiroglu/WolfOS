# ADR-0091: Native VirtIO-GPU rectangle rollback without device reset

Status: separate **draft PR #323** stacked on #322; no automatic merge.
QEMU-only proof for a single `virtio-vga`, **not** a production GPU driver.

## Purpose and bounded scope

PR #321 proved 4096 host pixels and explicit scanout disable. PR #322
proved full VGA compatibility restoration **after device reset**. This
follow-up tests a narrower but important property: a native VirtIO
scanout can change its displayed rectangle and recover the original
native frame **without resetting the device in between**.

The [OASIS VirtIO-GPU specification](https://github.com/oasis-tcs/virtio-spec/blob/master/device-types/gpu/description.tex)
defines a scanout as a rectangle completely covered by an existing
resource, with SET_SCANOUT switching the rectangle and RESOURCE_FLUSH
updating it. This demonstration uses one exclusively owned, already
transferred 64×64 B8G8R8X8 resource and only two allowed rectangles:
(0,0,64,64) and (0,0,32,32). No new backing, DMA remapping, or guest
physical allocations occur during the native mode transition.

## Six independent QEMU screenshots

- `baseline`: initial legacy VGA image before native scanout.
- `active`: 64×64 native screenshot; verify **all 4096 RGB pixels**.
- `reduced`: after fenced SET_SCANOUT 32×32 and FLUSH 32×32, QMP
  screenshot must be exactly 32×32 and each of its **1024 pixels**
  must match the corresponding top-left original resource pixels.
- `reexpanded`: after a second fenced SET_SCANOUT 64×64 and FLUSH,
  **before device reset**, QMP screenshot must be exactly byte-equal
  to the original `active` screenshot (all 4096 RGB pixels).
- `disabled`: explicit SET_SCANOUT(resource_id=0); native pattern
  disappears. This does **not** restore VGA mode.
- `restored`: after acknowledged DETACH+UNREF and the eventual full
  status=0 / queue-disabled reset, require exact `baseline` geometry
  and **every original VGA RGB pixel** to match.

All **14** genuine queue completions are required (GET_DISPLAY and
GET_EDID plus 12 distinct-fence resource operations), including
two native rectangle changes and both native flushes. All four
intermediate native transitions are completed and host-captured while
the VirtIO device remains active; no reset is performed until the
native rollback is independently verified. Nine exclusively allocated
PMM pages are freed **only after reset and QMP acknowledgment**.

The CI gate boots fresh headless QEMU; Python adversarial tests reject
missing/duplicated/misordered stage markers, stale frames, altered
single pixel, unexpected geometry, missing fences, and wrong reset
or cleanup counters. Synthetic fixtures never count as QEMU evidence.

## Limitations

This proves only 64×64→32×32→64×64 rectangular scanout switching on
the QEMU-emulated device and exact native-pixel rollback. It does not
prove arbitrary monitor timing, refresh-rate control, automatic EDID
mode choice, multi-monitor layouts, real hardware drivers, or general
user-requested resolution changes. For those claims the software must
have further mode capability and physical/device safety evidence.
