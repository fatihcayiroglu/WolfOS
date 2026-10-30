# ADR-0094: Real 1024×768 desktop framebuffer as a native scanout resource

- **Status:** Accepted
- **Supersedes:** nothing
- **Related:** ADR-0092 (verified display-mode catalog), ADR-0093 (host pixel
  attestation channel)
- **Flavor:** `qemu-virtio-gpu-desktop-scanout-smoke`
- **Scope:** QEMU `virtio-vga` only. No physical GPU, no register programming.

## Context

ADR-0092/0093 produced an evidence-graded mode catalog and a nonce-bound host
pixel attestation channel, but every *selectable* geometry was a 64×64 or 32×32
synthetic tile. Proven display geometries therefore could not describe a
desktop at all, and none of the transfer path had ever run at production size:
4 KiB of backing store versus the 3 MiB a real 1024×768 frame needs.

The open questions were concrete:

1. Can the driver present the *actual* bootloader framebuffer (real pitch, real
   VRAM content, real geometry) instead of a synthetic pattern?
2. Can a 3 MiB resource be attached when `ATTACH_BACKING` must carry every
   scatter-gather entry inside a single page-sized control request?
3. Does the transfer path still complete, fenced, band after band, when the
   resource is 768 pages instead of 4?
4. Can the host prove all 786,432 pixels, rather than 4,096?

## Decision

1. **Present the bootloader framebuffer, not a tile.** The driver validates the
   Limine framebuffer (`address != 0`, 4-aligned, 32 bpp, exactly 1024×768,
   `pitch >= 4096`, channel shifts exactly R=16/G=8/B=0) and refuses anything
   else (`UnsupportedFramebuffer`). There is no resampling, no "close enough"
   geometry and no guessed channel order.

2. **Paint, then copy from VRAM.** The driver paints a deterministic desktop
   image through the real framebuffer pointer, then copies each row from VRAM
   into the backing pages. The digest the host must answer is computed over the
   *copied backing bytes*, i.e. exactly what the device will read, and is
   additionally compared against the intended image so a corrupted copy fails
   as `framebuffer_copy_mismatch` instead of silently matching itself.

3. **Merge physically sequential pages into scatter-gather runs.** One resource
   row is exactly 4096 bytes, so backing page *y* holds row *y*. The driver
   sorts by pixel order and merges only runs whose physical address continues
   (`start + len == next`). Runs are limited to 254 entries, the most that fits
   in the 4096-byte control request (`32 + 254*16`). More fragmentation is
   refused as `TooManyRuns` rather than split across several `ATTACH_BACKING`
   commands, which QEMU does not support.

4. **Band the transfer.** Twelve fenced `TRANSFER_TO_HOST_2D` requests of 64
   rows (offset `y*4096`) cover the resource exactly once; the plan is unit
   tested to have no gap, no overlap and no out-of-bounds rectangle.

5. **Keep the host as the only pixel authority.** The guest prints a
   stage-unique nonce plus its own digest; the host captures a real QMP
   screenshot, verifies every pixel against the known image and answers with a
   digest computed from that screenshot. No reply, a replayed nonce, a resized
   scanout or a differing digest fails closed.

6. **Prove the teardown too.** After `SET_SCANOUT(resource 0)`, `DETACH_BACKING`
   and `UNREF`, the device is reset, and only then are the 773 frames freed.
   The host then re-captures the VGA output and requires every framebuffer
   pixel again: the full GPU resource lifecycle must not damage VRAM.

## Evidence (real QEMU, headless)

- All **786,432** pixels of a genuine 1024×768 QMP screenshot match the
  expected image.
- Host digest `0b6b1dc5` equals the guest's framebuffer digest, nonce
  `574f4445534b0004`.
- 768 backing pages were merged into **2 runs** (one `ATTACH_BACKING` request),
  with 12 band transfers and **19 fenced completions** (`used_idx=21`).
- After teardown and reset the VGA output shows **every** framebuffer pixel
  again.
- Forged host replies are refused with distinct reasons: `digest_mismatch`,
  `bad_nonce`, `wrong_geometry`.

## Consequences

Positive:

- The first real desktop geometry the driver can present, with host-owned pixel
  evidence for all 786,432 pixels.
- Pitch, channel order, fragmention and request-size limits are now exercised
  at production size instead of at 4 KiB.
- The scatter-graph merging, band plan and pixel arithmetic are pure,
  `rustc --test`-able functions (`virtio_gpu_desktop_wire`), so the safety
  boundary is testable without a device.

Negative / still missing:

- The presented image is a deterministic test image painted into the
  framebuffer, not the composited desktop: there is no window manager, no
  compositor and no damage tracking yet.
- Only 1024×768 xRGB8888 is supported, and only on `virtio-vga`.
- No refresh rate, pixel clock or mode programming: the catalog still records
  refresh as unavailable, and this geometry is not yet fed into the mode
  catalog.
- No multi-monitor, hotplug, page-flip or double buffering; the transfer is
  synchronous and blocking.
- Fragmented PMM allocation beyond 254 runs fails closed rather than falling
  back to a chained request.

## Next steps

1. Feed the host-verified 1024×768 scanout into the display-mode catalog as the
   first attested desktop geometry, so automatic selection prefers it over the
   probe tiles.
2. Replace the painted test image with real console/compositor output and add
   damage-tracked partial flushes (`RESOURCE_FLUSH` per rectangle).
3. Grow the wire contract toward arbitrary pitches, 16/24 bpp framebuffers and
   a second scanout.
