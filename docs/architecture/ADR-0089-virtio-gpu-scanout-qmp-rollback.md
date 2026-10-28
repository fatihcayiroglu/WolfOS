# ADR-0089: QEMU-only VirtIO-GPU scanout, host pixel proof, rollback

Status: separate **draft** stacked on PR #320. This is not a general
hardware driver and must not be merged into `main` without approval.

## Exact reversible controlq transaction

Prior #320 established real 64x64 B8G8R8X8 pixels copied from four
exclusively PMM-owned 4KiB guest pages into a QEMU VirtIO-GPU 2D resource.
This change adds visible output in **QEMU only**. `-M q35 -smp 1 -vga none
-device virtio-vga -display none` prevents host physical GPU interaction.
No guest physical disk or GPU firmware is written.

Per [OASIS VirtIO 1.3 GPU](https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html),
SET_SCANOUT (0x0103) is a 48-byte header+rect+scanout/resource request,
RESOURCE_FLUSH (0x0104) a 48-byte header+rect+resource/padding request;
`SET_SCANOUT` resource_id=0 disables the selected output. Only scanout
index 0 and a rect fully covering exactly x0,y0,w64,h64 are permitted.
The display-info proof must report scanout0 enabled, and every operation
requires a strict, independent echoed fence and 24-byte OK_NODATA reply.

After the already-proven GET_DISPLAY_INFO idx1, GET_EDID idx2,
CREATE idx3, ATTACH idx4 and TRANSFER idx5:

1. Halt guest progress at COM1 stage **baseline** until the QMP host has
   captured a fresh PPM for the untouched scanout.
2. SET_SCANOUT resource_id1 with 64x64 full rect, require used idx **6**.
3. RESOURCE_FLUSH resource_id1, require used idx **7**.
4. Halt at COM1 stage **active**. QMP `screendump` writes a temporary
   PPM in the CI job's private temporary directory; the host checks all
   64x64 pixels' RGB channels against guest B8G8R8X8 pixel bytes.
5. SET_SCANOUT resource_id0 with zero rectangle, require used idx **8**.
6. Halt at COM1 stage **restored**. Require exact screenshot byte and
   geometry equality with the baseline screenshot. Only then release
   the guest from the host screenshot handshake.
7. DETACH_BACKING idx **9**, then UNREF idx **10**, and require both
   independent fenced OK_NODATA acknowledgements. Reset status0,
   verify queue disabled, unmap+flush all PCI MMIO pages and return
   all nine owned PMM frames to exact PMM accounting baseline.

All **eight** fenced resource commands use pairwise distinct nonzero
fences; no out-of-range commands, unbounded waits, optimistic reset or
device error can pass. If the host does not capture and return its exact
single-byte stage token, a bounded guest wait fails closed. If an external
screenshot fails or pixel/rollback equality is not shown, CI fails and
the isolated QEMU process is stopped; no kernel success is claimed.

## Independent evidence and limitations

Use the official [QEMU QMP screendump command](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html)
with a Unix QMP control socket. A separate Unix COM1 socket keeps
the guest parked at precise capture boundaries, so the host does not
guess timing or reuse a mock screenshot. The active PPM must contain
the exact 4096 expected RGB pixels, not merely a matching checksum or
plausible response. The restored PPM must equal the actual baseline
pixel data and geometry, irrespective of what the initial BIOS display
was. Python adversarial tests mutate both the serial marker and the
host image; host-only fixtures never replace the real QEMU boot.

The kernel truthfully emits only **capture_acks=3** and
**host_pixels_verified_by_kernel=0**; the QMP *host test* is the
authority for pixel and rollback proof.

This is not general-purpose mode selection, accelerated rendering,
real hardware support or Windows application compatibility. A
subsequent independent milestone must extend beyond this one
QEMU-specific, 64x64, single-scanout, single-vCPU transaction.
