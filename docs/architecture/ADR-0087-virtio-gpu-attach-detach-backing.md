# ADR-0087: QEMU-only VirtIO-GPU four-page backing lifecycle

Status: experimental stacked draft on #318, **no merge to main** without
explicit approval. No physical GPU, display mode or disk operations.

## Contract and guest memory ownership

The prior #318 smoke proved real GET_DISPLAY_INFO, GET_EDID, RESOURCE_CREATE_2D
and RESOURCE_UNREF on QEMU virtio-vga with a five-PMM-frame split controlq.
This new isolated feature retains that path in the old five-frame build
unchanged. Only `qemu-virtio-gpu-attach-backing-smoke` allocates **nine**
exclusive PMM 4KiB frames: descriptors, available ring, used ring, command,
response, and **four additional guest memory backing pages**.

The resource is 64×64 pixels at four bytes per pixel: **16,384 bytes**.
Each of the four backing pages is a PMM-allocated, nonzero, aligned, distinct,
zero-verified 4KiB physical frame, not an alias of a queue or request page.
All pages remain owned/pinned through detach, unref and full device reset.

Normative VirtIO 1.3 section 5.7 GPU control commands:
[OASIS](https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html).
Linux/QEMU wire reference:
[Linux UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/virtio_gpu.h).

- `RESOURCE_CREATE_2D` (0x0101): 40-byte create, independently fenced.
- `RESOURCE_ATTACH_BACKING` (0x0106): exactly 96 bytes (24B control
  header, 4B resource ID, 4B entry count, then four 16B memory entries).
  Each entry is guest physical u64, length=4096 u32, padding=0.
- `RESOURCE_DETACH_BACKING` (0x0107): exact 32-byte request, explicit ack.
- `RESOURCE_UNREF` (0x0102): exact 32-byte final resource destruction.

All four require a separate, nonzero, pairwise distinct command fence.
A request submission, timeout, plausible 24-byte buffer or reset alone
does **not** count as success: for each transaction require exact used-ring
index **3, 4, 5, 6** respectively, head=0, length=24, response
`OK_NODATA` 0x1100, fence flag=1, echoed fence, zero context/reserved.
For a selected two-entry virtqueue, the available/used slots wrap 0/1.

The original GET_DISPLAY_INFO and GET_EDID commands must complete before
CREATE; CREATE must be acknowledged before ATTACH, ATTACH before DETACH,
and DETACH before UNREF. Only then can success be recorded. The GPU is
unconditionally reset before any of the nine frames can be freed; the
queue must read back disabled, PCI pages must be unmapped/flushed, and
allocated/free frame accounting must return to baseline. An uncertain reset
quarantines all exposed memory. Failed ATTACH/DETACH/UNREF responses are not
converted to success by a later reset. No retries hide failures.

## Verification and explicit exclusions

One new **mandatory real QEMU** CI step runs a single-vCPU q35 guest with
`-vga none -device virtio-vga -display none`. It first runs independent
offline Rust wire/ownership tests and Python marker-mutation tests.
Then it boots the actual ISO and requires six real controlq completions,
four fenced resource replies and nine allocated/released PMM frames.
The predecessor five-frame smoke still runs separately with its original
strict markers. The new proof uses an explicit nine-frame marker to avoid
claiming a five-frame result.

Backing is attached only to make guest memory available for *future*
transfer. This step does **not** issue TRANSFER_TO_HOST_2D, FLUSH,
SET_SCANOUT, modeset, framebuffer/readback, GPU rendering or user UI.
Host memory contents are zeroed, not transferred or displayed. A later
separate QEMU-only gate must prove bounded pixel transfer/scanout and
reversible cleanup before attempting visible graphics.
