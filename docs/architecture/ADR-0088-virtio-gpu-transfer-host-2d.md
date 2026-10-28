# ADR-0088: Real QEMU VirtIO-GPU 16KiB transfer-to-host acknowledgement

Status: isolated **draft** stacked on PR #319; no merge to `main` without
explicit approval. Strictly QEMU-only (q35, one vCPU, virtio-vga, no display).

## Goal and limits

PR #319 established a genuine nine-frame VirtIO-GPU guest backing lifecycle:
five PMM-owned controlq/request/response pages plus four distinct, zeroed
4KiB backing pages (64x64x4 = 16,384 bytes), including real
CREATE_2D, ATTACH_BACKING, DETACH_BACKING and UNREF acknowledgements.

This PR adds exactly one independently acknowledged 2D host transfer while
the four backing pages are still attached. No physical GPU or disk use.
No scanout, RESOURCE_FLUSH, visible pixels, modeset or actual host-image
readback is attempted. **An OK_NODATA response proves device acceptance,
not pixel correctness, host memory contents or screen display.**

The normative [VirtIO 1.3 GPU device specification](https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html)
and [Linux GPU UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/virtio_gpu.h)
define `VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D = 0x0105`,
request `struct virtio_gpu_transfer_to_host_2d`:

- 24B control header (FENCE flag, unique nonzero u64 fence, zero context).
- Rect at bytes 24-39: x=0, y=0, width=64, height=64.
- LE64 offset=0 at bytes 40-47.
- LE32 resource_id=1 at bytes 48-51 and zero padding 52-55.
- Exactly **56 request bytes** and fenced `OK_NODATA` 24B reply.

No offsets or rectangles outside this single full-resource bound are allowed.
Before attachment the four pages are painted with a deterministic,
nonzero, page-distinct 16KiB pattern, checked by volatile reads. Guest
pattern integrity is rechecked after the acknowledged transfer; this
guards against the device writing to source pages, but is NOT host readback.

## Real QEMU command ordering and ownership

The existing GET_DISPLAY_INFO and GET_EDID responses remain mandatory
(used indices 1 and 2). Then enforce on the same two-descriptor controlq:

1. CREATE_2D acknowledged used index **3** and its fence.
2. ATTACH_BACKING of four PMM physical pages acknowledged index **4**.
3. TRANSFER_TO_HOST_2D of precisely 16,384 bytes acknowledged index **5**,
   distinct fence, exact response header/length/head and device OK_NODATA.
4. DETACH_BACKING acknowledged index **6** and its independent fence.
5. UNREF acknowledged index **7** and its independent fence.

All five fences are pairwise distinct and nonzero. Split-ring slots
wrap according to the queue-selected power-of-two size, including a
two-entry queue. The command/response pages are zeroed and reused only
after prior used-ring acknowledgement. All waits are finite, no retry
turns a failure green, and wrong response, fence, used index or missing
cleanup fails closed. Until full GPU status=0 and queue_disabled=1 are
confirmed, *all nine* PMM frames are quarantined from reuse. After reset,
PCI MMIO mappings are unmapped/flushed and all nine frames return to
the original PMM allocation baseline.

## CI and next independent stage

A new mandatory QEMU smoke step compiles the kernel ISO with a dedicated
feature, runs host Rust 56-byte wire/extent/unique-fence/pattern tests,
runs Python adversarial serial marker tests, then actually boots QEMU.
The exact serial success marker requires seven notifications, five
fenced resource replies, host-transfer acknowledgement, pattern
integrity before/after, zero scanout writes and full nine-frame cleanup.
The predecessor five-page and nine-page tests continue unchanged in
their separate feature builds.

Next phase (separate review/test) must provide a real observable QEMU
pixel readback or reversible scanout/flush path, preserve prior
display state and prove rollback before claiming visible graphics.
