# ADR-0086: Genuine QEMU VirtIO-GPU 2D resource create and unref

Status: QEMU-only experimental stacked draft on #317. Do not merge `main`
without explicit approval.

## First safe 2D resource lifecycle

WolfOS already has proven real VirtIO-GPU PCI capabilities, bounded MMIO
mappings, feature negotiation, a split control queue and genuine sequential
GET_DISPLAY_INFO/GET_EDID completions. This change exercises only the next
host-resource lifecycle step. It does **not** change the visible display.

The normative VirtIO GPU device specification defines:

- `VIRTIO_GPU_CMD_RESOURCE_CREATE_2D = 0x0101`, a 40-byte request with
  resource ID, format, width and height, returning `OK_NODATA = 0x1100`.
- `VIRTIO_GPU_CMD_RESOURCE_UNREF = 0x0102`, a 32-byte request that destroys
  the resource, also returning `OK_NODATA`.
- `VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM = 2`.

References: [OASIS VirtIO 1.3 GPU device](https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html)
and [Linux VirtIO-GPU UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/virtio_gpu.h).

Use a single guest-generated resource ID **1**, format **2**, width **64**
and height **64** (a bounded 16KiB pixel extent). No guest framebuffer or
backing RAM is attached and no scanout changes are requested. The resource
may consume QEMU host memory temporarily; an acknowledged `UNREF` must
complete before success is reported.

## Four sequential actual DMA completions

Keep the existing five uniquely owned PMM frames: descriptor, avail,
used, request and writable response. Retain all prior PCI aperture, queue,
status and response-fence checks. After genuine GET_EDID used idx 2:

1. Zero the old 1056B EDID response and the 40B request space. Encode
   CREATE_2D with a new nonzero fence. Reuse exactly two descriptors,
   publish the next available head and notify queue0 once.
2. Require exact used idx **3**, id **0**, used bytes **24**, actual response
   type `OK_NODATA`, flags=FENCE, exact echoed fence and zero reserved fields.
3. Only after the acknowledged CREATE, zero/reuse the same bounded DMA
   frames for UNREF with a distinct nonzero fence. Publish avail idx **4**
   and notify queue0 once more.
4. Require exact used idx **4**, head **0**, length **24**, `OK_NODATA`,
   echoed UNREF fence and zero reserved fields.

The ring positions derive from `(next_idx-1) % queue_size`; this is
necessary when a valid device selects a two-entry queue. The code polls
with a bounded loop and rejects timeouts, wrong completions, stale responses,
device errors and missing cleanup. It does not retry or turn failures green.

After both QEMU responses, unconditionally reset status=0, confirm
queue_enable=0, unmap and flush both PCI MMIO pages and verify all five
PMM frames were freed against their baseline. If reset cannot be
confirmed after DMA exposure, quarantine the five frames until QEMU exits.
If CREATE succeeded but UNREF failed, report failure even if subsequent
device reset succeeds; do not pretend explicit host-resource destruction
was observed.

## Evidence and exclusions

A mandatory new QEMU CI step uses only `-M q35 -smp 1 -vga none
-device virtio-vga -display none` and no physical disks. Its exact serial
proof requires four real used-ring completions, two independent
fenced `OK_NODATA` responses, four total notifications, explicit UNREF,
reset-before-free and unchanged PMM accounting. Pure Rust wire/queue tests
and Python marker-mutation tests run in the same step.

No `RESOURCE_ATTACH_BACKING`, `SET_SCANOUT`, `RESOURCE_FLUSH`,
`TRANSFER_TO_HOST_2D`, physical GPU accesses, refresh-rate changes,
new display driver or user UI are included. The next phase must separately
prove backing ownership, scanout application, real readback and rollback.
