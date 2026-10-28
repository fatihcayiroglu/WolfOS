# ADR-0082: QEMU-only VirtIO-GPU queue0 notification address proof

Status: Experimental, draft follow-up to #313. Not a display driver.

## Motivation

VirtIO 1.2 PCI modern devices put the queue notification address at
`notify capability offset + queue_notify_off * notify_off_multiplier`,
**not** at a hard-coded BAR address. The `queue_notify_off` value is
device-specific per virtqueue and must be read from the common PCI
configuration. Before any `GET_DISPLAY_INFO` command can be submitted,
the original Rust driver must prove this pointer points to the correct
measured and non-RAM PCI memory aperture.

## QEMU-only evidence

- Preserve the preferred notify capability's `BAR`, `offset`, `length`,
  and `notify_off_multiplier` from the already validated PCI config
  chain. Do not invent a fixed QEMU offset.
- **Fail closed** if notify uses a separately sized BAR. This phase
  supports only the same BAR independently measured for common_cfg;
  a separate BAR will require its own reversible sizing evidence.
- After the existing actual QEMU controlq0 enable/reset-before-free
  #313 test, map the validated common_cfg page supervisor-only and
  read-only. Inspect queue0 selector/status/enabled/size and
  queue_notify_off through bounded volatile reads. Unmap and flush.
- Calculate notification register's *physical address* with overflow,
  alignment, notify-capacity, and exact BAR bounds checks.
- Refuse overlap with RAM or framebuffer memmap entries. Reject
  multiplier 0/unsupported formats in this first QEMU-only step.
- Emit one strictly parsed proof marker and enforce explicit
  negative-path unit tests and real `-device virtio-vga` CI.

The notification MMIO register is **write-only** and is never read.
Nothing is notified and no DMA descriptors or GPU commands run.
The test does not set `DRIVER_OK`, change screen resolution, or
change the currently running display backend.

## Next proof

Only after a green exact-head run: build a bounded 24-byte
`VIRTIO_GPU_CMD_GET_DISPLAY_INFO` request and 408-byte writable response
buffer (16 scanouts, no user-supplied address), install two valid split-ring
descriptors, submit exactly one head, explicitly signal the proven
notification register, and require a bounded used-ring completion and a
type-correct `VIRTIO_GPU_RESP_OK_DISPLAY_INFO` before a mandatory device
reset and PMM frame release. Fail closed/quarantine frames if resetting
fails. Keep this exclusively in QEMU until broader GPU device isolation
and driver lifecycle safety exist.
