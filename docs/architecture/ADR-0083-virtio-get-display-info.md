# ADR-0083: First real QEMU VirtIO-GPU GET_DISPLAY_INFO request

Status: Experimental, opt-in QEMU-only; stacked on #314.

## Scope and wire contract

Test runs only with `qemu-system-x86_64 -M q35 -smp 1 -vga none
-device virtio-vga`, inside the existing x86-64 Limine boot smoke
suite. It never targets physical GPUs or real disks.

After #302–#314 established PCI capability validity, preferred notify
address, VirtIO VERSION_1 handshake, one-page split-ring queue sizing,
and actual controlq0 reset-before-free, this test provisions **five**
distinct PMM-owned guest RAM pages: descriptor table, available ring,
used ring, 24-byte request, 408-byte writable response. Every page is
zeroed and fully read back prior to device exposure.

Use only two 16-byte split descriptors: device-readable request (NEXT=1)
and device-writable response (WRITE=2). Request header is the bare,
zero-padded VirtIO GPU control header with type 0x0100
(`VIRTIO_GPU_CMD_GET_DISPLAY_INFO`). The response format is
`virtio_gpu_resp_display_info`, a 24-byte header and up to sixteen
24-byte scanout entries, type 0x1101
(`VIRTIO_GPU_RESP_OK_DISPLAY_INFO`).

`VIRTIO_F_VERSION_1` is the sole negotiated feature; no packed ring,
EVENT_IDX, notification data, indirect descriptors, 3D features, or
driver binding. Control queue0 size and physical addresses are written
and verified after status 1→3→11, then queue enabled and DRIVER_OK
(status15) set. Publish exactly **one** available ring head (index0,
free-running idx1), notify the proven preferred PCI notification port
exactly once with u16 queue index0, and wait a bounded interval for
used ring idx1. Require used id0, length408 and response type0x1101,
then check bounded scanout dimensions. A headless disabled scanout
is valid evidence of a *reply*, not evidence of a connected display.

No GPU resources are created, attached, or set as a scanout. No
resolution or refresh-rate changes occur.

## Ownership and failure behavior

A full device_status0 reset is **unconditional** after initiating the
feature handshake, whether the response succeeds or fails. Require
both status0 and queue_enable0 within a bounded wait. Guest RAM pages
are released only after the device reset is proven, with PMM frame
statistics returning to baseline and temporary supervisor-only,
uncached common and notify MMIO mappings removed and TLB flushed. If any queue address
was exposed but reset is unconfirmed, quarantine all five pages until
QEMU teardown and fail. No retries or green without genuine QEMU
completion and strict serial proof.

## Next step

Extend this minimal QEMU-only query into a persisted, isolated graphics
driver state machine with bounded queue lifetime, multi-scanout
change events, EDID reads and explicit user-adjustable preferred display
mode. Do not infer refresh rate from GET_DISPLAY_INFO alone; use EDID
timing descriptors or suitable display capabilities. Physical GPU
support and game acceleration are much later milestones.
