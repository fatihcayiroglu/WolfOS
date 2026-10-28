# ADR-0081: QEMU-only VirtIO controlq0 registration and proven reset

Status: Experimental. Draft stacked on ADR-0080 / PR #312, not production GPU support.

## Scope

The single-vCPU `virtio-vga` QEMU smoke flavor, with the PCI vendor/device,
BAR bounds, read-only MMIO capability, offered `VIRTIO_F_VERSION_1`, queue0
capacity, and three-page PMM ownership already proven in #302–#312.

The test allocates three disjoint, real, 4 KiB physical PMM frames for one
split VirtIO 1.2 control queue (`descriptor`, `avail`, `used`). Each frame
is zeroed and the entire 4 KiB is read back before exposing its physical
address. A supervisor-only, uncached, non-RAM BAR mapping is temporarily
made writable. The test negotiates only VERSION_1; it never sets DRIVER_OK,
sends a notification, submits a descriptor or sends a GPU protocol command.

The test writes the three queue0 physical addresses as 32-bit LE halves,
the bounded queue size, and queue_enable=1, and demands MMIO readback. It
then performs a full `device_status=0` reset with bounded polling and
requires BOTH `device_status=0` and `queue_enable=0`, before PMM frames
may be released. The MMIO mapping is removed and TLB flush is required.

## Failure rules

If any physical queue address was exposed and a full reset cannot be
proven, the frames remain **quarantined**, intentionally allocated until
QEMU teardown; the test fails. A stale, nonzero physical address register
after reset is **not** a failure: VirtIO requires a reset queue to be
disabled, but does not promise zero address-register readback.

Unexpected device status, readback, layout, mapping, PMM ownership or
release produces explicit FAIL markers, never a synthetic green. Exact
serial markers, independent host contract tests and the real QEMU run
are all mandatory. Preceding flavors retain their read-only and
no-queue behavior.

## Safety / limitations

Only the explicit QEMU `-device virtio-vga -vga none` smoke configuration
may run this experiment; **never bind a physical GPU or access real disks**.
`DRIVER_OK` is never set, hence the device may not consume queue buffers;
there is no command submission, screen mode setting, rendering, or
Windows game acceleration. This evidence does not establish physical
hardware compatibility or readiness to merge into production `main`.

## Next proof boundary

Construct one valid fenced GPU controlq descriptor and a bounded
`GET_DISPLAY_INFO` response buffer in the QEMU-only flavor, then add
queue notification and a verified used-ring completion only after
driver-lifecycle design and cancellation have been independently audited.
