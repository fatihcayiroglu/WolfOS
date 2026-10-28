# ADR-0084: Real QEMU VirtIO-GPU GET_EDID after display-info

Status: Experimental opt-in QEMU-only, draft stacked on #315. Does not authorize production merge.

## Goal and scope

A stable consumer default must choose a native monitor resolution and an
honest refresh rate. GET_DISPLAY_INFO (ADR-0083) supplies scanout geometry,
not refresh. WolfOS already has strict checksum-validated EDID base + CTA
parsers and an independently tested display-mode policy with automatic/manual
resolution and refresh selection. This ADR connects the existing real
VirtIO-GPU queue to those parsers, without claiming hardware modesetting.

The opt-in `qemu-virtio-gpu-edid-live-smoke` uses only QEMU q35, one vCPU,
`-vga none -device virtio-vga -display none`. It never accesses a physical
GPU or any host disk.

## One bounded pair of real DMA commands

After all earlier PCI capabilities and GPU-specific configuration have been
read and validated, negotiate VIRTIO_F_VERSION_1 **and** the actually
advertised VIRTIO_GPU_F_EDID (bit 1). Reject unsupported feature negotiations.

First send exactly one GET_DISPLAY_INFO (request 24B, response 408B).
Validate used index1, used id0, used bytes408 and OK_DISPLAY_INFO.

Without allowing GPU reuse of unowned RAM, scrub the same exclusively owned
response frame, encode the existing 32-byte GET_EDID request for proved
scanout0 with nonzero fence, and switch the two descriptor lengths. Publish
avail head0 in slot1, advance available index to2, write the bounded queue
notify register exactly once more and await a bounded second used entry.
Require used index2, id0, bytes1056 and an exactly echoed response fence.
The full EDID response must pass strict length, header, version, checksums,
extension parsing and nonzero timed modes. Some QEMU guests advertise a
1024-byte response array while the EDID base declares fewer actual 128-byte
blocks; parse only those declared blocks, and accept surplus bytes **only**
when every byte is zero. Hidden nonzero trailing data and incomplete
declared extensions are rejected. Record the EDID-preferred mode's
pixel-timing-derived refresh in **millihertz**. Neither a guessed 60 Hz
fallback nor an unverified monitor mode is accepted as EDID evidence.

Regardless of response, perform a full status0 device reset and confirm
queue_enable0 before releasing the five physical DMA frames. Unmap and TLB
flush both independently validated common and notification PCI MMIO pages.
If reset is uncertain, quarantine frames until QEMU teardown and fail.

## Evidence and release policy

The QEMU test requires the unchanged #315 genuine response marker, the
second live EDID marker and both final kernel acknowledgements. Pure Rust
second-used-ring tests and Python negative marker mutations run before
QEMU. All tests run with first-failure-only, no retries and zero fake-green.

This does **not** select or apply a live graphics mode. Automatic/user
overrides still require a real connector generation, GPU bandwidth limits,
safe modeset/observed readback, 15-second confirmation rollback, and
hotplug handling. Physical GPU drivers remain outside this experiment.
