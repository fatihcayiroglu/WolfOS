# ADR-0075 — Real QEMU VirtIO-GPU scanout/capset readback

Status: **proposed**, stacked draft after ADR-0074 / PR #306.

## Why this is the next dependency

EDID transport, monitor auto-selection, per-monitor refresh rates and
reversible user override cannot safely operate without a real device
capability path. Reading the VirtIO 1.2 GPU-specific `virtio_gpu_config`
provides actual device-reported scanout and capability-set counts in QEMU,
while still deliberately not enabling an accelerated driver.

## Boundaries and design

- The existing strict capability parser must now expose the preferred
  GPU-specific type-4 vendor capability's BAR index, byte offset and length.
  Its independently validated minimum length is 16 bytes.
- This QEMU-only milestone **requires that device_config and common_config
  select the same BAR**. Reuse is safe only because the preceding test measured
  that BAR's aperture and restored its PCI COMMAND and BAR values exactly.
  A distinct BAR is rejected until independent sizing is implemented.
- Reuse the single-page, overflow-checked PCI memory-window contract with a
  separate minimum of 16 bytes. Reject cross-page and RAM/framebuffer overlap.
- On the single boot CPU before AP release, map the device config into a
  new virtual slot `0x0000_4000_0000_4000`. The one page is uncached and
  read-only to the CPU, not user-accessible. Flush and unmap regardless of
  register validation result.
- Perform only three **volatile 32-bit reads**, corresponding to
  `events_read` offset 0, `num_scanouts` offset 8, and `num_capsets`
  offset 12. Deliberately skip **`events_clear` offset 4**, which is
  write-one-to-clear.
- Validate the VirtIO-defined scanout range **1–16** and defined display
  event bit; do not invent an upper bound on the read-only `num_capsets`
  field. No queue setup, negotiation, EDID query, mode changes, interrupts,
  DMA, physical-GPU access, or persistent display setting.
- Require a new independent `--device` real-QEMU CI boot proving exact
  ordering: PCI caps, BAR restore, common MMIO unmap, device MMIO unmap,
  framebuffer, success. Earlier `--bars`, `--size` and `--mmio` flavors
  must reject any unexpected GPU-specific proof.

## Future work

Implement real PCI resources for different BARs, allocated queue transport,
`GET_DISPLAY_INFO` and `GET_EDID`, checked display mode preference,
atomic mode changes/rollback, UI override persistence and hotplug, with
real-hardware validation and no host-disk changes.

No integration into production `main` is authorized by this ADR.
