# ADR-0089: QEMU-only VirtIO-GPU screenshot pixel proof and safe scanout disable

Status: separate **draft** stacked on #320. Do not merge to `main`
without explicit approval. QEMU-only, single vCPU, no physical GPU.

## What is actually proven

PR #320 proved the real VirtIO-GPU 16KiB host-transfer acknowledgement.
This experiment verifies those pixels on the **QEMU host display surface**,
then explicitly disables scanout and confirms the transferred pattern
is no longer displayed. It does **not** restore the original guest
BIOS framebuffer geometry or image.

The [OASIS VirtIO 1.3 GPU specification](https://docs.oasis-open.org/virtio/virtio/v1.3/csd01/virtio-v1.3-csd01.html)
defines `SET_SCANOUT` (0x0103), `RESOURCE_FLUSH` (0x0104), and
SET_SCANOUT resource_id=0 to disable output. QEMU's
`virtio_gpu_disable_scanout()` disconnects the resource but does not
recreate the previous BIOS-created console surface or size.

On the first genuine QEMU test of this PR, **all 4096 active RGB pixels
matched**, but the baseline screenshot measured **1024x768**, while
the disabled screenshot measured **64x64**. The original
exact-baseline-rollback test correctly FAILED; preserving its run is
mandatory. It would be false to call the disable an exact geometry
restoration. This ADR explicitly narrows this milestone to
**real host pixel readback + verified scanout disable**. A later
independent PR must address exact original display geometry/state
restoration before any usable mode switching.

## Bounded QEMU-only sequence

After genuine GET_DISPLAY_INFO idx1 (scanout0 must be enabled), GET_EDID
idx2, CREATE idx3, ATTACH idx4, TRANSFER idx5:

1. Capture baseline QEMU PPM using a synchronous COM1/QMP handshake.
2. SET_SCANOUT resource1, rectangle (0,0,64,64), used idx **6**.
3. FLUSH resource1 full rectangle, used idx **7**.
4. Capture active QEMU PPM using a COM1/QMP handshake. Verify all
   **64x64=4096 RGB pixels** match the B8G8R8X8 backing bytes,
   not a synthetic fixture or checksum alone.
5. SET_SCANOUT resource_id=0, all-zero rectangle, used idx **8**.
6. Capture the **disabled** QEMU PPM. Require the 64x64 screenshot to
   be freshly generated and to differ from the active display:
   at most 8 of 4096 pixels may retain the precise transferred
   pattern. This guards against stale scanout but does **not**
   claim the BIOS 1024x768 screen returned.
7. DETACH idx **9** and UNREF idx **10**, both acknowledged, then
   reset status0/queue disabled, unmap and flush PCI MMIO and
   return all 9 exclusive PMM frames to the exact baseline.

All eight resource commands require distinct nonzero fences and exact
24-byte device `OK_NODATA` used-ring acknowledgements. No failing
command or timed-out host capture is treated as success. A reset
failure after exposure quarantines all nine physical pages. The
kernel stage markers cannot fake a host pixel comparison; only
Python's real QEMU QMP screenshot proof can pass that CI gate.

QEMU uses `-M q35 -smp 1 -vga none -device virtio-vga -display none`,
a private Unix COM1 socket for stage release, and a Unix
[QMP screendump](https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html)
socket. PPM files exist only in a fresh host CI temporary directory.
No guest disk, hardware GPU, system driver, or user-facing mode is used.

## Evidence and next safety gate

Keep the first failed exact-rollback CI run visible. Its 1024x768
vs 64x64 screen mismatch is a real QEMU behavior, not a random
flaky timeout. Run fresh CI on a separate corrective commit with
strict disable proof. The remaining work is **safe restoration of the
original display's geometry/content** (or refusal to change it),
not more speculative `SET_SCANOUT(0)` success claims.
