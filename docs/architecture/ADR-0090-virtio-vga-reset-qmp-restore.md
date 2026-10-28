# ADR-0090: QEMU VirtIO-VGA compatibility reset and exact host screenshot comparison

Status: **draft**, stacked on PR #321; do not merge without approval.
Scope: a **separate opt-in QEMU-only smoke**, not a production display manager.

## Rationale

[OASIS VirtIO-GPU VGA compatibility](https://github.com/oasis-tcs/virtio-spec/blob/master/device-types/gpu/description.tex)
states that `SET_SCANOUT` changes VGA-compatibility mode into native
VirtIO mode, while a **device reset** switches it back. PR #321 already
proved the important limitation: `SET_SCANOUT(resource_id=0)` makes the
64x64 host pattern disappear, but its QMP screenshot stays 64x64; the
original 1024x768 console is **not** restored at that stage.

This isolated experiment tests the **later reset transition** with an
additional host QMP screenshot rather than trusting the reset status
bit or the kernel's success marker alone.

## Mandatory four-stage proof

1. On one **QEMU `virtio-vga`** device, capture the current display
   through a COM1-coordinated QMP PPM screenshot (`baseline`).
2. Run the previously verified real CREATE, ATTACH, TRANSFER, SET_SCANOUT,
   FLUSH transactions; capture and independently validate all
   **4,096 transferred host RGB pixels** (`active`).
3. Explicitly disable the scanout with `SET_SCANOUT(resource_id=0)`;
   capture `disabled` and prove the pattern is gone. This stage is
   **not** treated as a rollback.
4. After acknowledged DETACH and UNREF, write VirtIO status zero, require
   status zero and queue disabled, then capture `restored` while nine
   PMM-owned frames are still pinned. The host must compare **the entire
   `restored` RGB image and dimensions, byte for byte**, to
   `baseline`. A single wrong pixel or changed geometry fails CI.
   Only then may the kernel unmap MMIO and release all nine PMM pages
   under the existing reset-before-free contract.

Three and four-stage tests are separate feature-gated QEMU boot paths.
The previous #321 gate keeps its original three-stage semantics.
Independent Python tests mutate each stage/ACK, dimensions, and a
single restored pixel. The mandatory new CI step boots a fresh QEMU
guest and performs four genuine host-side `screendump` operations.
No mocked QMP success substitutes for the actual screen proof.

Limits: one emulated legacy-compatible VirtIO VGA controller, one
scanout, 64x64 temporary native graphics resource, single CPU, headless
QEMU, ephemeral screenshots, no hardware GPU or physical disk writes.
Even a fully passing test does **not** establish a universal reversible
graphics driver, all resolutions, hotplug, or runtime recovery across
every device.

## Evidence policy

Before marking this specific milestone successful, record the **actual
new CI job/run** showing exact baseline geometry and pixel equality.
If the QEMU reset does not restore the image, retain the failed result,
analyze QEMU's actual behavior, and do not lower the compare threshold.
