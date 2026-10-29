# ADR-0093: Host pixel attestation for display-mode evidence

## Status

Accepted, implemented and verified under real QEMU (QMP screendump + COM1).

## Context

ADR-0092 introduced a display-mode catalog in which only a mode that was
*really applied and really verified by an independent host capture* may become
selectable (`ScanoutProof::HostVerifiedApplied`). The first implementation had a
serious weakness: the kernel **asserted** that claim itself.

```rust
// Rejected by this ADR: the driver grades its own homework.
modes.record(ModeEntry {
    width: 64, height: 64,
    proof: ScanoutProof::HostVerifiedApplied,
    refresh: RefreshEvidence::Unavailable,
})
```

The boot path printed `host_pixels_verified_by_kernel=0` and simultaneously
recorded entries marked host-verified. Nothing bound the claim to an actual
host observation, so a driver bug, a wrong stride, a corrupted DMA transfer or
a resized scanout would all have produced the same "verified" catalog. That is
exactly the fabricated capability claim this project forbids.

## Decision

Making the claim requires a **challenge/response with a nonce and a pixel
digest**, exchanged over the COM1 verification channel:

1. Before each capture the driver prints

   ```
   WOLFOS_GPU_STAGE_ATTEST stage=active geometry=64x64 \
       nonce=0000574f41540001 source_digest=171cbca5
   ```

   The nonce is stage-unique, and `source_digest` is FNV-1a over the canonical
   `(r, g, b)` triple of every source pixel the driver placed in the resource,
   in scanline order.

2. The host takes a real QMP screenshot, verifies every pixel against the
   expected pattern, and computes the *same* digest from the pixels it really
   saw. It replies with one line:

   ```
   A 64x64 0000574f41540001 171cbca5
   ```

3. `decode_attestation_reply` accepts the reply only if the stage token, the
   nonce, the geometry and the digest all match, the line is ASCII, has exactly
   four fields, and is at most `MAX_REPLY_BYTES` long. Anything else fails
   closed with a specific `AttestationError`.

4. Only an accepted `Attestation` can create a `ModeEntry`. The driver has no
   other way to obtain `ScanoutProof::HostVerifiedApplied`.

Refresh stays `RefreshEvidence::Unavailable` even after attestation: observing
geometry proves no pixel clock.

## Consequences

* A corrupted transfer, wrong stride, swapped channel order, wrong geometry or
  a replayed nonce cannot produce a selectable mode. The catalog stays empty of
  host-verified entries and automatic selection returns `NoSelectableMode`
  instead of guessing.
* The host still cannot be trusted blindly: it only ever *reports what it saw*.
  The driver compares that against its own source digest, so a host that
  fabricates a value it did not capture is caught by the same comparison.
* The selection really depends on evidence, not on a constant: the kernel
  rebuilds a catalog from the 32x32 attestation alone and requires the
  automatic choice to become 32x32.
* Costs one serial round trip per attested stage and one 32-bit hash over the
  source pixels (4096 pixels for 64x64) on each side.

## Verification

Real QEMU, real QMP screenshots, no mocked pixels:

* Clean run: `attested=3 unattested=0`, `selectable=2`, automatic 64x64,
  `used_idx_before=11 used_idx_after=11` (catalog work consumes no GPU command),
  every rejected EDID geometry still byte-identical on screen — exit 0.
* `WOLFOS_ATTEST_FAULT=digest` → kernel prints
  `WOLFOS_GPU_ATTEST_FAIL stage=active reason=digest_mismatch`, the run fails.
* `WOLFOS_ATTEST_FAULT=nonce` → `reason=bad_nonce`, the run fails.
* `WOLFOS_ATTEST_FAULT=geometry` → `reason=wrong_geometry`, the run fails.
* Offline fixtures reject missing, duplicate, reordered, replayed-nonce,
  wrong-geometry and wrong-digest attestations, and a serial log whose claimed
  digest is not the digest of the verified pattern.

The three fault runs are wired into CI (`qemu-virtio-gpu-attestation-negative`)
so the refusal cannot silently regress into a green run.

## Still open

* Only two geometries (64x64, 32x32) are host-attested. Real desktop sizes are
  not presented yet.
* The channel proves geometry and pixels, not timing: VirtIO-GPU still exposes
  no pixel clock, so no refresh rate can be selected or reported.
* The attestation transport is the QEMU test harness only; a production display
  manager would need an equivalent trusted path.
