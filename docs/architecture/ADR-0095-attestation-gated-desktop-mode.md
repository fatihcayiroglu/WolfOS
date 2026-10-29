# ADR-0095 — Selectable display modes can only come from host attestation

- Status: accepted
- Date: 2026-10-29
- Supersedes: nothing. Extends ADR-0092 (verified display mode catalog) and
  ADR-0093 (host pixel attestation channel).

## Context

ADR-0092 introduced a display mode catalog in which `ScanoutProof::HostVerifiedApplied`
was the only value that made an entry selectable. ADR-0093 replaced the driver's
self-report with a nonce-bound digest challenge answered by the QEMU host.

Both changes still left a structural hole. `ModeEntry` had public fields and
`Attestation` had a public constructor, so driver code could write

```rust
modes.record(ModeEntry {
    width: 64, height: 64,
    proof: ScanoutProof::HostVerifiedApplied,
    refresh: RefreshEvidence::Unavailable,
    scanout: 0,
});
```

and produce a selectable mode without any host capture at all. The mitigation
was a test (`selectable_mode_requires_attestation_not_driver_assertion`) that
documented the discipline, not a property the compiler enforced. The project
forbids presenting a theoretical mode as operational; a rule that only exists in
a test is not enough for that.

At the same time the first production-geometry scanout (1024×768, the real
Limine framebuffer) was proven pixel-exactly by the host, but that evidence was
thrown away: it never reached the catalog, so automatic selection could still
only choose a 64×64 test tile.

## Decision

1. **Proof is unforgeable by construction.** `ModeEntry::proof` is private and
   `Attestation` has no public constructor and private fields. Outside
   `display_mode_catalog`, the only expressible entry is
   `ModeEntry::device_reported(..)`, which is never selectable. A host-verified
   entry can only be produced by `decode_attestation_reply`, i.e. by a reply
   whose token, nonce, geometry and digest all match the challenge the driver
   issued for that exact stage. This is a type-level guarantee, not a test.

2. **Attest first, catalog second.** The desktop stage returns the accepted
   `Attestation` together with the resource plan. The caller feeds it to
   `prove_desktop_selection`, which is the only place that turns a host capture
   into an automatic choice.

3. **Every refusal is re-proved on each boot** by that same function:
   - a fresh, unattested catalog must fail with `NoSelectableMode`;
   - the device's own `GET_DISPLAY_INFO` geometry must be recorded but refused
     with `UnprovenGpuTiming`, however large its area is;
   - when the device reports exactly the attested geometry, recording the
     weaker claim must be refused with `ConflictingProof` instead of silently
     downgrading the proven entry;
   - the monitor's EDID millihertz value must be refused with
     `RefreshNotProgrammable`, both for the exact geometry and for automatic
     selection;
   - planning the already-applied geometry must be `Ok(None)`: no 15-second
     rollback window is opened for a switch that never happens.

4. **A rejected attestation is reported, not merely absent.** On any desktop
   failure the guest prints
   `WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_FAIL stage=… entries=0 selectable=0 mode=no_selectable_mode`,
   and the host harness requires exactly one such line and no catalog claim.
   The absence of evidence is therefore observable evidence, and a run cannot
   pass by omitting it.

5. **Deterministic device geometry.** The validator cross-checks the catalog
   line against the `GET_DISPLAY_INFO` geometry and the `GET_EDID` rate it
   actually observed, so a catalog claim cannot describe a different device
   state than the one recorded in the same boot.

## Consequences

- No driver, settings UI or future compositor can hand the user a mode that no
  independent capture proved. `refresh=unavailable` remains the honest answer
  for every VirtIO-GPU mode, because no pixel clock is programmed or measured.
- The 1024×768 desktop geometry is now the catalog's automatic choice in the
  real QEMU run, on the strength of 786,432 verified host pixels.
- Adding a genuinely programmed refresh rate later requires a driver that
  measures or programs a pixel clock and an attestation that covers the rate;
  until then `RefreshEvidence::VerifiedMilliHz` cannot be reached at all.
- The guarantee is per-process: a kernel compromise can still forge anything.
  It protects against driver bugs and self-grading, not against a compromised
  kernel.

## Not proven

- Multi-monitor, hotplug re-reads and generation changes.
- Any real GPU family other than QEMU's VirtIO-GPU.
- Production presentation: the image is a deterministic test pattern, not a
  compositor output, and the path has no double buffering or damage tracking.
