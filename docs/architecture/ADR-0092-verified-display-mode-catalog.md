# ADR-0092: Verified display-mode catalog and explicit unproven-mode refusal

Status: separate **draft PR** stacked on #323; no automatic merge.
QEMU-only proof for a single `virtio-vga`, **not** a production GPU driver
and **not** general display-mode programming.

## Purpose and bounded scope

ADR-0085 already required independent GPU timing evidence before an EDID
mode may be selected: `choose_with_gpu_evidence` fails closed with
`MissingGpuTimingEvidence` and the live GET_EDID gate asserts that refusal.
That gate said what is *not* allowed. This increment adds the first
concrete evidence model plus the user-selection policy built on it.

Three different facts were previously conflated:

- **EDID** describes the monitor: 7 advertised timings, preferred
  1280×800 at 74.994 Hz on the QEMU emulated connector.
- **GET_DISPLAY_INFO** describes the scanout rectangle the device has
  *configured*: enabled, 1280×800.
- **Host-verified applied scanout** is what this driver really made the
  device show and what an independent QMP capture verified pixel-exact:
  64×64 and 32×32.

On `virtio-vga` the configured 1280×800 scanout is not even what the host
shows at that moment: the QMP baseline is the 1024×768 VGA surface Limine
programmed, because the device's VGA compatibility output is presented
until the guest sets a resource scanout. `GET_DISPLAY_INFO` alone is
therefore not display evidence either.

## Catalog rules

`kernel/src/display_mode_catalog.rs` is pure, allocation-free policy with
19 host unit tests. Each entry carries a `ScanoutProof`:

- `HostVerifiedApplied` — the driver created a resource, set the scanout
  rectangle, and a host capture verified every pixel at that geometry.
  Only these entries are selectable.
- `DeviceReportedConfigured` — recorded from `GET_DISPLAY_INFO`, kept for
  reporting and refused for selection.

Rules that the tests and the QEMU gate enforce:

1. Automatic selection ignores device claims and EDID entirely and picks
   the largest host-verified geometry; a mode nothing has proven is never
   returned.
2. A requested geometry is refused with `UnprovenGpuTiming` unless that
   exact geometry is host-verified — including a geometry the device
   itself reports as enabled.
3. A requested millihertz value is refused with
   `RefreshNotProgrammable` while the refresh evidence is
   `Unavailable`. EDID's 74.994 Hz never becomes a "supported refresh
   rate", because VirtIO-GPU exposes no pixel-clock programming at all.
   A future native driver may supply `VerifiedMilliHz`; the same policy
   then accepts the rate it really programmed.
4. Proof can only move upward: recording `HostVerifiedApplied` upgrades a
   device claim, and a claim never overwrites proven evidence
   (`ConflictingProof`). Two different rates for one geometry are
   refused.
5. A mode change is only ever a *plan*: previous mode, requested mode,
   connector generation, one-use token and a 15 s confirmation deadline.
   Confirmation requires the real readback of the requested geometry;
   otherwise `DeviceDidNotApply` and the previous mode remains the
   rollback target.
6. Generation must be non-zero and current, the catalog is bounded to 16
   entries, and zero geometry/rate entries are rejected.

## Seven independent QEMU screenshots

Native rollback from ADR-0091 with one additional host-verified stage:

- `baseline`, `active`, `reduced`, `reexpanded` — as in ADR-0091.
- `refused`: while the 64×64 native scanout is live, the guest builds the
  catalog from real device data and evaluates every refusal path. The
  host must then capture a screen **byte-identical** to `reexpanded`,
  proving a rejected mode change disturbed nothing. The guest also proves
  the device used index is unchanged across the whole catalog stage, so
  `gpu_commands_sent=0` is a measured fact, not a promise.
- `disabled`, `restored` — as in ADR-0091.

The real run reports
`entries=3 selectable=2 device_reported=1`: two host-verified geometries,
one device claim, and `edid_advertised=7 edid_refused=7` — every genuine
EDID timing was refused as unproven. The Python gate additionally
cross-checks the catalog's device geometry against the DISPLAY_INFO
response, the refused count against the EDID response, and requires
`used_idx_before == used_idx_after`.

## Limitations

This proves mode *admission* semantics and refusal safety on the
QEMU-emulated device, not mode *programming*. `virtio-vga` offers no
pixel-clock or refresh programming, so WolfOS can currently change only
the scanned-out rectangle; automatic selection is therefore conservative
and prefers a geometry the device is already proven to show. Arbitrary
resolutions, real refresh-rate control, multi-monitor, hotplug,
arbitrary EDID validation, and real hardware GPU drivers remain
unimplemented, and no settings UI consumes the catalog yet.
