# ADR-0068 — Strict CTA-861 revision-3 display timing subset

Status: draft, QEMU/host parser only. Parent: ADR-0067, PR #299.

## Decision
Implement an allocation-free, bounded **one-extension** EDID consumer. Parse the
128-byte EDID 1.x base block plus exactly one checksummed CTA-861 revision-3
extension, validate all declared data block boundaries, parse its 18-byte DTD
records, and recognize only explicit, verified nominal progressive VIC timings
1, 4, 16, 31, 95, and 97. The six mode totals and clocks are checked against
the upstream Linux DRM CEA modes table:
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/534293368afa1a953c283310b82e4dc58309d51e/drivers/gpu/drm/drm_edid.c

Do not interpret an unsupported VIC as another timing. Do not silently ignore
unknown video-capable block families (vendor-specific HDMI codes, YCbCr 4:2:0,
HDR, other extended blocks): fail the entire parse so we cannot present a
misleading "complete" automatic mode list. Audio and speaker blocks cannot
advertise video timings and can be ignored after exact bounds validation.
Native SVD and CTA-native DTD flags may upgrade a timing's preference; exact
duplicate timings are merged. All refreshes are integer millihertz; 640x480
VIC 1 is 59,940 mHz, not 60,000 mHz.

Preserve the legacy parse_base API: it still rejects *any* advertised extension.
The new parse_complete API checks the whole 1-or-2-block input before
accepting it. Older EDID with no base DTD is still refused.

## Limits
This does **not** support multi-extension EDID, CTA revisions other than 3,
unmapped VICs, DisplayID, full 4:2:0/HDR/HDMI bandwidth negotiation, DDC/I2C
acquisition, hotplug, user settings, or real PLL/scanout refresh changes.
Rejecting a common monitor's unknown extension is expected and preferred to
silently inventing or omitting capabilities. Parsed advertised timings are
not proof of GPU support; the separate pipeline policy must reject unsupported
link bandwidth and modes. Real device proof requires display/connector readback.

Host tests use manufactured **format fixtures**, not physical monitor captures.
The QEMU Bochs VBE path cannot prove actual 60/120/144/165 Hz output.
No physical disk or GPU touched; no register I/O in this module.
