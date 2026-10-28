# ADR-0067: Strict EDID base-block timing parser for WolfOS display choice

Status: pure parser and host tests; live DDC/I2C, CTA/DisplayID and UI pending.

## Goal
WolfOS shall automatically select a supported resolution and refresh rate
per connected display, while allowing users to override each setting
independently. It must never invent a monitor refresh rate because a generic
framebuffer or QEMU Bochs VBE reports only geometry.

## Implemented
- New original Rust parser of one exactly 128-byte EDID version 1.0–1.4 base
  block with exact header, 8-bit wraparound checksum and zero extension count.
- Explicit fail-closed errors for invalid length, signature, checksum,
  unsupported major/minor version, unparsed extensions, malformed detailed
  timing and absent known detailed timing.
- Scans the four 18-byte base-block detailed timing slots, distinguishes
  non-timing monitor information descriptors from genuine pixel clocks,
  extracts active width/height, blanking totals, 10 kHz pixel clock and
  interlace flag, and calculates refresh in millihertz (not rounded to Hz).
- Honors the EDID 1.0–1.3 preferred timing feature bit; EDID 1.4 selects
  the first valid detailed timing as preferred. Deduplicates exact timings.
- Returns at most four verified modes without heap allocation. Its result
  feeds the existing independent DisplayModePolicy + GPU PipelineLimits.
  A user request such as 165 Hz is rejected if the EDID lacks that mode.
- Host tests cover valid 1920x1080@60, 2560x1440@120, preferred choice,
  manual mode selection, checksums, invalid fields, duplicate modes,
  interlaced capabilities and unsupported extensions.

## Hard boundaries
- This does not yet fetch EDID via DDC/I2C or trusted GPU driver APIs.
- This deliberately rejects all EDIDs reporting CTA-861/DisplayID/other
  extension blocks until a strict extension parser verifies their own
  checksums and timing semantics. Many real monitors have extensions,
  so the base-only parser **is not yet a consumer-ready auto-detection path**.
- Established and standard EDID timing lists and vendor quirk repair are
  also future work. If no complete trustworthy mode list exists, keep the
  current working firmware framebuffer mode and do not guess.
- No physical GPU timing registers are changed. Real display pipeline
  clock/link validation, hotplug and a 15-second revert UI still require
  implementation and hardware acceptance.

Format cross-check against the official Linux DRM EDID header structures,
not source reuse:
https://github.com/torvalds/linux/blob/master/include/drm/drm_edid.h
