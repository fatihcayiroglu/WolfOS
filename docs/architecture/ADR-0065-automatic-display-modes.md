# ADR-0065: Automatic display resolution and refresh-rate policy, user override

Status: policy contract implemented, discovery/UI/physical mode-setting pending.

## WolfOS product rule
WolfOS must automatically select an appropriate screen resolution and
refresh rate after discovering the *actual* connected monitor and GPU
display-pipeline capabilities. The user can separately override resolution
and refresh rate from Settings, and can restore automatic selection at any time.

Each monitor/connector has an independent list of supported modes,
including exact millihertz timings (59.94 Hz != 60 Hz), preferred/native flags,
interlace flags and pixel clocks. The GPU pipeline separately advertises its
maximum dimensions, rate and pixel clock. Allowed modes are the intersection.

## Implemented pure Rust policy
- DisplayMode and PipelineLimits reject zero/invalid/unsupported timings,
  interlaced modes on unsupported pipelines and modes beyond link limits.
- UserChoice independently represents automatic/manual resolution and
  automatic/manual refresh. Unsupported exact requests are *rejected*;
  WolfOS never invents an unsupported Hz or silently overclocks the panel.
- Automatic defaults prefer a trusted native/preferred timing and then
  select higher area and higher supported refresh among equally preferred
  timings. A manual resolution with automatic Hz chooses the best *verified*
  rate for that resolution.
- ModeChangePlan preserves the working mode, ties confirmation to a
  connector generation and confirmation token supplied by the display manager,
  requires matching hardware readback, and enforces a bounded 15,000 ms
  confirmation deadline. On failed apply, timeout, or connector hotplug,
  the display manager MUST reapply rollback_target and verify the restored
  hardware state. Planning alone does not perform a mode switch.
- 22 standalone host Rust tests cover preferred automatic choice, independent
  user overrides, unsupported Hz, 59.94-vs-60 exactness, overclock rejection,
  stale connector, wrong readback and deadline expiry.

## Important unimplemented integration
This module does **not** discover EDID/DisplayID, program physical GPU timing
registers, schedule a timeout, show a Settings confirmation dialog, hotplug
devices, or make an AMD/NVIDIA/Intel graphics driver work. These functions
require a real connector discovery implementation, monitor-safe timing parser,
vendor-specific link training/modeset and tested atomic hardware transactions.
On missing/untrusted timing data, preserve the current firmware display mode
rather than guess arbitrary settings.

The existing QEMU stdvga mode rollback proof (ADR-0064) demonstrates a
separate 1280x800 -> 1024x768 -> 1280x800 *virtual* resolution transaction.
Bochs VBE reports geometry, not trustworthy per-mode refresh rates; do not
treat that test as evidence of 60/120/144/165 Hz support.

Implement subsequent phases with exact connector readback, hotplug-driven
capability invalidation, correct multi-display behavior, refresh throttling
when links cannot sustain timings, and an accessible UI that always exposes
auto selection and safe rollback.

Reference for independently developed design: official kernel KMS atomic
test-only state validation (not reused OS code):
https://docs.kernel.org/gpu/drm-kms.html
