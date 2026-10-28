# ADR-0085: Verified EDID and GPU timing intersection before mode selection

Status: Experimental QEMU-only gate, stacked draft on #316. Not a production
display driver and not permission to merge into `main`.

## Problem

A monitor's genuine GET_EDID response is evidence of the monitor's supported
timings, **not** proof that WolfOS has a driver, framebuffer resource, GPU
bandwidth or an active scanout capable of applying any of those timings.
QEMU's real VirtIO-GPU GET_DISPLAY_INFO gives scanout geometry but **not**
an independently validated pixel-clock/link budget. Claiming EDID-native
resolution or Hz as an applied GPU mode would be false.

## Selection contract

`VerifiedScanout` carries a checksummed real EDID mode catalogue and a
nonzero connector generation. A separate GPU driver must supply
`GpuTimingEvidence`: that same generation, exact driver-validated modes and
verified pipeline width/height/pixel-clock/refresh/interlace bounds. The new
`choose_with_gpu_evidence`:

1. Rejects absent GPU evidence and stale connector generations.
2. Takes the **exact timing intersection** of verified EDID and driver modes.
   Preferred/native metadata is preserved from EDID, not trusted as GPU proof.
3. Applies the existing automatic/manual resolution and exact-millihertz
   refresh policy to the intersection. Unsupported combinations never
   silently round 59.94 Hz to 60 Hz or synthesize other refresh rates.
4. Rejects absent common timings and modes outside driver pipeline limits.

`plan_with_gpu_evidence` performs the same checks for a user-requested
change, including validation that the *current* mode is also in the trusted
intersection. It produces only the existing 15-second confirmation/rollback
**plan**. A future real modeset driver is responsible for applying a mode,
observing hardware readback and actually restoring the previous setting.

## Genuine QEMU proof, no fake mode selection

The #316 real GET_DISPLAY_INFO and GET_EDID commands remain unchanged:
two genuine used-ring completions, negotiated EDID feature, exact response
fence, bounded DMA, mandatory reset-before-PMM-free and five-frame accounting.
After the real EDID parser returns a catalogue, the opt-in live experiment
passes **no GPU timing evidence**, because none has been established. The
selection API must reject with `MissingGpuTimingEvidence`. The serial marker
records `gpu_timing_proof_required=1 mode_writes=0`. A Python validator and
negative marker mutations require these fields; failure is not a pass.

Host Rust regressions cover driver/EDID intersection, manual resolution and
exact refresh, missing evidence, stale generations, pipeline rejection,
unverified current mode, and the 15-second rollback plan. The existing
mandatory genuine-QEMU GET_EDID CI step runs on every PR update. No
physical GPU, disk, modesetting, scanout resource creation, 3D path or
synthetic display mode is touched.

## Next hardware prerequisite

A separate QEMU-only driver PR must establish actual resource/scanout
capabilities and successful modeset/readback/rollback before WolfOS may
advertise any new choice as *applicable*. Only then should automatic default
selection and user-facing resolution/Hz controls be enabled.
