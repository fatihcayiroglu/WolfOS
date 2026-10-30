# ADR-0096 — Transactional, host-attested display mode change

Status: accepted (QEMU-only, draft stack on top of ADR-0095)
Date: 2026-10-29

## Context

ADR-0094 proved that the kernel can present its real 1024×768 Limine
framebuffer as a native VirtIO-GPU scanout and that an independent host capture
matches every pixel. ADR-0095 made that proof the *only* way a mode can become
selectable, so an unproven geometry can never enter the settings catalog.

What existed was still a **plan**, not a change. `ModeCatalog::plan_change`
returned a `ModeChangePlan` with a 15 s rollback window, and nothing ever
applied a switch, read it back, accepted a confirmation or restored the
previous mode. A display system that cannot do that cannot offer a settings UI:
the user would have no guarantee that a mode change which breaks the screen is
undone.

## Decision

### 1. A mode change is a state machine with named states, not a return value

`kernel/src/display_mode_transaction.rs` owns one in-flight change:

```
begin -> Pending -> (applied + readback) -> Pending
        -> Confirmed          (host-attested observation inside the window)
        -> RollingBack        (expiry, contradicted readback, peer refusal)
           -> RolledBack      (restoration proven again)
           -> Unreconciled    (restoration not proven; resources stay pinned)
```

Enforced properties, each with host tests:

* a confirmation requires **both** an applied signal from the device **and** a
  host-attested observation at the requested geometry — the driver cannot
  confirm its own switch;
* an expiry claim earlier than `confirmation_deadline_ms` is refused
  (`deadline_not_reached`) instead of being obeyed, so a peer cannot shorten
  the window;
* a rollback is `RolledBack` only when the restored geometry is again proven;
  otherwise `Unreconciled`, and `resources_may_be_released()` stays false;
* the rollback target is always a catalog entry with `HostVerifiedApplied`
  proof, never a device claim or an EDID mode.

### 2. The second geometry is a real frame, not a cropped lie

A second selectable geometry is required, otherwise "change the mode" degrades
to "change the same mode". `virtio_gpu_desktop_wire` now also encodes a
**1024×384** presentation of the same resource: six fenced band transfers of a
visually distinct pattern, `SET_SCANOUT`, `RESOURCE_FLUSH`.

The width is deliberately identical to the desktop mode. A transfer band must
be a contiguous guest buffer whose layout equals the resource layout
(one 4 KiB page per scanline); any other width would make the packed transfer
window disagree with the backing pages, and the digest check would then be
comparing different bytes than the device shows.

Discovery and change are separate, and both are host-verified:

1. present 1024×768 → capture `desktop` → attestation;
2. present 1024×384 → capture `reduced` → attestation;
3. catalog proof (two proven entries, device claim and EDID rate refused);
4. transaction 1024×384 → 1024×768: plan, re-upload only the six bands the
   reduced mode overwrote, `SET_SCANOUT`, `RESOURCE_FLUSH`, device readback,
   capture `applied`, verdict.

### 3. What the device readback really is on this device

The readback is a fresh fenced `GET_DISPLAY_INFO` at its own control-queue
index. On QEMU's `virtio-vga` it reports **1280×800** — the VGA console
geometry — regardless of the `SET_SCANOUT` rectangle the driver set:

```
WOLFOS_VIRTIO_GPU_DISPLAY_READBACK index=35 enabled=1 x=0 y=0
  width=1280 height=800 flags=0
```

So on this device the readback proves `scanout 0 is enabled and attached`, and
nothing about the rectangle. The state machine encodes that honestly as
`Applied::ScanoutEnabled` (`readback=console_enabled`), which is a *weaker named
signal*, never a silent substitution:

* device reports our rectangle → `Applied::Geometry` (`readback=device`);
* device reports the stable console geometry → `Applied::ScanoutEnabled`;
* device reports anything else → `DeviceDidNotApply`, immediate rollback;
* device reports `enabled=0` → `DeviceDidNotApply`, immediate rollback.

The geometry and pixel authority for the new mode remains the independent host
capture. This is the same safety boundary as ADR-0095: nothing about a mode is
believed because the driver or the device says so.

### 4. The confirmation window is owned by the guest clock

The 15 s window used to be measured by the peer that answers it, which meant a
peer that simply went silent could leave the guest in a half-applied mode
forever. A window only the other side measures is not a window.

The display flavor now validates the HPET at `0xFED00000` before trusting it:
PCI vendor `0x8086`, revision ≥ 1, a 64-bit main counter, a device-reported
counter period of at most 10^8 fs, and a liveness check that the counter really
advances. Any rejection leaves `clock=absent`, prints the reason, and falls back
to a host-measured window that is named as such in the evidence — fail-closed,
never a silent substitution.

Exactly one MMIO write is made: General Configuration bit 0 (`ENABLE_CNF`). No
comparator is programmed, no interrupt is routed, and no other bit is touched.
The write is necessary because the main counter does not run until it is set.

Durations are computed only from the period the device reports (`period_fs`,
128-bit math, wrap-tolerant); no nominal frequency is assumed. Evidence states
`deadline_clock=hpet`, `verdict_source=guest`, `window_enforced_by=guest` and the
guest's own `verdict_elapsed_ms`, which the harness cross-checks against its wall
clock to within a few seconds.

Before asking the peer to look at a stage, the driver waits one refresh on that
same clock: grading a frame the console has not picked up yet would measure
timing instead of pixels.

Protocol:

* the driver prints the stage challenge (nonce + its own source digest);
* the host captures, compares, and answers `X <elapsed_ms>` (its own measurement)
  or the nonce-bound attestation;
* `X <elapsed_ms>` with `elapsed >= 15000` ends the window: the guest re-checks
  the deadline itself and rolls back;
* an early `X 1000` is refused by `expire` (`deadline_not_reached`) and the
  transaction stays pending;
* a verdict that arrives *after* the guest already ended the window is dropped
  and counted (`WOLFOS_GPU_STALE_REPLY_DROPPED late_verdict=1`), as is a reply
  that names an older stage nonce (`late_stage=1`) — that reply answers a stage
  that no longer exists. Stage nonces only grow, so this is a comparison, not a
  guess. Buffered leftovers are also drained before a challenge, so the drain
  can never stall on a line that does not arrive.

## Consequences

* The positive QEMU run now proves 1,048,576 pixels across two geometries in
  one boot, plus a real device readback and an applied frame that must equal
  the original desktop image byte for byte.
* `WOLFOS_DESKTOP_FAULT=mode_expired` makes the host really wait past the
  window, then forces a rollback whose restoration is again host-verified —
  the first evidence in WolfOS that a *failed* mode change puts the user back
  on a working screen.
* `WOLFOS_DESKTOP_FAULT=mode_early` proves the guest does not obey a shortened
  window.
* The control-queue bound `DESKTOP_MAX_INDEX` grows from 21 to 46 (worst case:
  discovery plus change plus verified rollback); it stays a compile-time
  constant and every completion is still fence-matched.

## Limits

* Not a timing change: no pixel clock, no refresh rate, no link training.
  `RefreshEvidence::VerifiedMilliHz` remains unreachable in production paths.
* One scanout, one resource, one synthetic connector generation; no hotplug
  re-read, so a real monitor swap is not detected.
* The second geometry is a scanout rectangle of the same resource, not a
  separately allocated framebuffer per mode; a production driver needs one
  resource (or a reallocation transaction) per mode.
* Transfer is synchronous and blocking; there is no page-flip, no double
  buffering and no damage-region flush.
* The window is enforced by the guest only when the HPET validates; the
  fallback to a host-measured window is printed, and the HPET is assumed to be
  at its architectural address on `q35` (no ACPI table walk yet). There are no
  comparator interrupts, so expiry is a polled deadline, not a timer IRQ.
* `virtio-vga` does not always shrink its console back to the restored
  rectangle: it may keep the previous height and show the restored frame in the
  top rows. The harness therefore grades the restored frame by content (the
  full image, byte for byte, in those rows) and prints which case the device
  produced (`restored_console=shrunk|kept_console_height`) rather than assuming
  a resize.
