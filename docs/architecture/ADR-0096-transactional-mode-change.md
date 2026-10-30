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

### 4. The confirmation window is measured by the host, and graded by the guest

The kernel still has no wall clock on this path (no calibrated TSC, HPET or
ACPI PM timer in the display flavor), so it will not pretend to own a 15 s
timer. Protocol:

* the driver prints the applied-mode challenge (nonce + its own source digest);
* the host answers `X <elapsed_ms>` — the real time it measured between the
  challenge and its verdict;
* if `elapsed >= 15000` the host sends nothing else and the driver calls
  `expire(elapsed)`, which re-checks the deadline itself;
* otherwise the host sends the normal nonce-bound attestation and the driver
  calls `confirm(..)`;
* an early `X 1000` is refused by `expire` (`deadline_not_reached`) and the
  transaction stays pending.

Evidence therefore states `window_enforced_by=host`. This is a documented gap,
not a claim: a hostile host can stall the driver, and the guest-side bound is a
bounded poll budget, not a wall-clock deadline. The next step for this axis is
a real monotonic clock (HPET or ACPI PM timer) so the guest can enforce the
window on its own.

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
* The window is enforced by the host (see §4).
