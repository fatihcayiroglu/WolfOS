# ADR-0059: Read-only GPU identity and fail-closed boot display fallback

Status: Draft, subject to exact-head CI.

## Decision
- Identify PCI display-class functions (class 0x03) using their observed vendor
  and device IDs. Recognize NVIDIA (10de), AMD (1002), Intel (8086), emulated
  QEMU (1234/1b36), and VirtIO (1af4) **as identities, not working drivers**.
- Maintain independent `DisplayIdentity` and `DisplayDriverPlan` types.
- Until a real trusted native driver has been implemented and verified, every
  device remains **unbound**. No PCI BAR, command register, MMIO, DMA or
  firmware operations occur as a result of vendor or device matching.
- Use the existing Limine-provided framebuffer **only after** existing strict
  framebuffer validation and pixel readback. Report
  `native_accel=0 driver_loaded=0` honestly. Absence of a validated
  framebuffer yields `Unavailable`, not an untrusted driver installation.

## Evidence and limitations
- Host Rust tests exercise all vendor classifications, absent devices,
  non-display classes, unknown hardware, and both fallback states.
- Strict Python tests reject forged driver/acceleration claims, mismatched
  PCI identities and out-of-order boot evidence.
- QEMU BIOS VGA and verified framebuffer evidence are required in `make smoke`.
- No vendor kernel driver, 3D acceleration, firmware or package downloader is
  implemented here. PCI identity does **not** identify which GPU supplies a
  particular bootloader framebuffer on a multi-GPU host.
- No real-disk I/O, no network driver download, and no real hardware changes.

## Future acceptance to activate a native driver
A separate PR must implement and test hardware-specific programming, firmware
license provenance and policy, ABI compatibility, signed package verification,
error recovery and safe rollback, optional hotplug, GPU memory isolation,
relevant real-hardware tests, and fully audited automatic binding. Until then
vendor detection may not silently enable an accelerated driver.
