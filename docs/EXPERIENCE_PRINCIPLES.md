# WolfOS — Comfort-First Product Contract

This is a product quality contract, NOT a claim that these features exist today.
WolfOS remains an independent Rust-kernel operating system. The objective
is not to visually imitate Windows, Linux, or macOS, but to preserve the
strongest user-facing outcomes of all three while developing WolfOS-specific
technology that can be measured against them.

## Product outcomes (non-negotiable)

1. **macOS-like ease without macOS restrictions:** consistent controls,
   coherent typography, graceful default settings, accessibility and
   localization, immediate visual feedback, no requirement to learn a CLI
   for ordinary installation, updates, peripherals or recovery.
2. **Windows-like app and game reach:** supported native applications and
   mature compatibility modes must install, launch and uninstall with
   clearly described limitations. Steam and GTA V Story Mode are measurable
   long-term targets, not current guarantees. Third-party kernel anti-cheat
   and DRM limitations must remain explicit.
3. **Linux-like user agency:** transparent diagnostics, shell and scripting
   access, optional expert controls, inspectable security policy and
   freedom from mandatory cloud identity or telemetry.
4. **WolfOS-owned core:** kernel, scheduling policies, memory isolation,
   native application/runtime and UX integration are designed by WolfOS.
   Existing open standards and high-quality software may be adopted where
   they demonstrably accelerate correctness, reach and product quality.
5. **Fail-closed protection:** never silently downgrade memory isolation,
   update signature verification or malware defenses to improve app
   compatibility.

## Engineering order: proof of a user task, not accumulation of boot flags

- First milestone: compile+link a standalone native ELF64 application, load
  validated RX and RW+BSS segments, run in real CPL3 under a protected private
  CR3, print a recognizable message via syscall, EXIT(0), and verify owner
  resource cleanup in QEMU.
- Next: generalize ownership into process/thread handles, a basic kernel
  heap, a small RAM filesystem and a bounded native stdout/write ABI.
- Next: make native shell input/output interactive; keyboard and terminal
  events must flow through the same process isolation and error controls.
- Next: functional graphical desktop with keyboard navigation, consistent
  settings, accessible interaction and safe application install/update.
- Later: broader device support, performance/game optimizations, Windows
  application compatibility and consumer-ready recovery flows.

## Acceptance metrics (baselines still to be measured)

**Never declare a score better than Windows/macOS/Linux without repeatable,
comparable testing on the SAME machine.** For each supported real device:

- Cold boot to first responsive interaction, including driver initialization.
- p50, p95, p99 application-launch latency and frame-time distribution.
- Usable responsiveness while background CPU/disk/I/O load is sustained.
- Percentage of supported hardware requiring no manual driver installation.
- Successful unattended install/update/rollback under interrupted power.
- Number of ordinary user tasks (Wi-Fi connect, app install, display change,
  file opening, device setup) that require a terminal or documentation.
- User-mode fault containment, recoverable operation and preserved user data.
- First-run completion and accessibility testing by non-expert users.

Every claimed improvement should include a test scenario, reproducible
instrumentation, baseline hardware and a regression gate. QEMU smoke tests
prove CPU behavior only; they do NOT measure everyday consumer comfort.
