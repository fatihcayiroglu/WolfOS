# ADR-0111 — QMP pixel attestation for genuine Ring3-authored standard VGA display

Status: proposed. Stacked on PR #341 (real CPL3 guest-written pixel buffers).
This is an isolated, single-BSP QEMU smoke, not a production window manager.

## Remaining evidence gap

PRs #338-#341 established four-level PMM-owner-checked user virtual pixel
copying and showed that independently linked Ring3 code actually writes
xRGB8888 pixels into private RW+NX user stack buffers before INT80.
However, their compositor output was kept in a 5x3 kernel CPU array:
there was **no host-observed screen image showing those guest-authored
pixels**, nor an exact restoration proof.

## Isolated display adapter

Opt-in `user-surface-writer-display-smoke` inherits the existing real
CPL3 user-surface-writer feature and **all existing ABI/CR3/PMM tests**.

At a genuine user INT80 trap, while the real user CR3 is still active:
1. The kernel authenticates saved user R12/R13 pointers and the true
   `ProcessTable` owner; its four-level user PTE walk verifies W/R
   permissions and rejects any physical frame not owned by that PID.
2. Existing `compose_user_snapshots` copies two genuine user-written
   8-byte surface buffers, merges them into a 5x3 kernel-owned CPU image,
   and verifies every pixel and surface revocation.
3. Only the 15 composed `u32` values escape the process table's
   locked closure. Neither a borrowed userspace pointer, writable
   mapping, source frame nor surface handle is exposed to display code.
4. The new main-kernel-only adapter validates the Limine mapped 32bpp
   RGB framebuffer width/height/pitch/shifts and every fixed patch
   pixel offset before any write. It saves the previous contents of
   a 5x3 rectangle at absolute (200,150) in that real framebuffer.
5. Serial stage **baseline** asks the host QMP to screendump a PPM and
   send acknowledgement `B`. The kernel paints the composited CPU
   snapshot using volatile aligned 32-bit stores and asks for **active**:
   host full-frame RGB must match the baseline byte-for-byte EXCEPT for
   the 15 expected xRGB8888 pixels. The host sends `A` only after the
   pixel-perfect comparison.
6. The kernel restores all original framebuffer words, asks the host
   for **restored** and receives `R` only if the full QMP RGB frame
   equals the original baseline byte-for-byte. On unexpected byte,
   malformed stage or stalled host, the QEMU smoke fails closed.
7. After the screenshot proofs, the original real INT80 syscall path
   resumes to genuine CPL3 and finishes with EXIT, hardware boot CR3
   restoration, exact 7-frame physical PMM cleanup and zero leaks.

The test harness uses QEMU's real QMP `screendump` command on **std
VGA**, not a screenshot constructed from guest-claimed source pixels.
It independently verifies RGB geometry, all channels, all untouched
screen pixels and exact rollback, one stage in strict serial order.

## Trust boundary

This is authentic **guest-authored -> user copy -> CPU composition ->
Limine standard VGA memory -> host-observed QMP screen** evidence.
It is a substantial step beyond an in-kernel array-only proof.

It is **NOT** a VirtIO-GPU hardware command or actual fenced DMA.
The VGA scanout is emulated by QEMU, and the guest writes the framebuffer
with the CPU, not through a real vendor driver. No production GUI syscall,
real two-PID concurrent compositor, persistent surface memory mapping,
SMP display lock, frame-ready IRQ or physical GPU driver is included.

The synchronous COM1 acknowledgement protocol and polling are only
compiled in this opt-in single-BSP IF=0 QEMU test. It is deliberately
not a general rendering or event loop.

## Acceptance

The mandatory P0 step `make user-surface-writer-display-smoke` must
complete on its exact PR head; all existing GPU, Ring3, real-PMM and
SMP regressions remain. The host must capture baseline, active and
restored QMP screenshots; a serial-only claim, timeout, skip or kernel
log string cannot substitute for pixel evidence. No release or merge to
`main`; no physical installation disk access.
