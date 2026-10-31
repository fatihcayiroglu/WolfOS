# ADR-0110 — Genuine Ring3-authored writable surface pixels in QEMU

Status: proposed; stacked draft on PR #339 / ADR-0109.

## Why the previous proof was insufficient

PR #339 proved that a real CPL3 guest-provided RDI pointer can be translated
through its authenticated private user CR3 and owner-only PMM pages into a
kernel software-composed image. Those bytes, however, came from the guest's
read-only linked ELF fixture; it did not prove a guest can **write pixels**
to a writable user buffer that the kernel subsequently reads safely.

## New isolated proof

A new `user-surface-writer-smoke` feature inherits the existing genuine
CPL3 user-copy and user-surface-pointer hardware tests, while keeping all
original smoke flavors unchanged.

In `user/hello.S`, only under `WOLFOS_USER_SURFACE_WRITER=1`:

1. The real CPU executing the independently assembled/linkable ELF in CPL3
   uses four `mov dword ptr [rsp - offset], immediate` instructions to
   write two independent 8-byte xRGB8888 pixel arrays to the actual user
   RW+NX stack, below the guest RSP. These aren't synthetic kernel writes.
2. R12 and R13 contain user virtual addresses of the two arrays. The
   program still invokes the original WRITE-like syscall 5 with RDI
   pointing to the original ELF text string; existing ABI, negative
   kernel read and RX write-refusal regressions remain unchanged.
3. The kernel's real INT80 trap authenticates active user CR3, PID RUNNING
   state, saved user stack and saved R12/R13. It requires a page-table
   `Access::Write` walk of both addresses; the physical leaves must be
   the same authentic PID-owned PMM frame and each 8-byte region must
   fit within the page.
4. The kernel mints two surface handles for that RUNNING PID, calls the
   bounded `compose_user_snapshots` bridge on both actual guest-written
   user VAs, and checks **all 15** output pixels of an opaque overlapping
   two-window 5x3 software composition against the guest's exact
   programmed xRGB8888 words.
5. Kernel closes the two surface handles and repeats the attempted
   composition. It must reject the revoked surfaces without modifying
   any destination pixel. Then the original 4-syscall EXIT(0) sequence
   still restores supervisor CR3 and reclaims all seven real PMM frames.

The exact new serial proof marker begins
`WOLFOS_USER_SURFACE_WRITER_CPL3_OK guest_stack_written=1 user_rw_nx=1`
and explicitly ends `real_gpu_dma=0`. The opt-in user-copy QEMU host
harness requires that unique marker after the previous genuine-pointer
proof, before the original user EXIT proof. A separate mandatory P0 step
runs `make user-surface-writer-smoke`.

## Limitations and trust

This *does* prove the user executable wrote genuine pixel words to its
real mapped RW/NX private stack and that the trusted software compositor
copied them through full 4-level PTE and PMM owner checks. It does **NOT**
create a reusable production graphics syscall, map a persistent dedicated
application surface, submit these pixels to VirtIO-GPU, show them on the
screen, attest a host screenshot, enforce per-app GUI permissions, or
support concurrent multi-PID graphics or physical GPU hardware.

The test is isolated BSP-only, IF=0, with an existing process registry
lock. Production still needs synchronized page pinning, compositor
scheduling, GPU-fence used-ring verification, per-app capability checks
and teardown integration. Never treat this as GUI readiness.

All feature changes remain draft and stacked. No merge to `main`, no
physical disk operations and no claim of green until exact-head P0 success.
