# ADR-0109 — Genuine CPL3 user-pointer surface snapshot in QEMU

Status: proposed. Stacked draft above PR #338 / ADR-0108.

## Exact evidence

The previous PR implemented a process/PMM-owned `user_copy::copy_from`
bridge and host tests with modeled physical memory. This increment adds an
**independent real-QEMU feature** `user-surface-copy-hardware-smoke`,
inheriting the existing `user-copy-smoke` hardware journey.

The real x86-64 CPU boots a new user CR3, executes a linked ELF64 program in
CPL3 and invokes its existing WRITE-like INT80 with RDI containing a genuine
user virtual pointer into the executable's read-only ELF text/fixture.
After the genuine trap to CPL0, the kernel checks the hardware CR3 and
ProcessTable RUNNING state. Under the serialized BSP process table lock and
interrupts disabled, it:

1. Opens two distinct generation-tagged surface handles for the authenticated
   RUNNING PID (same process, distinct surface slots).
2. Takes two separate 8-byte slices from the **actual user text page**,
   beginning at the guest-provided RDI and RDI+8, using the existing
   `user_copy` four-level page-table walk. Each PTE and physical pixel-byte
   read must belong to the same actual PMM frame lease.
3. Composes an exact 5x3 kernel-stack xRGB8888 software viewport.
   Opaque rectangles each cover two pixels and overlap in one: first owner
   contributes one, second contributes two, and twelve remain background.
   All fifteen output values are checked against the actual ELF bytes.
4. Revokes the process's two surface handles and verifies a subsequent
   compositor attempt is rejected before changing a single pixel.
5. Verifies a forged generation is also refused while the user ELF page
   remains physically mapped; then returns to the original WRITE journey,
   normal EXIT syscall, supervisor CR3 restoration and exact PMM cleanup.

A new serial proof marker
`WOLFOS_USER_SURFACE_CPL3_OK guest_rdi_pointer=1 real_user_cr3=1 exact_owner_frames=1 source_bytes=16 two_surfaces=1 composed_pixels=15 revoked_denied=1 synthetic_gpu_acks=0 real_gpu_dma=0`
is required exactly once in-order by the existing QEMU user-copy harness
only when `WOLFOS_USER_SURFACE_HARDWARE=1`. The old `user-copy-smoke`
marker list, module behavior and P0 gate are preserved.

The new P0 gate adds `make user-surface-copy-hardware-smoke` on top of
all previously mandatory real GPU, Ring3 and SMP tests. Neither a scripted
guest-fault nor a mere host-only model can satisfy the evidence.

## Precise limitations

This is the first proof that **genuine CPL3-provided user pointers** reach
a process-authorized software surface copy. It is NOT a real graphics
syscall, not a writeable graphics buffer authored by Ring3, and does not
submit these fifteen pixels to VirtIO-GPU or attest them in a host screenshot.
The values come from immutable ELF fixture bytes, and both distinct surface
handles belong to the same running PID. No actual two-PID concurrent
graphics app, user-writable mapped graphic pages, real GPU DMA, physical
driver installation or desktop GUI is demonstrated.

The isolated smoke uses BSP-only IF=0, its existing process registry lock,
real private CR3 and PMM pages, and no concurrent CPU users of those
mappings. Production must separately authenticate syscall capabilities,
serialize all CPU/scheduler/PMM/graphics participants, pin page frames
through copy+presentation, validate hardware fenced completions and retire
the original process through the guarded teardown entrypoints.

Keep PRs draft, preserve `main` unchanged and require exact-head P0 CI.
