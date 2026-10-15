# ADR-0041 — Admission-only no-yield ELF validation in real QEMU Ring3 test

Date: 2026-10-16
Status: Experimental, pending CI.

The original #95 hardware test still boots two historical yielding ELFs, makes
exactly two real xAPIC preemptions followed by eight INT80 yields, and exits
both processes. The separate non-yielding ELF files from #100 are now compiled
using the same Rust build-script GNU binutils toolchain into actual independent
ELF64 images and embedded **only** in the `p2-ring3-timer-preempt-smoke`
flavor.

Before allocating or mapping even one PMM frame for the historical experiment,
WolfOS invokes its actual no-heap strict ELF64 kernel preflight on both new
images. This also checks build-script-resolved independently linked ELF
symbols, private RX/RW page layout and no writable+executable mappings.
QEMU must attest one precise
`WOLFOS_RING3_NONYIELD_PREFLIGHT_OK` line, explicitly including
`executed=0`, before starting the historical xAPIC hardware test.

This is **not** running those new workloads and does not establish
eight timer-only context switches. The host tests in #100 inspect the
object disassembly for exactly one INT80, EXIT; here the kernel only
validates ELF load plans. Production CPU interrupts, TSS, FXSAVE64,
process lifetime and actual multiple timer-only Ring3 transitions are
separate unsolved parts of #96.

Keep the old QEMU, single-BSP and all prior test gates mandatory. No
physical disks are accessed. Next implementation should have its own
isolated runtime flavor to execute the new workloads with genuine
no-yield involuntary switches, clean EXITs and exact PMM cleanup.
