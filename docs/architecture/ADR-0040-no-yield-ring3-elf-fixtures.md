# ADR-0040 — Independently linked syscall-free Ring3 CPU workloads

Date: 2026-10-16
Status: fixture + host-verification only; no timer-only hardware claim.

## Rationale

Merged #95 proved exactly two genuine hardware xAPIC preemptions; #99
binds the software policy to that old acceptance mode. Neither demonstrates
sustained timer-only switching because the old `user/yield.S` executes eight
voluntary INT80 yields following its non-syscall busy segments.

## New fixture

`user/timer_no_yield.S` is independently assembled and statically linked
into two ET_EXEC ELF64 programs (PID1 / PID2), using the same strict
two-PT_LOAD linker layout as the previous userspace tests. Each process
executes sixteen CPU-intensive private-data steps without software yield,
retains PID and SSE/XMM0 sentinel state, and issues exactly one experimental
EXIT(0) INT80 only after verifying completion. Unexpected return uses UD2.

`tests/test_timer_no_yield_elf.py` requires GNU assembler, linker, nm
and objdump and rejects missing symbols, wrong ELF class/architecture,
missing user code boundaries, unexpected INT80 within the workload,
multiple syscalls, and identical PID-specific images. The regular existing
`make test` Python discovery includes this host check without skip.

## Explicit gaps and follow-up (#96)

These fixtures are **not yet embedded in, loaded by, or executed under** the
real Ring3 QEMU timer runtime. The follow-up must establish a separate
feature flavor and real hardware IRQ gate, safe source/destination pinned
GPR+IRET frames, runtime scheduling with at least eight involuntary
cross-PID switches, zero voluntary yields, both ELF exits, clean PIC/LVT/
SVR/MMIO/TSS/FX teardown and zero PMM-frame leaks. The historical #95
two-switch gate remains mandatory and unchanged.
