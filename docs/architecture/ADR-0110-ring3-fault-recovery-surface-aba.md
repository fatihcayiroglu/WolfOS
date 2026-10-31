# ADR-0110 — Real Ring3 fault recovery must reject stale graphics surface handles

Status: proposed; draft incremental feature stacked above PR #337 / ADR-0108.

## Motivation and compatibility

The WolfOS Ring3 surface retirement smoke chain tests an isolated authentic
hardware CPL3 program's EXIT, invalid-opcode and page-fault terminal paths.
However, it previously proved one surface lifetime per QEMU boot. A real
desktop routinely reuses an object's fixed-capacity slot after a failed
application and starts an independent process. An old surface handle or
previous GPU fence must never authorize operations in the next process.

This experiment deliberately uses ADR-0110 rather than ADR-0107/0108:
parallel draft PRs #336 and #338 independently own those same ADR numbers
for different pixel provenance research. Do not silently overwrite them.

## Proof path

New feature `user-surface-fault-recovery-smoke` inherits the actual
`user-process-fault-recovery-smoke` hardware test. It retains both
independently linked ELF binaries, their separate PMM-backed CR3 roots,
the original `#PF` fault with exit code 139 for PID1, complete reclaim,
then the independent healthy ELF program with real INT80 syscalls and
EXIT(0) for PID2. Both physical seven-frame leases are returned and the
actual PMM count must equal the boot baseline after each process.

- The *same* fixed-capacity `SurfaceLedger<1>` survives process retirement,
  even though the exact surface handle is closed and logically released.
- PID1 opens slot 1 with surface generation 1; its software-only GPU
  fences are 1 and 2. The real Ring3 #PF path restores boot CR3, refuses
  early/half-completed/metadata-retained reap, then takes explicitly
  **synthetic** transfer and flush acknowledgements, closes its handle,
  and returns the counted PMM lease through the authenticated guarded API.
- The fixture records PID1's retired handle but does not retain any
  real PMM frame or pointer from PID1.
- PID2 can only open after genuine PID1 CR3/PMM retirement and subsequent
  independent ELF launch. It reuses slot 1, necessarily with a strictly
  newer surface generation and its own authenticated PID generation.
- The kernel asserts the exact retired PID1 handle is rejected as stale,
  the old generation owns zero handles and cannot close a new PID2
  surface, and replay of prior fence pair 1/2 is refused by the global
  fence watermark. PID2 must submit new software-only fences 3 and 4.
- PID2's legitimate EXIT(0) then goes through the same CPU/PMM,
  guarded-surface retirement and genuine seven-frame reclamation path.

The test harness checks *exactly once* and in strict serial order:
boot, authenticated PID1 surface open, real PID1 CPL3 entry, page fault,
guarded surface reaping, real physical PMM cleanup, PID2 relaunch,
old-handle/fence denial before PID2 surface open, real PID2 CPL3 entry,
healthy EXIT, guarded surface reaping, final physical PMM cleanup.
It also retains every old two-ELF launch and cleanup requirement and
forbids any unexpected kernel exception, timeout or duplicated proof.

## Safety claims and limitations

This proves real hardware Ring3 execution, protected CR3 restoration,
a process-owned PMM ledger, and logical surface/fence generation
resistance to ABA across two genuinely different processes.

**Not proven:** actual userspace pixel mappings, real VirtIO GPU queue
submissions, hardware-completed fences, DMA page pinning, multi-CPU
concurrent locking or a production GUI. Both logical GPU acknowledgements
remain synthetic; the fixture is a BSP-only IF=0 `UnsafeCell` isolated
to the opt-in QEMU flavor. Never equate `software_acks=1` with real DMA.

A production integration still needs one authoritative process/graphics
retirement lock and device-validated fence acknowledgements before
physical buffer lifetime is reclaimed. This experimental feature does
not remove legacy unguarded ProcessTable entry points.

## Acceptance

The new `make user-surface-fault-recovery-smoke` real QEMU target is
mandatory in P0 alongside all existing GPU, Ring3, SMP, exit and fault
regressions. Require exact-head green CI, no skipped coverage accepted
as a pass. Keep all PRs draft, production `main` untouched and never
modify a physical installation disk.
