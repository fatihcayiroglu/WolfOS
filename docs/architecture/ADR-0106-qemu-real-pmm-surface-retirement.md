# ADR-0106 — Real QEMU PMM accounting for surface-owner retirement

Status: proposed, stacked draft above PR #333 / ADR-0105.

## Evidence goal

The call-through surface retirement tests in ADR-0105 run only as host
metadata contracts. This experiment adds an **isolated real QEMU boot**
using WolfOS's existing physical memory manager (PMM) and actual boot
supervisor CR3. It proves that two independent process-owned physical
frame leases are not released while a bound graphics surface has an
outstanding logical transfer/flush. It does not send GPU DMA commands.

## Test construction

New opt-in `qemu-surface-reap-pmm-smoke` feature inherits the existing
`process-table-smoke` and first executes its original 28-real-frame
three-resident PID/context bootstrap and cleanup evidence, unchanged.

The second isolated phase:

1. Reads the real supervisor CR3, allocates four unique aligned physical
   PMM pages and checks the actual PMM allocation counter.
2. Reserves two independent READY `ProcessTable<2,2>` owners, each with
   two real physical frames, then calls the authenticated
   `open_registered` bridge to issue separate surface handles.
3. Stages a *software-only* transfer/flush fence pair for the first handle.
   A counted cancel must fail with `OutstandingSurfaces`; the process
   registry and all four real PMM pages remain owned, and the second
   process/surface remains active.
4. Exercises out-of-order flush refusal and a synthetic transfer
   acknowledgement. Half-completion still cannot return the PMM lease.
   After a separate synthetic flush acknowledgement and explicit metadata
   release, the guarded cancel returns precisely the first two frames.
5. Returns only those verified frames to the actual PMM and checks that
   the other process still owns exactly two physical pages.
6. Closes the second surface (which had no GPU work), cancels its PID
   without inventing any hardware fence and frees only its two frames.
   The real allocated-frame counter must return to the original baseline,
   with no surviving PID or surface handle.

The serial marker is
`WOLFOS_SURFACE_REAP_PMM_OK pids=2 real_pmm_pages=4 early_release_denied=1 half_ack_denied=1 cross_pid_isolated=1 synthetic_gpu_acks=1 pmm_no_leak=1 cpl3_executed=0 real_gpu_dma=0`.
The host harness requires it exactly once and after all original
process-table evidence. Existing negative kernel fault markers and the
expected QEMU ISA debug-exit code remain mandatory.

## What this DOES NOT prove

The transfer and flush acknowledgements in this feature are deliberately
**synthetic policy inputs**, clearly labeled as such. These tests do not
claim real VirtIO-GPU command/response, on-screen pixels, Ring3 execution,
userspace mapping, secure GPU pinning, SMP scheduler lock or completed real
DMA retirement. Other existing CI steps test real VirtIO-GPU fences and
real Ring3 execution independently, but they are not yet integrated here.

This is a narrowly scoped ownership-accounting milestone, not a production
GUI or justification to merge any draft branches.

## Acceptance

P0 adds a mandatory real QEMU `make qemu-surface-reap-pmm-smoke` step.
No test may be skipped, retried or marked green from host-only fixtures.
Keep the existing main branch and physical disks unchanged.
