# ADR-0018: 256 real saved-context kernel TCBs on BSP

Status: Proposed until branch, PR and merged-main GitHub Actions pass.

## Scope
- Scale PR #19's shared indexed Rust entry / x86-64 RSP+callee-saved
  register context switching from 16 to exactly 256 distinct TCBs.
- Each TCB owns an aligned static 16 KiB kernel stack. Compile-time
  assertions cap the entire stack bank at 4 MiB and enforce the existing
  256-TCB prototype cap and unique u8 event-index representation.
- BSP maintains the cooperative ready queue, runs each task four
  times on its own stack, and delays the blocked task's explicit wake.
- Verify 1024 task dispatch events, 2048 context switches,
  767 yields, exactly one block/wake, 256 finishes, every task's
  independent digest, RSP-in-owner-stack check and stack canary.
- Keep the existing 256 SMP *state-machine* TCB test intact. Do not
  incorrectly claim its per-CPU scheduler is already executing these
  separate real saved-RSP contexts on all cores.

## Security and limitations
- BSP-only. APs run previously validated work and then park before
  context switching begins; no AP context migration or work stealing.
- Boot-only static memory; no reclamation, stack guard pages, FPU/XSAVE,
  TLS/GS, interrupts, preemption, userspace or asynchronous blocking.
- Stack bank limit is a bootstrap engineering decision, not a WolfOS
  production RAM or task-count limit.
- Invalid initial or resumed context causes fail-stop / failed test.
- QEMU tests only. Never write to the physical host disks.

## Acceptance
- make test: source/ABI contracts
- make smoke: 256 contexts, 1024 events, 2048 RSP switches, 4 MiB
  static stack bank and valid completion marker
- make topology-smoke: four vCPUs boot with intact SMP tests and
  BSP-local real TCB context verification
- make exception-smoke, make paging-fault-smoke: no regressions
- Both push and pull_request checks green before merge
