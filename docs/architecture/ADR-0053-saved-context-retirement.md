# ADR-0053: Generation-safe saved Ring3 context retirement metadata

Status: **bounded metadata contract and host tests** (not wired into the production Ring3 scheduler).

## Motivation

The x86-64 PMM-owned `ActiveAddressSpace` (#202–#206) prevents a root frame release while any CPU reservation is still outstanding. A saved interrupt frame, ready-queue entry, timed wakeup or suspended Ring3 context can also reload the private root later. Counting quiescent CPUs alone is therefore insufficient.

## Decision

- Bind a `SavedContextGate<64>` to the move-only `ActiveAddressSpace` owner. Each saved resumable context occupies one slot and carries an opaque globally unique address-space generation plus monotone admission epoch. Slot reuse invalidates stale resume and revoke tokens.
- Require `register_saved_context` before a scheduler exposes a resumable saved frame; require `reserve_saved_resume` to check the matching context and reserve the destination CPU under the same exclusive coordinator lock.
- Starting retirement closes **both** future CPU admission and saved context admission. Existing saved slots remain pinned until explicitly revoked by an unsafe caller that has canceled the real queue/frame/wakeup/handoff references.
- `finish_retirement` refuses completion if **either** any CPU is still reserved/active or any saved context slot is occupied. `unsafe reclaim` requires both gates closed/retired; it still requires independent hardware, alias, and DMA proof. A dropped owner deliberately leaks frames.
- No dynamic heap allocations, no `std`, 64 bounded context slots for this first contract. Epoch wrap fails closed. Slots are **not** necessarily process IDs or the actual full scheduler capacity.

## Critical limitations

This PR introduces a testable ownership/revocation contract only. **No actual Ring3 dispatcher, saved interrupt frame, process table, runnable queue, timer wakeup, cross-core handoff, or actual QEMU CR3 switch is connected to this new gate.** Existing `reserve_cpu` is intentionally available for fresh non-saved loads and cannot automatically detect callers bypassing the saved-context gate. A caller that lies about queue cancellation or fails to register a context can still cause premature reclamation. Never treat host tests or the `Retired` phase as evidence of real memory safety.

The next production integration must:

1. Choose a genuinely globally unique lifetime generation and bind every user-context state transition and queue entry to this owner.
2. Register real saved contexts before publishing to ready/wait/timer queues; use saved-context validation + CPU reservation under one scheduler ownership lock.
3. On exit/crash, atomically prevent enqueue/wakeup, drain or invalidate in-flight handoffs, cancel saved frames, and only then revoke their exact tickets.
4. Observe each CPU's authenticated supervisor-CR3 switch and receiver-side TLB quiescence, integrate the IPI shootdown barrier, and account for aliases, device/DMA references and PCID/global translations before permitting `unsafe reclaim`.
5. Prove on real 4-vCPU QEMU that withheld dispatch and late scheduler wakeups cannot reload a reclaimed root, in addition to deterministic host tests.

## Tests

- Stand-alone host: bounded admission, generation and slot replay rejection, slot-63 mask, epoch overflow, closing barrier, pending-token drain.
- Real owner/PMM mock host integration: saved context prevents frame release even when CPU mask is empty; exact CPU reservation and saved revocation are independently required; canceled/stale token cannot reserve a CPU; retirement blocks new user resumes.
- Existing 4-vCPU CR3/IPI/INVLPG hardware gates must remain green, but their prior evidence must not be presented as proof of the new (unintegrated) scheduler contract.
