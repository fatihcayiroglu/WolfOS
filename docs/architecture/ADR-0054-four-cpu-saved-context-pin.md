# ADR-0054: Four-CPU CR3 departure with a withheld saved-context token

Status: **isolated CPL0 QEMU evidence**, not an end-to-end Ring3 scheduler proof.

## Context

ADR-0053 connected the no-heap, generation-tagged `SavedContextGate<64>`
to the PMM-backed `ActiveAddressSpace` owner and verified refusal to
retire when a saved-return slot is still occupied. Its evidence was from
host mocks. The four-vCPU hardware smoke previously exercised only
CPU reservations and real CR3 departures, leaving saved-context
completion untested in a live multi-core execution.

## Procedure

In the existing isolated four-vCPU QEMU smoke:

1. The BSP publishes one owned private PML4 cloned from the resident
   supervisor PML4; borrowed children remain pinned.
2. All three APs reserve their CPUs and load the private root. The BSP
   registers a **synthetic saved-return token** under the same exclusive
   owner ledger before loading the private root itself.
3. The BSP closes both admission gates while APs remain active. CPU and
   saved-context resume attempts are refused.
4. The BSP and the first two APs restore trusted supervisor CR3 and
   acknowledge; the last AP deliberately remains active, so retirement
   refuses with `OutstandingCpus`.
5. The last AP restores supervisor CR3 and acknowledges. With all four
   CPU masks now empty, `finish_retirement` still refuses with
   `OutstandingContexts` and no PMM frame has been released.
6. An attempted resume with the recorded saved ticket is refused with
   `Context(WrongPhase)` after retirement admission is closed.
7. The BSP explicitly revokes the **synthetic** token (no actual
   Ring3 stack/queue/timer/wakeup existed), finishes retirement, and only
   then performs the preexisting independently justified unsafe
   reclamation. PMM baseline is restored exactly.

Every success marker now includes `saved_context_pinned=1` and is
matched byte-for-byte in the QEMU evidence parser. Offline tests reject
missing or corrupted saved-context markers for both the CPU and owner
proofs. No skip, downgrade or reinterpretation of existing QEMU gates.

## Security boundary

This is an important hardware/metadata composition check. It does
**not** execute a Ring3 saved return, cancel an actual dispatcher
queue, prove timer/event wakeup cancellation, or establish general
process teardown. The unsafe synthetic revocation is justified only
because the probe never creates a real saved user frame or queue entry.
Real Ring3 teardown will require the actual runqueue, event wait gate,
user context bank and per-process PMM owner to share a synchronized
admission/revocation protocol, followed by authenticated multi-CPU
TLB quiescence.

## Acceptance

- New exact 4-vCPU QEMU evidence with all prior CR3/PMM proofs, plus
  held saved-context pin and explicit revocation.
- Parser rejects forged/missing `saved_context_pinned` fields.
- Existing host and QEMU regression suites remain green.
