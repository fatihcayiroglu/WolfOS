# ADR-0055: Serialized Ring3 runqueue/saved-context retirement bridge

Status: **real Ring3RunQueue policy integration + isolated four-vCPU CPL0
hardware composition**. Not connected to the production Ring3 trap handler.

## Problem

ADR-0053 and ADR-0054 introduce a generation-safe saved-context pin on
`ActiveAddressSpace` and show in QEMU that an occupied context blocks frame
reclamation after all CPUs restore supervisor CR3. But the Ring3 scheduler
also holds generation-tagged ready/blocked/exit records and one-use event
wait tickets. These policy objects need a coordinated cancellation protocol.

## Contract

`Ring3SavedBinding` associates one exact generation-tagged
`Ring3RunQueue::Handle` with one `ActiveAddressSpace` saved-context
ticket. All operations require an **external exclusive lock across the
actual queue and address-space owner**; this module does not implement that
runtime lock.

- `attach`: verify the exact queue incarnation is READY or BLOCKED and
  register its saved-context pin in the owner. The external trusted caller
  is responsible for authenticating the process PID, CR3 ownership and
  actual saved GPR/IRET/FX state before making this binding visible.
- `wake_for_event`: reject a wrong queue generation, wrong event ticket,
  closed owner admission, or stale context before changing blocked state.
  The queue's existing one-use wait sequence remains authoritative.
- `start_next`: stage a copy of the actual queue, ensure the selected
  handle matches the binding, and reserve the exact context's CPU before
  committing the policy dispatch. Any error leaves the queue unchanged;
  successful CPU reservations remain pinned until authenticated cleanup.
- `unsafe cancel`: stage a READY/BLOCKED cancellation, then revoke the
  exact owner context ticket, then publish the canceled queue state as
  one serialized policy operation. The caller must already have canceled
  the real saved trap frame, event/timer wakeups and CPU handoffs.
- `unsafe retire_exited`: for a trusted running-process EXIT trap, require
  the queue record to be EXITED before revoking its saved-context pin.
  Existing queue `reap` remains a separate post-PMM-reclamation step.

These functions do not save registers, switch CR3/TSS/FX, issue IPIs,
authenticate IRQ/event sources, allocate memory, cancel actual wakeup
backends or implement scheduler synchronization. Bypassing the bridge via
old unguarded APIs remains possible until every production dispatch and
wake path is migrated. These limitations must not be hidden.

## Evidence

- Exact real `Ring3RunQueue` host tests with PMM mock owner: late event
  wake after retirement leaves queue unchanged; cancellation prevents
  event resurrection; wrong selected handle and busy CPU cannot partially
  commit a dispatch; EXITED context blocks retirement until unsafe
  cancellation proof and explicit revocation.
- Four actual QEMU CPUs reserve and load a cloned PML4. A synthetic
  BLOCKED queue record and its one-use wait ticket bind to the same
  owner. After all actual CPUs restore supervisor CR3, frame retirement
  still fails for `OutstandingContexts`. A late event wake is rejected,
  exact queue cancellation revokes the token, and only then may the
  root frame be reclaimed.
- Exact QEMU evidence includes `saved_context_pinned=1`,
  `runqueue_cancel=1` and `late_wake_rejected=1`, enforced by offline
  parser mutation cases. `ring3=0` remains explicit.

## Next production step

Connect the binding to actual Ring3 timer/syscall trap transitions and
`UserContextBank` with a shared lock and authenticated saved frames;
atomically close event/timer admission during exit, drain in-flight AP
handoffs, enforce owner+queue generation equality, and prove late
wakeups cannot reload a reclaimed CR3 on actual multi-CPU QEMU.
