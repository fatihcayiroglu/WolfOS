# ADR-0108 — Real Ring3 #UD/#PF terminal faults drain surfaces before PMM reclaim

Status: proposed, stacked on PR #335 / ADR-0107.

## Objective

On WolfOS, process termination does not occur exclusively through
voluntary INT80 EXIT. A genuine Ring3 invalid-opcode exception (#UD) or
denied supervisor-memory access (#PF) must revoke its graphics handles
before the process's PMM-owned frames can be returned. A faulted process
must not gain an easier cleanup/bypass path than a normal exit.

## Implementation

The two opt-in QEMU flavors `user-surface-ud-retire-smoke` and
`user-surface-pf-retire-smoke` inherit the existing genuine hardware
`user-invalid-opcode-retire-smoke` and `user-page-fault-retire-smoke`,
respectively. The existing hardware CPL3 guest and IDT handlers remain
unchanged.

The same feature-isolated software surface ledger and authenticated
`ProcessTable` bridge from ADR-0107 now participate in these exceptions:

1. After real process RUNNING admission and actual private CR3, the kernel
   mints one surface handle from a ProcessTable snapshot and enters
   hardware CPL3. GPU transfer/flush fence IDs are **synthetic**.
2. The independently linked ELF performs real INT80 syscalls, then either
   executes the designated invalid instruction (#UD) or attempts a denied
   supervisor address read (#PF). The existing hardware handler verifies
   authentic CPL3 provenance, the expected fault address/vector and the
   corresponding 132 or 139 exit status.
3. The shared terminal `finish_exited` restores actual boot CR3 and
   retires the CPU's address-space reservation before the new guarded
   counted process reap, exactly as for normal EXIT.
4. A pending logical GPU surface prevents the PMM lease from being
   returned. A simulated transfer acknowledgement alone is insufficient;
   simulated flush plus explicit metadata release is necessary. Only then
   can the real seven-frame process lease be reaped and the actual PMM
   allocator return to its pre-launch count.

The Python QEMU harness requires a strictly ordered, single occurrence of
boot, surface open, actual ELF CPL3 entry, expected #UD/#PF terminal marker,
surface-guarded counted reap, and final zero-leak PMM cleanup. The exact
existing #UD/#PF status and provenance expectations also remain active.

## Evidence boundaries

The CPU fault, IDT, user page permissions, CR3 restoration, process table
and physical PMM are exercised as real QEMU guest operations. This fixture
does **not** submit GPU DMA or validate hardware transfer/flush responses:
it deliberately injects synthetic fence acknowledgements into the pure
software ledger after a real terminal CPU fault. No production concurrent
GUI or Ring3-owned pixel buffers are implemented, and no real IRQ/SMP
surface lock is established.

The original user-ELF EXIT, #UD and #PF QEMU tests are left intact.
Do not merge stacked drafts to production main without owner approval.

## Acceptance

All P0 checks, including both new real-CPL3 fault-flavor smokes and the
existing mandatory real-QEMU graphics/regression suite, must pass on the
exact proposed head. No skip, retry, timeout-based success or synthetic
hardware attestation.
