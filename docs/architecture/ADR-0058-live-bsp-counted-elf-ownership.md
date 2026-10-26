# ADR-0058: transfer and retire the real bounded BSP ELF frame owner

Date: 2026-10-26

## Problem

ADR-0057 provided a tested preparation transaction, but the live single-BSP
ELF fixtures still manually allocated and freed physical frames. Their PID
metadata did not consume staging ownership before CR3 activation or require
an active-owner CPU ticket before terminal reclamation.

## Decision

Use `ElfLaunch<Reserved -> PayloadReady -> TablesReady>` in every existing
six/seven/eight/nine-frame `user_elf_run_smoke` flavor, including EXIT(42),
#UD/#PF, sequential PIDs, RamFS/VFS and user-copy/file-I/O variants. Preserve
the independent fixture layout, two-PT ELF/HHDM admission, exact PTE checks
and sanitized shared kernel graft. Independently audit every LOAD/BSS/padding
byte and all stack bytes for every layout before unsafe publication.

The sole static PMM provider is exclusively borrowed by the transaction and
then its active owner. A busy flag forbids reborrowing until reclamation
consumes that owner. One BSP-only IF=0 slot stores the active owner and its
CPU ticket. IA32_APIC_BASE authenticates the BSP bit; PCID must be disabled.
Private user mappings are non-global. APs never receive these private roots.

Reserve the exact PID lease, then consume the transaction into an active owner
and reserve its CPU ticket **before** the first CR3 write. Confirm activation
against the BSP's actual CR3. Publication refusal cancels the unpublished READY
PID before clearing cached references and explicitly aborting the transaction.
The PID registry and atomic user-copy views only mirror ownership; neither may
independently free frames. Unexpected invariant failures halt closed; this is
not a general recoverable launch-error API.

On terminal EXIT or authenticated fault, take the canonical owner and close
admission. Require retirement to refuse an outstanding CPU and require an
acknowledgement using the actual still-private CR3 to fail. PMM accounting
must still include the whole lease. Restore and reread trusted boot CR3,
completing local non-global invalidation, then acknowledge the exact ticket.
Reap the PID, verify its complete ordered lease against the owner and revoke
all cached user-copy/return references. Finish retirement and consume the
owner through unsafe `reclaim`, checking every release and the PMM baseline.
No separate raw frame-free loop remains.

No old trap frame can return: terminal paths never IRET, and this IF=0 path
has no saved scheduler contexts, queued resumes, outstanding walkers or DMA.
The trap stack and borrowed boot kernel tables remain resident outside the
private lease. These are concrete obligations of this caller, not evidence
that metadata alone proves hardware quiescence.

## Preparation stack regression

The first real PID1-fault/PID2 regression exposed preparation overflowing the
16-KiB TSS.RSP0 stack and zeroing adjacent expected-RSP0 metadata. Actual CR3,
user entry and CS were correct; the next trap observed expected RSP0 zero.
Do not enlarge that trap stack or relax its bounds checks. After full PID1
reap, permanently abandon its trap path and CALL the next preparation from a
separate aligned 64-KiB supervisor stack. An explicit C ABI supplies the stack
handoff contract. Check its lower canaries and the original TSS preflight
before publication. This static preparation stack is bounded BSP machinery;
it is not a general per-process kernel-stack allocator or hardware guard page.

## Verification

Every live launch first reserves real PMM/HHDM pages, presents a wrong final
LOAD backing, requires unchanged bytes and unpublished PID metadata, then
explicitly aborts and verifies the exact budget and PMM baseline. The normal
launch uses a fresh transaction. Two-PT variants additionally retain their
previous rejection/retry probe on the same staged lease.

All seven affected QEMU runners require exact rollback, active-owner,
premature-retirement refusal and reclaim observations for every PID, ordered
around actual guest entry and exact cleanup. Sequential PID2 also requires the
checked preparation-stack proof. Parser regressions reject missing, duplicated,
decorated, altered, wrongly ordered or wrong-generation observations. Existing
syscall, fault, privilege, no-leak and debug-exit checks remain mandatory.

Local validation ran all 67 workflow Make targets (136 Python and 854 Rust
test executions, then all 66 QEMU targets). Supplemental OVMF validation ran
the unchanged full validators on all 13 affected Ring3 ISO flavors, including
the four budgets, EXIT(42), #UD/#PF, fault recovery, sequential PIDs and
file/user-copy variants. Each required debug-exit 33. The separate four-vCPU
UEFI CPL0 retirement control also passed. OVMF was read-only; these results
cover QEMU firmware variants, not real hardware or general UEFI compatibility.

## Limits and next work

This establishes ownership on the fixed single-BSP IF=0 launcher only. It
does not migrate the separate timer/cooperative Ring3 schedulers, cancel real
saved resumable contexts, retire users on multiple CPUs, support PCID/private
global translations or establish real-hardware firmware compatibility. The separate real
four-vCPU retirement and INVLPG/IPI controls remain regression evidence for
their own bounded scenarios. Next connect counted owners to saved-context
scheduler admission under one coordinator, then exercise remote retirement
with withheld acknowledgements before any shared physical-frame release.
