# ADR-0056: share an ELF-derived one/two-PT table builder

Date: 2026-10-26

## Problem

After PR #254, independently linked six/seven/eight/nine-frame images really
execute in CPL3 and retire through counted process leases. However, the
hardware runner still chooses its table budget by compile-time flavor, writes
one-PT tables inline at fixture indices, and uses a separate two-PT writer.
This prevents a reusable launch path from choosing a hierarchy from the ELF.

## Decision

`plan_bounded_with_budget` derives the actual unique 2-MiB PT regions from all
validated ELF LOAD leaves **and** the separate RW/NX stack. The exact table
budget is three upper-level frames plus one frame for each used PT. The
existing fixed one/two-PT planning APIs retain their contracts for callers
that explicitly require those bounds; no rejection in those APIs is relaxed.

`ElfPageTables::bind` reparses immutable ELF bytes and seals an ordered mapping
recipe against an exact physical frame slice. Callers cannot supply or mutate
its VAs, leaf permissions, region ordering or table count. Construction rejects
wrong lease lengths, padded extra frames, duplicates across every table/leaf,
unaligned/zero/out-of-range frames, unsupported directories and invalid slots.
The source image must fit PML4 slot zero; placement uses a chosen empty slot
1..255. The entry and stack pointer must stay in the canonical user half.
This placement contract is not a general ET_EXEC relocation implementation.

One `TableBuffers` interface supplies four actual table buffers and an optional
fifth. The optional PT must exactly match the ELF-derived hierarchy. Before
any table write, populate checks **every** destination entry is zero. A dirty
last entry or wrong bank shape leaves the whole bank unchanged. It computes
the mapping from validated ELF leaves rather than fixture PD/PT indices.
Parent permissions admit the fresh writable stack; each leaf independently
enforces user accessibility, W^X, RX text and the NX stack/data contract.

The exact audit checks all 2,048 or 2,560 entries before supervisor grafting,
including unmapped gaps and empty high-half slots. The recipe owns no PMM
allocation or physical pointer, switches no CR3, and authorizes no execution
or retirement. The caller must prove PMM ownership, exclusive HHDM buffer
provenance, payload/BSS bytes, trusted kernel grafts and hardware quiescence.

## Actual execution integration

All independently linked single-process CPL3 ELF flavors now obtain their
budget through automatic planning and populate/audit through this common
mapper. One-PT fixture-index writes are removed. Two-PT flavors preserve their
independent full ELF/physical-frame/byte/HHDM admission and cardinality checks
after the common population; their old standalone shadow writer remains
available to its existing independent tests. Source kernel graft checks,
actual CR3 observation, active-root reap refusal, strict native syscalls,
EXIT/fault provenance and counted reverse-order release remain mandatory.

The runner requires one exact `WOLFOS_ELF_TABLE_PLAN_OK` proof after boot and
before its real private-CR3 entry record for each expected 6/7/8/9-frame image.
Missing, duplicate, decorated, reordered or incorrect-budget proofs fail.
The prior hardware entry, permission, syscall, exit, fault and exact-cleanup
evidence remains required. No CI gate is removed or made optional.

Host tests independently walk the resulting physical table pointers, exercise
nonfixture PD indices and reversed program-header order, cover a second PT
needed solely by the stack, validate every physical-alias pair in a nine-frame
lease, corrupt permissions/parents/gaps, and preserve addresses above 64 GiB.
These metadata tests are complemented by the four existing real CPL3 ELFs.

## Limits and next dependency

At most three LOAD pages plus one fresh stack, two PT regions and one 1-GiB
directory remain supported. The test runner still checks its specific linked
guest symbols and syscall sequence; OWNED storage and payload checks retain
fixture-specific controls. Image materialization has separate one/two-PT
paths, and the process allocator is not yet a reusable fallible launch
transaction. This is a shared mapping mechanism, not a production arbitrary
ELF loader, dynamic linker, heap, scheduler or general process manager.

Next: bind materialization buffers and exact counted PMM staging to the same
immutable plan, preserve rollback on every prepublication failure, then offer
a reusable launch transaction without duplicating fixture assumptions.

## 2026-10-26: bind one-PT ELF payload bytes to the same checked recipe

The shared `ElfPageTables` recipe now also exposes a no-heap,
pre-publication `stage_load_and_stack` operation for exclusively borrowed,
caller-owned PMM backings. It rederives the validated image layout, checks
the exact ELF leaf count, checks **every** expected frame identity (including
the independently zeroed stack), checks **every** owned destination is clean,
and prevalidates all materialization source ranges before copying any page.
Wrong last-page provenance, a stale or changed ELF layout, dirty backing
pages and malformed source images leave every destination unchanged.

The real one-PT six- and seven-frame Ring3 paths use this common recipe
rather than their earlier open-coded per-leaf copy loop. The separate
existing two-PT stager and its full audit retain their established
eight/nine-frame hardware contracts until they can be converged safely.

Independent host tests check the bounded six/seven/eight/nine-frame
materialization layouts and their exact preflight-derived PMM counts,
negative last-leaf/stack failures, and rollback on a failed partial PMM
allocation or rejected prepublication staging. A staged
`FrameBatch` is still never an active CR3 owner; no memory is reclaimed
from an active CPU by this new API.

**Remaining work:** bind this stage to a reusable ownership-transfer
transaction, including independently authenticated HHDM provenance, a
complete final byte/PTE audit, and safe verified retirement/quiescence.
This change alone is not a general process loader.
