# ADR-0057: compose counted ELF preparation under one unpublished owner

Date: 2026-10-26

Status update: ADR-0058 integrates this transaction into the fixed BSP IF=0
Ring3 launcher and its terminal retirement. The original component's external
hardware safety obligations remain; other schedulers are not migrated.

## Problem

The real bounded Ring3 fixtures now share ELF-derived mapping and payload
staging, but their caller still manually allocates/releases an array and
halts on preparation errors. A reusable fallible launcher needs one owner
that retains every reserved frame across validation failures and cannot
accidentally leave a staging destructor armed after active publication.

## Decision

Add an allocation-free `ElfLaunch` coordinator over the existing immutable
image plan, `FrameBatch::acquire_count`, `ElfPageTables` and
`ActiveAddressSpace`. It keeps an immutable ELF borrow during preparation.
Its private fields and consuming type stages are:

`Reserved -> PayloadReady -> TablesReady -> unsafe publish -> ActiveAddressSpace`

The array capacity is not an allocation count. Reserve derives the exact
six/seven/eight/nine-frame prefix from supported ELF leaves. Invalid slot,
malformed ELF or insufficient capacity fails without allocator calls.
Physical-frame/placement binding runs before any destination write. If it
fails after allocation, explicit close returns the entire acquired prefix
and reports successful/failed releases. This includes a legitimately owned
physical frame zero that cannot serve as the contract's private-root identity.

Stage and table-build failures return the unchanged-phase transaction with
its lease still owned. The caller can correct metadata/buffers and retry or
abort. Aborting explicitly returns `ReleaseReport`; dropping an unpublished
transaction retains FrameBatch's best-effort reverse rollback policy. Release
failures remain allocated, are reported by explicit operations, and are never
silently retried by a destructor. Callers must treat failed rollback as an
allocator failure, not successful recovery. No PID or CPU state is published.

Only TablesReady has the consuming publication method. It transfers the
guard to the existing active owner with no CR3 write or PMM release. A refused
publication reconstructs the same staged owner. Success disarms staging
rollback by ownership transfer; active Drop retains frames in every phase.
The existing retirement/context/CPU gates and unsafe reclaim contract remain
the sole active-owner release path through this API.

## External safety boundary

Stage types record completed operations, not immutable physical snapshots.
They cannot authenticate HHDM references, prevent out-of-band table changes,
validate supervisor kernel grafts or prove hardware quiescence. Publication
is therefore unsafe: the caller must establish final complete ELF-byte,
PTE/stack/HHDM/kernel-graft admission and stable mappings, no pre-existing
CPU/context/walker/device reference, and reservation through the returned
active owner's gate for every future CR3 load. Provider ownership guarantees
remain mandatory. End physical-buffer borrows before aborting their lease.

The coordinator does not provide IRET, a scheduler, process-table admission,
an executable namespace, general ELF relocation, or a production launch API.
It is not yet called by `user_elf_run_smoke`: live migration must replace its
raw allocator and manual cleanup together, retain exact process metadata,
and prove actual CR3/context retirement. Do not merely create a staged owner
around that code and leave it armed while loading its CR3.

## Evidence

`make test` cross-compiles the public contract as a no_std x86-64 library.
Host tests run the exact coordinator and real backend callbacks with synthetic
physical IDs: all four budgets, all partial-allocation boundaries, every
prepublication abort/drop phase, failed frame/placement binding, late staging
and mapping failures with retry, explicit release-error accounting, refused
publication, one-time active transfer and active Drop retention.

Separate compiler-negative cases import that cross-compiled public API and
must fail with E0599 when Reserved or PayloadReady attempts publication.
The positive contract build ensures these are real phase-API failures rather
than missing modules or target dependencies. These checks are mandatory;
the complete historical host and genuine QEMU suite remains required.

Host CPU-ticket values here are ledger composition tests, not hardware CR3
observations or multicore acknowledgements. Existing real QEMU gates remain
independent evidence and do not prove live integration of this coordinator.
That integration is the next independently verifiable increment.
