# ADR-0028 — Bounded byte-derived ELF launch-page layout

Date: 2026-10-26

## Decision

Introduce `user_elf_launch_layout::plan_static_image` as an allocation-free
parser-to-loader contract for strict static x86-64 ET_EXEC files. It consumes
untrusted ELF bytes using the existing fail-closed ELF64 preflight and derives:

- Every 4-KiB PT_LOAD virtual leaf, its owning program-header index and
  exact RX or RW+NX permission;
- A separate RW+NX stack immediately after the highest PT_LOAD page, even
  when ELF headers are not sorted by address;
- A hard ceiling of three LOAD leaves plus one stack leaf;
- A single shared 2-MiB page-table region so the current four-table-frame
  hierarchy can map the entire image.

An oversized image, invalid ELF, cross-table layout, boundary-crossing stack,
or noncanonical stack address is rejected **before** PMM allocation or any
byte copy. It never trusts a user-declared stack location.

The existing genuine CPL3 single-BSP QEMU path now asks this layout for
the source PT_LOAD page of each backing frame, materializes each leaf through
the checked byte-copy routine, and derives leaf PTE permissions and indices
from the same layout. The test fixture still requires two LOAD pages and
exactly seven fresh owned frames; existing ProcessTable, high-half isolation,
CR3 reaping, WolfOS Shield and cleanup gates remain enforced.

## Validation

Host tests cover separated RX/data+BSS pages, an additional fully BSS-only
LOAD page, unordered ELF headers, too many LOAD leaves, LOADs in different
2-MiB tables, a stack crossing the table boundary or canonical user end,
malformed ELF, and attempted writable+executable segment. The normal
`make test` and the full QEMU workflow run on the exact PR head.

## Scope and next steps

This is **not** a general untrusted executable launcher. The genuine Ring3
smoke still runs a separately kernel-approved, independently linked ELF from
a fixed fixture, with a single 2-MiB PT and one-page stack. Additional runtime
frames, a general multi-table VMM, package signatures, dynamic linking,
multiple concurrent live images and an end-user consent UI are still needed.
The layout itself does not perform signed-image attestation, frame provenance,
heap allocation, memory mapping, user execution or physical disk writes.

## Counted PMM staging and exact ownership (2026-10-26)

The strict byte-derived launch budget now supplies the count actually requested
by the real isolated CPL3 smoke's PMM allocation loop. Existing hardware
flavors still enforce exact 7/8/9-frame layouts **before** allocation because
the fixed-capacity process table and staging arrays cannot safely admit
arbitrary counts. This is a runtime input to the PMM loop, not yet a generic
variable-size live Ring3 process.

For future variable-size loaders, `FrameBatch::acquire_count` can stage
1 through `N` frames in a fixed-capacity no-heap array. Zero and oversized
counts reject without touching PMM; failed partial acquisitions release only
the acquired prefix in reverse order. The unused zero tail is never considered
owned. `ActiveAddressSpace::publish` validates precisely the leased prefix,
preserves staged rollback on refusal, and only reclaims that prefix after its
explicit retirement and external quiescence proof. The legacy full-size
process-table comparison rejects shorter padded leases.

Host fault-injection tests cover counts 6/7/8/9, zero/oversized bounds,
partial exhaustion, early Drop, explicit release failures, rejected publication
and post-retirement exact reclaim. Existing QEMU tests must continue to
demonstrate genuine user execution, restored supervisor CR3 and zero PMM leaks.

Still missing: integrating variable-count ownership into the production Ring3
process record, varying the number of PTs and LOAD destinations in one live
runner, and authenticating cross-CPU teardown for arbitrary executable images.
