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
