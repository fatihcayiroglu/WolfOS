# ADR-0029 — Two independently backed user PTs under one directory

Date: 2026-10-26

## Decision

Keep the original one-PT ELF admission contract unchanged for all existing
real CPL3 smoke flavors, and introduce a **separate**, allocation-free
two-PT layout and shadow-map path:

- \`plan_two_pt_image\` derives each static PT_LOAD and RW+NX stack leaf
  from strictly checked ELF64 bytes. It allows at most three LOAD leaves
  plus one stack leaf, spanning no more than two 2-MiB page-table regions
  in the same 1-GiB PDPT directory. Invalid cross-directory, third-table
  and user-space boundary cases are rejected before any PMM acquisition.
- \`user_vm_two_pt\` maps up to eight disjoint user leaves with five
  explicitly owned table frames (PML4, PDPT, PD, PT0, PT1), all within
  one PML4/PDPT path. It checks all physical-frame aliases, user VA bounds,
  duplicate virtual addresses, NX and W^X before any PTE mutation.
- Each parent and PT leaf is independently validated. An exact audit of all
  **2,560** entries detects an extra mapping, permission upgrade, hidden
  alias, different frame or nonzero high-half PML4 entry.
- \`validate_elf_bindings\` and \`audit_elf_bindings\` verify all advertised
  page VAs and RX/RW+NX flags against the original immutable ELF bytes,
  including a separate NX stack, rather than trusting caller metadata.

## Hardware proof

The existing \`user-vm-shadow\` QEMU flavor now reuses its eight disjoint
PMM frames for an additional disconnected proof AFTER its old one-PT audit.
Five frames back two distinct PTs on opposite sides of VA \`0x600000\`;
three data frames contain genuine materialized ELF text, ELF data+BSS
and a zeroed RW+NX stack. The proof checks the ELF-to-PTE bindings, exact
data/BSS bytes, HHDM frame provenance, tampered data and executable-data
PTE rejection, unchanged physical CR3, and complete eight-frame cleanup.
It exposes \`WOLFOS_USER_TWO_PT_OK\` in the real QEMU serial evidence.

All preexisting one-PT ELF execution / ProcessTable / Shield tests remain
unchanged and must pass. No physical disk is touched.

## Security boundary / next work

This is a **shadow-only**, BSP/IF=0 validation of the two-PT hierarchy,
not a general-purpose multi-address-space PMM or live Ring3 launcher.
The runtime ELF hello still uses its previously audited one-PT path;
new trusted code must pin PMM frames, prove byte-source immutability,
audit higher-half mappings and process ownership, and perform controlled
CR3/IRET handoff before any new two-PT image is actually executed.
Future work includes more PD/PT regions, guard pages, dynamic frame
bookkeeping, ELF loading from trusted packages and signed manifests,
device drivers, persistent storage, and graphical user-facing permissions.
