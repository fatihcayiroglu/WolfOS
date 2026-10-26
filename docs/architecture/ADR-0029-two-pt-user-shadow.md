# ADR-0029 — Two independently backed user PTs under one directory

Date: 2026-10-26

## Decision

Keep the original one-PT ELF admission contract unchanged for all existing
real CPL3 smoke flavors, and introduce a **separate**, allocation-free
two-PT layout and shadow-map path, now also reused by a dedicated live CPL3 runner:

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
- `derive_relocated_elf_pages` constructs a fixed-capacity leaf manifest
  directly from the immutable ELF and exactly one owned physical data frame
  per LOAD/stack page; callers cannot invent VAs or permissions. It checks
  slot bounds, frame count, aliases, W^X and both PT regions before mapping.
  Host tests also admit an ELF spanning three LOAD leaves and two PTs.

## Hardware proof

The existing \`user-vm-shadow\` QEMU flavor now reuses its eight disjoint
PMM frames for an additional disconnected proof AFTER its old one-PT audit.
Five frames back two distinct PTs on opposite sides of VA \`0x600000\`;
three data frames contain genuine materialized ELF text, ELF data+BSS
and a zeroed RW+NX stack. The proof checks the ELF-to-PTE bindings, exact
data/BSS bytes, HHDM frame provenance, tampered data and executable-data
PTE rejection, unchanged physical CR3, and complete eight-frame cleanup.
It exposes \`WOLFOS_USER_TWO_PT_OK\` in the real QEMU serial evidence.

The follow-up admission gate also binds these checks in one fail-closed
`audit_two_pt_staged_image`: all five exact table frames, all 2,560 PTEs,
immutable ELF-backed RX/RW bytes, exactly one backing for every LOAD leaf
and a disjoint zeroed RW+NX stack. Host and hardware tests reject mutations
of staged bytes, forged PTE permission upgrades, duplicates and wrong
backings. Only after strict admission does the disconnected root borrow
the live Limine high-half PML4 entries. Their user privilege bits are
cleared and audited, including a test that rejects a deliberate high-half
U/S escalation before restoring the expected supervisor-only bytes.
The original CR3 remains active throughout.

The `WOLFOS_USER_TWO_PT_OK` marker additionally requires
`staged_admission=1`, `admission_tamper_denied=1`,
`kernel_supervisor=1`, `high_half_copied=1` and
`high_half_escalation_denied=1`.

## Relocatable user-slot staging (follow-up)

Real WolfOS CPL3 smoke selects a vacant *nonzero* PML4 user slot before
entering Ring3. A separate byte-derived `validate_relocated_elf_bindings`
now translates an otherwise bounded static ELF within its original low slot
into exactly one checked slot in `1..255`. Both the PML4 slot and the full
per-leaf addresses, permissions, data frames and sole stack are independently
audited. Slots 0, 256..511, an ELF spanning beyond its original 512-GiB
slot, forged shifted pointers and unsafe permission changes fail closed.

`audit_relocated_two_pt_staged_image` binds the shifted PTE locations
back to the **unshifted** immutable ELF byte sources and verifies full
RX/RW/BSS contents plus zeroed stack. The real-PMM QEMU proof chooses an
actually vacant PML4 slot from the live Limine root, populates five fresh
two-PT tables, verifies source-byte provenance and high-half inheritance,
and rejects a deliberately corrupted data byte. The QEMU marker is
`WOLFOS_USER_RELOCATED_TWO_PT_OK`. Hardware CR3 remains unchanged and
the same eight PMM frames are reaped.

The `user-vm-shadow` and relocated shadow acceptance flavors remain
**disconnected proofs**: their physical CR3 does not change. Independently,
the dedicated `user-elf-two-pt-run-smoke` QEMU flavor now exercises a truly
live two-PT Ring3 ELF process. It selects a vacant PML4 user slot, leases
five page-table frames and three data frames from PMM, derives RX text,
RW+NX data/BSS and RW+NX stack leaves from the ELF, and requires exact
PTE/byte-source/HHDM audits before grafting supervisor-only kernel mappings.
With interrupts disabled on the single BSP it switches hardware CR3,
IRETs into CPL3, executes 22 INT80 syscalls, restores boot CR3 on exit,
and releases all eight owned frames. The live evidence is
`WOLFOS_ELF_TWO_PT_ENTER` with `derived_pages=1 owned_frames=8` plus the
existing CPL3 exit/retirement markers. This proof runs the original
**two-LOAD-leaf** static ELF; the three-LOAD-leaf manifest is host-tested
and is **not yet exercised by the live QEMU launcher**.

All preexisting one-PT ELF execution / ProcessTable / Shield tests remain
unchanged and must pass. No physical disk is touched.

## Security boundary / next work

The **disconnected** two-PT proof remains a BSP/IF=0 shadow test, but a
separate dedicated smoke path now executes an admitted image under a real
relocated two-PT CR3. Neither is a production executable loader or a
general-purpose multi-address-space process model. Frame lease and
high-half borrowing are intentionally BSP-scoped; only the fixed two-LOAD
ELF has been run on hardware. Next steps include executing three-LOAD
images after generalized per-leaf materialization, guard pages and dynamic
frame bookkeeping, multiple PD/PT regions, trusted-package and untrusted
ELF loading, real process lifecycle integration, device drivers, persistent
storage, and graphical user-facing permissions.
