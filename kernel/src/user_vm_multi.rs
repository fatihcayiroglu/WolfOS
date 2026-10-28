//! P2: bounded mixed RX / RW+NX pages in ONE disconnected x86-64 root.
//!
//! A fixed bank of four PMM-owned page-table frames (PML4/PDPT/PD/PT)
//! supports up to four distinct 4-KiB pages within ONE 2-MiB region.
//! The caller owns every physical frame and supplies four HHDM-mapped,
//! freshly zeroed page tables. No memory allocation or CR3 modification.
//!
//! All validation happens BEFORE the first table write. Every audit checks
//! ALL 2048 entries, including every unused PT leaf and the high half.
//! This is not a general multi-PT VMM, a runnable CR3, or Ring 3 execution.

use crate::elf64_preflight::{preflight, ElfError, ImagePlan, PAGE_BYTES, USER_MIN, USER_END};
use crate::elf64_page_image::{audit_materialized_batch, audit_zeroed_stack, PageAuditError, PAGE_SIZE};
use crate::user_vm_layout::{
    indices, Indices, ENTRY_COUNT, NX, PRESENT, USER, WRITABLE,
};

pub const MAX_PAGES: usize = 4;
pub const TABLE_FRAMES: usize = 4;
const PHYS_END: u64 = 1 << 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserPage {
    pub virtual_address: u64,
    pub physical_frame: u64,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MultiError {
    EmptyOrOversized,
    InvalidPhysicalFrame,
    AliasedPhysicalFrame,
    InvalidVirtualPage,
    DifferentPageTable,
    DuplicateVirtualPage,
    WriteExecute,
    DirtyDestination,
    MismatchedLayout,
}

fn physical_ok(p: u64) -> bool {
    p != 0 && p & (PAGE_BYTES - 1) == 0 && p < PHYS_END
}

fn validate(
    tables: &[u64; TABLE_FRAMES],
    pages: &[UserPage],
) -> Result<(Indices, bool), MultiError> {
    if pages.is_empty() || pages.len() > MAX_PAGES {
        return Err(MultiError::EmptyOrOversized);
    }
    let mut seen_phys = [0u64; TABLE_FRAMES + MAX_PAGES];
    for (i, phys) in tables.iter().copied().enumerate() {
        if !physical_ok(phys) { return Err(MultiError::InvalidPhysicalFrame); }
        if seen_phys[..i].contains(&phys) { return Err(MultiError::AliasedPhysicalFrame); }
        seen_phys[i] = phys;
    }

    let mut first: Option<Indices> = None;
    let mut any_writable = false;
    for (n, page) in pages.iter().enumerate() {
        if !physical_ok(page.physical_frame) {
            return Err(MultiError::InvalidPhysicalFrame);
        }
        if seen_phys[..TABLE_FRAMES + n].contains(&page.physical_frame) {
            return Err(MultiError::AliasedPhysicalFrame);
        }
        seen_phys[TABLE_FRAMES + n] = page.physical_frame;
        if page.writable && page.executable {
            return Err(MultiError::WriteExecute);
        }
        let idx = indices(page.virtual_address)
            .map_err(|_| MultiError::InvalidVirtualPage)?;
        if let Some(first) = first {
            if idx.pml4 != first.pml4 || idx.pdpt != first.pdpt || idx.pd != first.pd {
                return Err(MultiError::DifferentPageTable);
            }
        } else {
            first = Some(idx);
        }
        if pages[..n].iter().any(|old| old.virtual_address == page.virtual_address) {
            return Err(MultiError::DuplicateVirtualPage);
        }
        any_writable |= page.writable;
    }
    Ok((first.expect("nonempty validated pages"), any_writable))
}

fn parent_flags(any_writable: bool) -> u64 {
    PRESENT | USER | if any_writable { WRITABLE } else { 0 }
}

fn leaf_flags(page: &UserPage) -> u64 {
    PRESENT | USER
        | if page.writable { WRITABLE } else { 0 }
        | if page.executable { 0 } else { NX }
}

fn expected(table: usize, index: usize, indices: Indices,
    tables: &[u64; TABLE_FRAMES], pages: &[UserPage], writable: bool,
) -> u64 {
    let flags = parent_flags(writable);
    match table {
        0 if index == indices.pml4 => tables[1] | flags,
        1 if index == indices.pdpt => tables[2] | flags,
        2 if index == indices.pd => tables[3] | flags,
        3 => pages.iter().find(|page|
            (page.virtual_address >> 12 & 511) as usize == index
        ).map_or(0, |page| page.physical_frame | leaf_flags(page)),
        _ => 0,
    }
}

/// A bounded ELF-to-private-PTE contract. All PT_LOAD pages, including
/// fully BSS-only ones, must have exactly one matching physical leaf; the
/// additional user stack must be a distinct RW+NX page outside every LOAD.
/// No extra user virtual pages, permission upgrades, frame/table aliases
/// or cross-PT roots are accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfBindingError {
    Image(ElfError),
    TooManyPages,
    StackInvalid,
    MissingOrExtraPage,
    PermissionMismatch,
    PhysicalOrRoot(MultiError),
}

/// Pure pre-installation validation: parse original immutable ELF bytes,
/// derive exact 4KiB page requirements and compare to a proposed mapping.
/// No table writes, PMM allocations, HHDM copies or CR3 changes.
/// The caller must map/pin exactly the audited frames and recheck source
/// bytes before hardware execution.
pub fn validate_elf_bindings(
    image: &[u8],
    stack_page: u64,
    tables: [u64; TABLE_FRAMES],
    pages: &[UserPage],
) -> Result<ImagePlan, ElfBindingError> {
    let plan = preflight(image).map_err(ElfBindingError::Image)?;
    let end = stack_page.checked_add(PAGE_BYTES)
        .ok_or(ElfBindingError::StackInvalid)?;
    if stack_page & (PAGE_BYTES - 1) != 0
        || stack_page < USER_MIN || end > USER_END
    {
        return Err(ElfBindingError::StackInvalid);
    }

    // Reject a huge LOAD before walking its pages. All valid page counts
    // fit the same fixed four-leaf PMM hierarchy as the stack.
    let mut required: [Option<(u64, bool, bool)>; MAX_PAGES] = [None; MAX_PAGES];
    let mut count = 0usize;
    for seg in plan.segments[..plan.len].iter().flatten() {
        let num = seg.page_end.checked_sub(seg.page_start)
            .ok_or(ElfBindingError::TooManyPages)? / PAGE_BYTES;
        if num == 0 || num > (MAX_PAGES - 1 - count) as u64 {
            return Err(ElfBindingError::TooManyPages);
        }
        for k in 0..num {
            required[count] = Some((
                seg.page_start + k * PAGE_BYTES, seg.writable, seg.executable
            ));
            count += 1;
        }
    }
    if required[..count].iter().flatten().any(|(va, _, _)| *va == stack_page) {
        return Err(ElfBindingError::StackInvalid);
    }
    required[count] = Some((stack_page, true, false));
    count += 1;
    if pages.len() != count {
        return Err(ElfBindingError::MissingOrExtraPage);
    }
    // Every virtual page must occur exactly once, with its RX/RW+NX
    // permissions matching the verified PT_LOAD plan or the stack.
    for page in pages {
        let Some((_, writable, executable)) = required[..count].iter()
            .flatten().find(|(va, _, _)| *va == page.virtual_address)
        else { return Err(ElfBindingError::MissingOrExtraPage) };
        if page.writable != *writable || page.executable != *executable {
            return Err(ElfBindingError::PermissionMismatch);
        }
    }
    // The bounded VMM independently validates physical-frame uniqueness,
    // 4-KiB alignment, canonical user range and one 2-MiB PT scope.
    validate(&tables, pages).map_err(ElfBindingError::PhysicalOrRoot)?;
    Ok(plan)
}

/// Strict post-install audit bound to the original ELF bytes, not merely
/// to a caller-supplied page list. Fail closed if the byte-derived PT_LOAD
/// layout, stack permissions, PTE flags, physical frame ownership or ANY
/// hidden high-half/unused shadow entry differs.
///
/// This is an offline audit of a disconnected root. The hardware CR3,
/// actual frame contents and loader-byte immutability remain caller-owned.
pub fn audit_elf_bindings(
    image: &[u8],
    stack_page: u64,
    pml4: &[u64; ENTRY_COUNT],
    pdpt: &[u64; ENTRY_COUNT],
    pd: &[u64; ENTRY_COUNT],
    pt: &[u64; ENTRY_COUNT],
    tables: [u64; TABLE_FRAMES],
    pages: &[UserPage],
) -> Result<ImagePlan, ElfBindingError> {
    let plan = validate_elf_bindings(image, stack_page, tables, pages)?;
    audit(pml4, pdpt, pd, pt, tables, pages)
        .map_err(ElfBindingError::PhysicalOrRoot)?;
    Ok(plan)
}

/// Fail closed on the FIRST missing proof in a prospective ELF image:
/// actual shadow PTE bytes, exact source-derived LOAD page coverage, exact
/// owned PMM page contents, and zeroed one-page user stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadyImageError {
    Mappings(ElfBindingError),
    MissingOrUnexpectedLoadPage,
    Bytes(PageAuditError),
    DirtyStack { offset: usize },
}

/// Single read-only pre-handoff verification for a bounded disconnected
/// ELF64 user root. No heap, mappings, CR3 writes or code execution.
///
/// The trustworthy caller must serialize/pin original ELF bytes, all owned
/// PMM frames and the four shadow tables during the audit. A successful
/// result does NOT authorize a dynamic scheduler or hardware IRET by itself.
pub fn audit_ready_elf_image<const N: usize>(
    image: &[u8],
    stack_page: u64,
    tables: [u64; TABLE_FRAMES],
    mapped_pages: &[UserPage],
    pml4: &[u64; ENTRY_COUNT],
    pdpt: &[u64; ENTRY_COUNT],
    pd: &[u64; ENTRY_COUNT],
    pt: &[u64; ENTRY_COUNT],
    requests: [(&crate::elf64_preflight::LoadSegment, u64); N],
    contents: [&[u8; PAGE_SIZE]; N],
    stack_bytes: &[u8; PAGE_SIZE],
) -> Result<ImagePlan, ReadyImageError> {
    let plan = audit_elf_bindings(
        image, stack_page, pml4, pdpt, pd, pt, tables, mapped_pages,
    ).map_err(ReadyImageError::Mappings)?;

    // Reject an incomplete/mismatched content audit. Exact PTE bindings
    // alone do not prove that every file-backed leaf was initialized.
    let mut expected_count = 0usize;
    for segment in plan.segments[..plan.len].iter().flatten() {
        let pages = (segment.page_end - segment.page_start) / PAGE_BYTES;
        for index in 0..pages {
            let va = segment.page_start + index * PAGE_BYTES;
            if !requests.iter().any(|(requested_segment, requested_va)|
                *requested_va == va && **requested_segment == *segment
            ) {
                return Err(ReadyImageError::MissingOrUnexpectedLoadPage);
            }
            expected_count += 1;
        }
    }
    if expected_count != N {
        return Err(ReadyImageError::MissingOrUnexpectedLoadPage);
    }

    audit_materialized_batch(image, requests, contents)
        .map_err(ReadyImageError::Bytes)?;
    audit_zeroed_stack(stack_bytes)
        .map_err(|offset| ReadyImageError::DirtyStack { offset })?;
    Ok(plan)
}

/// Install a fixed set of pages in an EMPTY 4-level shadow hierarchy.
/// Parent W bit is set if any leaf needs write permission; individual
/// RX code leaves remain read-only by their *leaf* PTE. No W+X allowed.
pub fn populate(
    pml4: &mut [u64; ENTRY_COUNT],
    pdpt: &mut [u64; ENTRY_COUNT],
    pd: &mut [u64; ENTRY_COUNT],
    pt: &mut [u64; ENTRY_COUNT],
    tables: [u64; TABLE_FRAMES],
    pages: &[UserPage],
) -> Result<(), MultiError> {
    let (idx, any_writable) = validate(&tables, pages)?;
    if pml4.iter().chain(pdpt.iter()).chain(pd.iter()).chain(pt.iter())
        .any(|value| *value != 0)
    {
        return Err(MultiError::DirtyDestination);
    }
    let flags = parent_flags(any_writable);
    pml4[idx.pml4] = tables[1] | flags;
    pdpt[idx.pdpt] = tables[2] | flags;
    pd[idx.pd] = tables[3] | flags;
    for page in pages {
        let pt_idx = (page.virtual_address >> 12 & 511) as usize;
        pt[pt_idx] = page.physical_frame | leaf_flags(page);
    }
    Ok(())
}

/// Fail closed when ANY entry is different, even an unmapped hidden alias.
/// The audit is intentional O(4*512*MAX_PAGES), bounded at compile time.
pub fn audit(
    pml4: &[u64; ENTRY_COUNT],
    pdpt: &[u64; ENTRY_COUNT],
    pd: &[u64; ENTRY_COUNT],
    pt: &[u64; ENTRY_COUNT],
    tables: [u64; TABLE_FRAMES],
    pages: &[UserPage],
) -> Result<(), MultiError> {
    let (idx, writable) = validate(&tables, pages)?;
    for (table_id, table) in [pml4, pdpt, pd, pt].iter().enumerate() {
        for (position, actual) in table.iter().copied().enumerate() {
            if actual != expected(table_id, position, idx, &tables, pages, writable) {
                return Err(MultiError::MismatchedLayout);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLES: [u64; 4] = [0x10_000, 0x11_000, 0x12_000, 0x13_000];
    const PAGES: [UserPage; 4] = [
        UserPage { virtual_address: 0x401000, physical_frame: 0x14_000, writable: false, executable: true },
        UserPage { virtual_address: 0x402000, physical_frame: 0x15_000, writable: false, executable: true },
        UserPage { virtual_address: 0x403000, physical_frame: 0x16_000, writable: true, executable: false },
        UserPage { virtual_address: 0x404000, physical_frame: 0x17_000, writable: true, executable: false },
    ];
    type Bank = [[u64; ENTRY_COUNT]; TABLE_FRAMES];

    fn bank() -> Bank { [[0; ENTRY_COUNT]; TABLE_FRAMES] }

    fn elf_fixture() -> [u8; 512] {
        let mut bytes = [0u8; 512];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4..7].copy_from_slice(&[2, 1, 1]);
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x401100u64.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        // RX code, two pages including a BSS-only page.
        bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5u32.to_le_bytes());
        bytes[72..80].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[80..88].copy_from_slice(&0x401100u64.to_le_bytes());
        bytes[96..104].copy_from_slice(&8u64.to_le_bytes());
        bytes[104..112].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[112..120].copy_from_slice(&4096u64.to_le_bytes());
        // Separate RW data in page 3.
        bytes[120..124].copy_from_slice(&1u32.to_le_bytes());
        bytes[124..128].copy_from_slice(&6u32.to_le_bytes());
        bytes[128..136].copy_from_slice(&0x180u64.to_le_bytes());
        bytes[136..144].copy_from_slice(&0x403180u64.to_le_bytes());
        bytes[152..160].copy_from_slice(&8u64.to_le_bytes());
        bytes[160..168].copy_from_slice(&0x600u64.to_le_bytes());
        bytes[168..176].copy_from_slice(&4096u64.to_le_bytes());
        bytes[0x100] = 0xc3;
        bytes
    }

    #[test]
    fn unified_elf_image_gate_refuses_omitted_tampered_or_unzeroed_backing() {
        use crate::elf64_page_image::{materialize_batch, PageAuditError};
        let elf = elf_fixture();
        let plan = preflight(&elf).unwrap();
        let text = plan.segments[0].unwrap();
        let data = plan.segments[1].unwrap();
        let mut tables = bank();
        let [r, a, d, t] = &mut tables;
        populate(r, a, d, t, TABLES, &PAGES).unwrap();
        let mut code = [0x55; PAGE_SIZE];
        let mut bss = [0x66; PAGE_SIZE];
        let mut rw = [0x77; PAGE_SIZE];
        let mut stack = [0u8; PAGE_SIZE];
        let requested = [
            (&text, 0x401000), (&text, 0x402000), (&data, 0x403000),
        ];
        materialize_batch(&elf, requested, [&mut code, &mut bss, &mut rw]).unwrap();
        let [r, a, d, t] = &tables;
        assert_eq!(audit_ready_elf_image(
            &elf, 0x404000, TABLES, &PAGES, r, a, d, t,
            requested, [&code, &bss, &rw], &stack,
        ), Ok(plan));

        assert_eq!(audit_ready_elf_image(
            &elf, 0x404000, TABLES, &PAGES, r, a, d, t,
            requested[..2].try_into().unwrap(), [&code, &bss], &stack,
        ), Err(ReadyImageError::MissingOrUnexpectedLoadPage));

        let mut forged = data;
        forged.file_size = 1; // plausible, but NOT the original ELF plan
        assert_eq!(audit_ready_elf_image(
            &elf, 0x404000, TABLES, &PAGES, r, a, d, t,
            [(&text, 0x401000), (&text, 0x402000), (&forged, 0x403000)],
            [&code, &bss, &rw], &stack,
        ), Err(ReadyImageError::MissingOrUnexpectedLoadPage));

        bss[14] = 0xaa;
        assert_eq!(audit_ready_elf_image(
            &elf, 0x404000, TABLES, &PAGES, r, a, d, t,
            requested, [&code, &bss, &rw], &stack,
        ), Err(ReadyImageError::Bytes(PageAuditError::ContentMismatch {
            index: 1, offset: 14,
        })));
        bss[14] = 0;
        stack[19] = 0xfa;
        assert_eq!(audit_ready_elf_image(
            &elf, 0x404000, TABLES, &PAGES, r, a, d, t,
            requested, [&code, &bss, &rw], &stack,
        ), Err(ReadyImageError::DirtyStack { offset: 19 }));
        stack[19] = 0;
        let mut altered = tables;
        altered[3][1] |= WRITABLE; // executable text PTE may not gain W
        let [r, a, d, t] = &altered;
        assert_eq!(audit_ready_elf_image(
            &elf, 0x404000, TABLES, &PAGES, r, a, d, t,
            requested, [&code, &bss, &rw], &stack,
        ), Err(ReadyImageError::Mappings(
            ElfBindingError::PhysicalOrRoot(MultiError::MismatchedLayout)
        )));
        let [r, a, d, t] = &tables;
        assert_eq!(audit_ready_elf_image(
            &elf, 0x404000, TABLES, &PAGES, r, a, d, t,
            requested, [&code, &bss, &rw], &stack,
        ), Ok(plan));
    }

    #[test]
    fn exact_elf_and_real_pte_audit_rejects_permission_and_hidden_alias_corruption() {
        let elf = elf_fixture();
        let mut b = bank();
        let [root, pdpt, pd, pt] = &mut b;
        populate(root, pdpt, pd, pt, TABLES, &PAGES).unwrap();
        let [root, pdpt, pd, pt] = &b;
        let expected = validate_elf_bindings(&elf, 0x404000, TABLES, &PAGES).unwrap();
        assert_eq!(
            audit_elf_bindings(&elf, 0x404000, root, pdpt, pd, pt, TABLES, &PAGES),
            Ok(expected)
        );
        // Even if the page list still passes the ELF preflight binding,
        // actual shadow PTEs must not gain W on executable code, X on a
        // data/stack leaf or a hidden kernel-half user alias.
        for (table, slot, flag) in [
            (3usize, 1usize, WRITABLE),
            (3, 3, NX),
            (3, 4, NX),
            (0, 511, PRESENT | USER),
        ] {
            let mut broken = b;
            broken[table][slot] ^= flag;
            let [root, pdpt, pd, pt] = &broken;
            assert_eq!(
                audit_elf_bindings(&elf, 0x404000, root, pdpt, pd, pt, TABLES, &PAGES),
                Err(ElfBindingError::PhysicalOrRoot(MultiError::MismatchedLayout)),
            );
            // The audit is a pure read-only operation.
            assert_eq!(broken[table][slot], b[table][slot] ^ flag);
        }
        let mut altered_elf = elf;
        altered_elf[124..128].copy_from_slice(&5u32.to_le_bytes()); // data becomes RX
        let [root, pdpt, pd, pt] = &b;
        assert_eq!(
            audit_elf_bindings(&altered_elf, 0x404000, root, pdpt, pd, pt, TABLES, &PAGES),
            Err(ElfBindingError::PermissionMismatch),
        );
        assert_eq!(
            audit_elf_bindings(&elf, 0x403000, root, pdpt, pd, pt, TABLES, &PAGES),
            Err(ElfBindingError::StackInvalid),
        );
    }

    #[test]
    fn elf_to_pte_binding_covers_every_load_bss_and_nx_stack() {
        let elf = elf_fixture();
        let plan = validate_elf_bindings(&elf, 0x404000, TABLES, &PAGES).unwrap();
        assert_eq!(plan.entry, 0x401100);
        assert_eq!(plan.len, 2);
        let shuffled = [PAGES[3], PAGES[1], PAGES[0], PAGES[2]];
        assert_eq!(validate_elf_bindings(&elf, 0x404000, TABLES, &shuffled), Ok(plan));
    }

    #[test]
    fn elf_to_pte_binding_refuses_missing_bss_extra_alias_and_permission_upgrades() {
        let elf = elf_fixture();
        assert_eq!(validate_elf_bindings(&elf, 0x404000, TABLES,
            &[PAGES[0], PAGES[2], PAGES[3]]
        ), Err(ElfBindingError::MissingOrExtraPage));
        let mut wrong = PAGES;
        wrong[1].virtual_address = 0x405000;
        assert_eq!(validate_elf_bindings(&elf, 0x404000, TABLES, &wrong),
            Err(ElfBindingError::MissingOrExtraPage));
        let mut permission = PAGES;
        permission[0].writable = true;
        assert_eq!(validate_elf_bindings(&elf, 0x404000, TABLES, &permission),
            Err(ElfBindingError::PermissionMismatch));
        permission = PAGES;
        permission[3].executable = true;
        assert_eq!(validate_elf_bindings(&elf, 0x404000, TABLES, &permission),
            Err(ElfBindingError::PermissionMismatch));
        assert_eq!(validate_elf_bindings(&elf, 0x403000, TABLES, &PAGES),
            Err(ElfBindingError::StackInvalid));
        let mut aliased = PAGES;
        aliased[3].physical_frame = PAGES[0].physical_frame;
        assert_eq!(validate_elf_bindings(&elf, 0x404000, TABLES, &aliased),
            Err(ElfBindingError::PhysicalOrRoot(MultiError::AliasedPhysicalFrame)));
        let mut corrupt = elf;
        corrupt[68..72].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(validate_elf_bindings(&corrupt, 0x404000, TABLES, &PAGES),
            Err(ElfBindingError::Image(ElfError::InvalidPermissions)));
    }

    #[test]
    fn elf_to_pte_binding_rejects_page_footprints_larger_than_bounded_root() {
        let mut elf = elf_fixture();
        elf[104..112].copy_from_slice(&0x4000u64.to_le_bytes());
        // Shift the RW segment out of range so strict ELF preflight
        // succeeds; the bounded four-PTE footprint still must refuse.
        elf[136..144].copy_from_slice(&0x409180u64.to_le_bytes());
        assert_eq!(validate_elf_bindings(&elf, 0x404000, TABLES, &PAGES),
            Err(ElfBindingError::TooManyPages));
        assert_eq!(validate_elf_bindings(&elf_fixture(), 0, TABLES, &PAGES),
            Err(ElfBindingError::StackInvalid));
    }

    #[test]
    fn mixed_pages_share_same_pml4_and_ancestors_but_not_permissions() {
        let mut b = bank();
        let [pml4, pdpt, pd, pt] = &mut b;
        populate(pml4, pdpt, pd, pt, TABLES, &PAGES).unwrap();
        assert_eq!(pml4[0], TABLES[1] | PRESENT | USER | WRITABLE);
        assert_eq!(pdpt[0], TABLES[2] | PRESENT | USER | WRITABLE);
        assert_eq!(pd[2], TABLES[3] | PRESENT | USER | WRITABLE);
        assert_eq!(pt[1], PAGES[0].physical_frame | PRESENT | USER);
        assert_eq!(pt[2], PAGES[1].physical_frame | PRESENT | USER);
        assert_eq!(pt[3], PAGES[2].physical_frame | PRESENT | USER | WRITABLE | NX);
        assert_eq!(pt[4], PAGES[3].physical_frame | PRESENT | USER | WRITABLE | NX);
        assert!(pml4[256..].iter().all(|entry| *entry == 0));
        assert_eq!(audit(pml4, pdpt, pd, pt, TABLES, &PAGES), Ok(()));
    }

    #[test]
    fn unordered_pages_work_but_cannot_create_same_virtual_alias() {
        let mut b = bank();
        let shuffled = [PAGES[3], PAGES[0], PAGES[2], PAGES[1]];
        let [pml4, pdpt, pd, pt] = &mut b;
        populate(pml4, pdpt, pd, pt, TABLES, &shuffled).unwrap();
        assert_eq!(audit(pml4, pdpt, pd, pt, TABLES, &PAGES), Ok(()));
        let mut b = bank();
        let [pml4, pdpt, pd, pt] = &mut b;
        assert_eq!(populate(pml4, pdpt, pd, pt, TABLES, &[PAGES[0], PAGES[0]]),
            Err(MultiError::AliasedPhysicalFrame));
        assert!(b.iter().flatten().all(|entry| *entry == 0));
        let mut duplicate = PAGES[0];
        duplicate.physical_frame = 0x18_000;
        let [pml4, pdpt, pd, pt] = &mut b;
        assert_eq!(populate(pml4, pdpt, pd, pt, TABLES, &[PAGES[0], duplicate]),
            Err(MultiError::DuplicateVirtualPage));
        assert!(b.iter().flatten().all(|entry| *entry == 0));
    }

    #[test]
    fn no_partial_writes_for_cross_pt_wx_and_invalid_frames() {
        let mut b = bank();
        let mut bad = PAGES;
        bad[3].virtual_address = 0x600000;
        let [pml4, pdpt, pd, pt] = &mut b;
        assert_eq!(populate(pml4, pdpt, pd, pt, TABLES, &bad),
            Err(MultiError::DifferentPageTable));
        bad = PAGES;
        bad[1].writable = true;
        let [pml4, pdpt, pd, pt] = &mut b;
        assert_eq!(populate(pml4, pdpt, pd, pt, TABLES, &bad),
            Err(MultiError::WriteExecute));
        bad = PAGES;
        bad[1].physical_frame = TABLES[0];
        let [pml4, pdpt, pd, pt] = &mut b;
        assert_eq!(populate(pml4, pdpt, pd, pt, TABLES, &bad),
            Err(MultiError::AliasedPhysicalFrame));
        bad = PAGES;
        bad[1].physical_frame = 1 << 52;
        let [pml4, pdpt, pd, pt] = &mut b;
        assert_eq!(populate(pml4, pdpt, pd, pt, TABLES, &bad),
            Err(MultiError::InvalidPhysicalFrame));
        assert!(b.iter().flatten().all(|entry| *entry == 0));
    }

    #[test]
    fn reject_dirty_existing_mapping_without_modifying_it() {
        let mut b = bank();
        b[0][256] = 0xdead_beef;
        let old = b;
        let [r, a, d, t] = &mut b;
        assert_eq!(populate(r, a, d, t, TABLES, &PAGES),
            Err(MultiError::DirtyDestination));
        assert_eq!(b, old);
    }

    #[test]
    fn audit_finds_hidden_high_half_aliases_and_each_permission_violation() {
        let cases = [(0, 0, USER), (1, 0, WRITABLE), (2, 2, 1 << 7),
                     (3, 1, WRITABLE), (3, 3, NX), (3, 4, NX), (3, 5, PRESENT),
                     (0, 511, PRESENT)];
        for (which, pos, corrupted) in cases {
            let mut b = bank();
            let [r, a, d, t] = &mut b;
            populate(r, a, d, t, TABLES, &PAGES).unwrap();
            b[which][pos] ^= corrupted;
            let [r, a, d, t] = &b;
            assert_eq!(audit(r, a, d, t, TABLES, &PAGES),
                Err(MultiError::MismatchedLayout));
        }
    }

    #[test]
    fn one_page_and_invalid_number_enforced() {
        let mut b = bank();
        let [r, a, d, t] = &mut b;
        assert_eq!(populate(r, a, d, t, TABLES, &[]),
            Err(MultiError::EmptyOrOversized));
        let [r, a, d, t] = &mut b;
        assert_eq!(populate(r, a, d, t, TABLES, &[PAGES[0]; 5]),
            Err(MultiError::EmptyOrOversized));
        let [r, a, d, t] = &mut b;
        populate(r, a, d, t, TABLES, &PAGES[..1]).unwrap();
        assert_eq!(r[0], TABLES[1] | PRESENT | USER);
        assert_eq!(audit(r, a, d, t, TABLES, &PAGES[..1]), Ok(()));
    }
}
