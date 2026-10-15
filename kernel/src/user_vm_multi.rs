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

use crate::elf64_preflight::PAGE_BYTES;
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
