//! P2 four-level x86-64 USER page-table layout prototype (no CR3 write).
//!
//! The five physical frames must be allocated and exclusively owned by the
//! caller: PML4, PDPT, PD, PT, and one payload page, in that order.
//! This initializes EXACTLY one 4-KiB lower-half user mapping in a fresh,
//! otherwise zeroed address-space root. Upper half and all other virtual
//! addresses stay unmapped in this deliberately non-runnable shadow root.
//!
//! This does NOT install kernel supervisor mappings, activate CR3, turn on
//! EFER.NXE, supply an RSP0 for traps or safely enter CPL3. The future
//! runtime must verify all of those before ever activating the root.

use crate::elf64_preflight::{PAGE_BYTES, USER_END, USER_MIN};

pub const ENTRY_COUNT: usize = 512;
pub const FRAME_COUNT: usize = 5;
pub const PRESENT: u64 = 1;
pub const WRITABLE: u64 = 1 << 1;
pub const USER: u64 = 1 << 2;
pub const NX: u64 = 1 << 63;
const PHYSICAL_END: u64 = 1 << 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootError {
    UnalignedVirtual, OutOfUserRange, InvalidPhysicalFrame,
    AliasedFrame, WriteExecute, DirtyDestination, MismatchedLayout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Indices {
    pub pml4: usize,
    pub pdpt: usize,
    pub pd: usize,
    pub pt: usize,
}

pub fn indices(va: u64) -> Result<Indices, RootError> {
    if va & (PAGE_BYTES - 1) != 0 {
        return Err(RootError::UnalignedVirtual);
    }
    if va < USER_MIN || va.checked_add(PAGE_BYTES)
        .is_none_or(|end| end > USER_END)
    {
        return Err(RootError::OutOfUserRange);
    }
    Ok(Indices {
        pml4: ((va >> 39) & 511) as usize,
        pdpt: ((va >> 30) & 511) as usize,
        pd: ((va >> 21) & 511) as usize,
        pt: ((va >> 12) & 511) as usize,
    })
}

fn check_frames(frames: [u64; FRAME_COUNT]) -> Result<(), RootError> {
    for (at, frame) in frames.iter().copied().enumerate() {
        if frame == 0 || frame % PAGE_BYTES != 0 || frame >= PHYSICAL_END {
            return Err(RootError::InvalidPhysicalFrame);
        }
        if frames[..at].contains(&frame) {
            return Err(RootError::AliasedFrame);
        }
    }
    Ok(())
}

fn entries(frames: [u64; FRAME_COUNT], write: bool, exec: bool) -> [u64; 4] {
    let parent = PRESENT | USER | if write { WRITABLE } else { 0 };
    [
        frames[1] | parent,
        frames[2] | parent,
        frames[3] | parent,
        frames[4] | parent | if exec { 0 } else { NX },
    ]
}

fn only_entry(table: &[u64; ENTRY_COUNT], at: usize, value: u64) -> bool {
    table.iter().enumerate().all(|(i, found)|
        *found == if i == at { value } else { 0 })
}

/// Produce a disconnected, single-page page-table hierarchy. Every input
/// is checked before any output table is written. No partial publication.
///
/// Caller MUST provide five PMM-owned physical frames, all distinct, HHDM
/// mapped, and four zero-initialized table arrays corresponding exactly to
/// frames[0..4]. Code pages use R+X; data pages R+W+NX. W+X is forbidden.
pub fn populate_one(
    root: &mut [u64; ENTRY_COUNT],
    pdpt: &mut [u64; ENTRY_COUNT],
    pd: &mut [u64; ENTRY_COUNT],
    pt: &mut [u64; ENTRY_COUNT],
    frames: [u64; FRAME_COUNT],
    virtual_page: u64,
    write: bool,
    exec: bool,
) -> Result<Indices, RootError> {
    let ix = indices(virtual_page)?;
    check_frames(frames)?;
    if write && exec {
        return Err(RootError::WriteExecute);
    }
    if [root as &[_; ENTRY_COUNT], pdpt, pd, pt].iter()
        .any(|table| table.iter().any(|entry| *entry != 0))
    {
        return Err(RootError::DirtyDestination);
    }
    let values = entries(frames, write, exec);
    root[ix.pml4] = values[0];
    pdpt[ix.pdpt] = values[1];
    pd[ix.pd] = values[2];
    pt[ix.pt] = values[3];
    Ok(ix)
}

/// Verify the complete freshly built table, including ALL 2048 entries:
/// every non-path leaf and all high-half kernel slots must be empty.
/// Rejects unexpected global, large-page, supervisor, permission, and
/// alternate physical-frame aliases by requiring exact entries.
pub fn audit_one(
    root: &[u64; ENTRY_COUNT],
    pdpt: &[u64; ENTRY_COUNT],
    pd: &[u64; ENTRY_COUNT],
    pt: &[u64; ENTRY_COUNT],
    frames: [u64; FRAME_COUNT],
    virtual_page: u64,
    write: bool,
    exec: bool,
) -> Result<(), RootError> {
    let ix = indices(virtual_page)?;
    check_frames(frames)?;
    if write && exec {
        return Err(RootError::WriteExecute);
    }
    let values = entries(frames, write, exec);
    if !only_entry(root, ix.pml4, values[0])
        || !only_entry(pdpt, ix.pdpt, values[1])
        || !only_entry(pd, ix.pd, values[2])
        || !only_entry(pt, ix.pt, values[3])
    {
        return Err(RootError::MismatchedLayout);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAMES: [u64; FRAME_COUNT] =
        [0x1_0000, 0x1_1000, 0x1_2000, 0x1_3000, 0x1_4000];
    type Tables = [[u64; ENTRY_COUNT]; 4];

    #[test]
    fn root_and_ancestors_are_user_accessible_but_kernel_half_is_empty() {
        let mut t: Tables = [[0; ENTRY_COUNT]; 4];
        let [root, pdpt, pd, pt] = &mut t;
        let ix = populate_one(root, pdpt, pd, pt, FRAMES, 0x401000, false, true).unwrap();
        assert_eq!(ix, Indices { pml4: 0, pdpt: 0, pd: 2, pt: 1 });
        assert_eq!(root[0], FRAMES[1] | PRESENT | USER);
        assert_eq!(pdpt[0], FRAMES[2] | PRESENT | USER);
        assert_eq!(pd[2], FRAMES[3] | PRESENT | USER);
        assert_eq!(pt[1], FRAMES[4] | PRESENT | USER);
        assert!(root[256..].iter().all(|entry| *entry == 0));
        assert_eq!(audit_one(root, pdpt, pd, pt, FRAMES, 0x401000, false, true), Ok(()));
    }

    #[test]
    fn rw_data_page_requires_all_ancestors_rw_and_leaf_nx() {
        let mut t: Tables = [[0; ENTRY_COUNT]; 4];
        let [r, a, b, c] = &mut t;
        populate_one(r, a, b, c, FRAMES, 0x601000, true, false).unwrap();
        assert!(r[0] & WRITABLE != 0);
        assert!(a[0] & WRITABLE != 0);
        assert!(b[3] & WRITABLE != 0);
        assert_eq!(c[1], FRAMES[4] | PRESENT | USER | WRITABLE | NX);
        assert_eq!(audit_one(r, a, b, c, FRAMES, 0x601000, true, false), Ok(()));
        assert_eq!(
            audit_one(r, a, b, c, FRAMES, 0x601000, false, true),
            Err(RootError::MismatchedLayout)
        );
    }

    #[test]
    fn no_partial_write_on_rejected_mapping() {
        let mut t: Tables = [[0; ENTRY_COUNT]; 4];
        let bad_va = [0, 0xf000, USER_END, USER_END - 4095, u64::MAX];
        for address in bad_va {
            let [r, a, b, c] = &mut t;
            assert!(populate_one(r, a, b, c, FRAMES, address, false, true).is_err());
            assert!(t.iter().flatten().all(|entry| *entry == 0));
        }
        let [r, a, b, c] = &mut t;
        assert_eq!(
            populate_one(r, a, b, c, FRAMES, 0x401000, true, true),
            Err(RootError::WriteExecute)
        );
        assert!(t.iter().flatten().all(|entry| *entry == 0));
    }

    #[test]
    fn reject_aliased_unaligned_and_out_of_range_physical_frames() {
        for invalid in [
            [FRAMES[0], FRAMES[0], FRAMES[2], FRAMES[3], FRAMES[4]],
            [FRAMES[0], FRAMES[1] + 1, FRAMES[2], FRAMES[3], FRAMES[4]],
            [0, FRAMES[1], FRAMES[2], FRAMES[3], FRAMES[4]],
            [FRAMES[0], FRAMES[1], FRAMES[2], FRAMES[3], 1 << 52],
        ] {
            let mut t: Tables = [[0; ENTRY_COUNT]; 4];
            let [r, a, b, c] = &mut t;
            assert!(populate_one(r, a, b, c, invalid, 0x401000, false, true).is_err());
            assert!(t.iter().flatten().all(|entry| *entry == 0));
        }
    }

    #[test]
    fn refuse_used_table_or_hidden_kernel_mapping_without_mutation() {
        let mut t: Tables = [[0; ENTRY_COUNT]; 4];
        t[0][256] = 0xdead_beef;
        let snapshot = t;
        let [r, a, b, c] = &mut t;
        assert_eq!(
            populate_one(r, a, b, c, FRAMES, 0x401000, false, true),
            Err(RootError::DirtyDestination)
        );
        assert_eq!(t, snapshot);
    }

    #[test]
    fn audit_detects_supervisor_flag_nx_large_page_and_hidden_entries() {
        for (table, index, mask) in [
            (0usize, 0usize, USER),
            (1, 0, USER),
            (2, 2, 1 << 7), // wrong huge-page flag
            (3, 1, NX), // executable page wrongly made NX
        ] {
            let mut t: Tables = [[0; ENTRY_COUNT]; 4];
            let [r, a, b, c] = &mut t;
            populate_one(r, a, b, c, FRAMES, 0x401000, false, true).unwrap();
            t[table][index] ^= mask;
            let [r, a, b, c] = &t;
            assert_eq!(
                audit_one(r, a, b, c, FRAMES, 0x401000, false, true),
                Err(RootError::MismatchedLayout)
            );
        }
        let mut t: Tables = [[0; ENTRY_COUNT]; 4];
        let [r, a, b, c] = &mut t;
        populate_one(r, a, b, c, FRAMES, 0x401000, false, true).unwrap();
        t[0][510] = FRAMES[4] | PRESENT;
        let [r, a, b, c] = &t;
        assert_eq!(
            audit_one(r, a, b, c, FRAMES, 0x401000, false, true),
            Err(RootError::MismatchedLayout)
        );
    }
}
