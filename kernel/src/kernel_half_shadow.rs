//! P2 kernel-half supervisor-only PML4 inheritance for an INACTIVE shadow root.
//!
//! The source is the live bootloader PML4. We copy existing upper-half PML4
//! entries to an independently owned zero-high-half user root AFTER verifying
//! they are supervisor-only, present/valid and do not point to caller-owned
//! temporary frames. We NEVER mutate the live source or descendant tables.
//!
//! Unlike copying only an arbitrary kernel virtual address, this preserves
//! the exact pre-existing kernel, HHDM, IDT/stack and framebuffer upper-half
//! PML4 entries. All kernel upper-half PML4 entries remain U/S=0, which
//! denies CPL3 access regardless of lower-level flags.
//!
//! This is only an admission + metadata-copy proof. It does NOT activate
//! CR3, validate descendant identity mappings, initialize TSS.RSP0,
//! enter Ring 3, or establish complete process isolation. Before a
//! real CR3 switch the OS must verify entry/exit and all supervisor mappings.

pub const PML4_ENTRIES: usize = 512;
pub const HIGH_HALF_START: usize = 256;
pub const PTE_PRESENT: u64 = 1;
pub const PTE_USER: u64 = 1 << 2;
pub const PTE_LARGE_PAGE: u64 = 1 << 7;
pub const PHYS_MASK: u64 = 0x000f_ffff_ffff_f000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraftError {
    InvalidUserIndex,
    InvalidUserEntry,
    UnexpectedLowMapping,
    DirtyKernelHalf,
    NoKernelMappings,
    NonPresentMetadata,
    UserAccessibleKernel,
    InvalidKernelRootEntry,
    AliasedOwnedFrame,
    AuditMismatch,
}

fn check_user_lower(
    root: &[u64; PML4_ENTRIES],
    index: usize,
    expected: u64,
) -> Result<(), GraftError> {
    if index >= HIGH_HALF_START {
        return Err(GraftError::InvalidUserIndex);
    }
    if expected & PTE_PRESENT == 0 || expected & PTE_USER == 0
        || expected & PHYS_MASK == 0 || expected & PTE_LARGE_PAGE != 0
    {
        return Err(GraftError::InvalidUserEntry);
    }
    if root[..HIGH_HALF_START].iter().enumerate().any(|(i, entry)|
        *entry != if i == index { expected } else { 0 }
    ) {
        return Err(GraftError::UnexpectedLowMapping);
    }
    Ok(())
}

fn validate_source(
    active: &[u64; PML4_ENTRIES],
    owned: &[u64],
) -> Result<usize, GraftError> {
    let mut mapped = 0usize;
    for entry in active[HIGH_HALF_START..].iter().copied() {
        if entry == 0 { continue; }
        if entry & PTE_PRESENT == 0 {
            return Err(GraftError::NonPresentMetadata);
        }
        if entry & PTE_USER != 0 {
            return Err(GraftError::UserAccessibleKernel);
        }
        if entry & PTE_LARGE_PAGE != 0 || entry & PHYS_MASK == 0 {
            return Err(GraftError::InvalidKernelRootEntry);
        }
        if owned.iter().any(|frame| *frame == (entry & PHYS_MASK)) {
            return Err(GraftError::AliasedOwnedFrame);
        }
        mapped += 1;
    }
    if mapped == 0 {
        return Err(GraftError::NoKernelMappings);
    }
    Ok(mapped)
}

/// Preflight all source and destination entries BEFORE writing any byte.
/// Caller must hold an exclusive, fresh shadow PML4 frame and a stable
/// snapshot of the live PML4. Owned frames are the fresh PMM frames,
/// including the destination PML4 itself and all user page-table frames.
pub fn graft_kernel_half(
    active: &[u64; PML4_ENTRIES],
    shadow: &mut [u64; PML4_ENTRIES],
    user_pml4_index: usize,
    expected_user_entry: u64,
    owned: &[u64],
) -> Result<usize, GraftError> {
    check_user_lower(shadow, user_pml4_index, expected_user_entry)?;
    if shadow[HIGH_HALF_START..].iter().any(|entry| *entry != 0) {
        return Err(GraftError::DirtyKernelHalf);
    }
    let count = validate_source(active, owned)?;
    shadow[HIGH_HALF_START..].copy_from_slice(&active[HIGH_HALF_START..]);
    Ok(count)
}

/// Independently re-check low-half cardinality, exact high-half equality and
/// supervisor access on every high PML4 slot after inheritance.
pub fn audit_kernel_half(
    active: &[u64; PML4_ENTRIES],
    shadow: &[u64; PML4_ENTRIES],
    user_pml4_index: usize,
    expected_user_entry: u64,
    owned: &[u64],
) -> Result<usize, GraftError> {
    check_user_lower(shadow, user_pml4_index, expected_user_entry)?;
    let count = validate_source(active, owned)?;
    if shadow[HIGH_HALF_START..] != active[HIGH_HALF_START..] {
        return Err(GraftError::AuditMismatch);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    const FRAMES: [u64; 8] = [
        0x10_000, 0x11_000, 0x12_000, 0x13_000,
        0x14_000, 0x15_000, 0x16_000, 0x17_000,
    ];
    const USER_ENTRY: u64 = FRAMES[1] | PTE_PRESENT | PTE_USER | 2;
    fn source() -> [u64; PML4_ENTRIES] {
        let mut root = [0u64; PML4_ENTRIES];
        root[256] = 0x40_000 | PTE_PRESENT | 2;
        root[510] = 0x50_000 | PTE_PRESENT;
        root[511] = 0x60_000 | PTE_PRESENT | 2;
        root
    }
    fn target() -> [u64; PML4_ENTRIES] {
        let mut root = [0u64; PML4_ENTRIES];
        root[0] = USER_ENTRY;
        root
    }

    #[test]
    fn inherits_all_kernel_entries_without_making_any_user_accessible() {
        let src = source();
        let mut dst = target();
        assert_eq!(graft_kernel_half(&src, &mut dst, 0, USER_ENTRY, &FRAMES), Ok(3));
        assert_eq!(dst[..256].iter().filter(|x| **x != 0).count(), 1);
        assert!(dst[256..].iter().all(|x| x & PTE_USER == 0));
        assert_eq!(dst[256..], src[256..]);
        assert_eq!(audit_kernel_half(&src, &dst, 0, USER_ENTRY, &FRAMES), Ok(3));
        assert_eq!(src, source()); // never write to the active source.
    }

    #[test]
    fn fail_without_partial_write_on_user_bit_and_absent_kernel_root() {
        let mut src = source();
        src[511] |= PTE_USER;
        let mut dst = target();
        let before = dst;
        assert_eq!(graft_kernel_half(&src, &mut dst, 0, USER_ENTRY, &FRAMES),
            Err(GraftError::UserAccessibleKernel));
        assert_eq!(dst, before);

        let src = [0u64; PML4_ENTRIES];
        assert_eq!(graft_kernel_half(&src, &mut dst, 0, USER_ENTRY, &FRAMES),
            Err(GraftError::NoKernelMappings));
        assert_eq!(dst, before);
    }

    #[test]
    fn low_user_mapping_cannot_be_replaced_or_aliased() {
        let src = source();
        let mut dst = target();
        dst[1] = 0x80_007;
        let prior = dst;
        assert_eq!(graft_kernel_half(&src, &mut dst, 0, USER_ENTRY, &FRAMES),
            Err(GraftError::UnexpectedLowMapping));
        assert_eq!(dst, prior);
        let mut dst = target();
        assert_eq!(graft_kernel_half(&src, &mut dst, 256, USER_ENTRY, &FRAMES),
            Err(GraftError::InvalidUserIndex));
        assert_eq!(graft_kernel_half(&src, &mut dst, 0, USER_ENTRY & !PTE_USER, &FRAMES),
            Err(GraftError::InvalidUserEntry));
    }

    #[test]
    fn rejects_dirty_destination_source_metadata_and_frame_aliases() {
        let src = source();
        let mut dst = target();
        dst[511] = 0x70_003;
        let before = dst;
        assert_eq!(graft_kernel_half(&src, &mut dst, 0, USER_ENTRY, &FRAMES),
            Err(GraftError::DirtyKernelHalf));
        assert_eq!(dst, before);
        let mut dst = target();
        let mut malformed = src;
        malformed[511] = 0x60_000; // nonpresent but nonempty
        assert_eq!(graft_kernel_half(&malformed, &mut dst, 0, USER_ENTRY, &FRAMES),
            Err(GraftError::NonPresentMetadata));
        malformed[511] = 0x60_081; // illegal PML4 PS
        assert_eq!(graft_kernel_half(&malformed, &mut dst, 0, USER_ENTRY, &FRAMES),
            Err(GraftError::InvalidKernelRootEntry));
        malformed[511] = FRAMES[4] | PTE_PRESENT;
        assert_eq!(graft_kernel_half(&malformed, &mut dst, 0, USER_ENTRY, &FRAMES),
            Err(GraftError::AliasedOwnedFrame));
        assert_eq!(dst, target());
    }

    #[test]
    fn audit_rejects_privilege_escalation_physical_target_change_and_hidden_entry() {
        let src = source();
        let mut dst = target();
        graft_kernel_half(&src, &mut dst, 0, USER_ENTRY, &FRAMES).unwrap();
        for (idx, bit) in [(256, PTE_USER), (511, 0x10_000), (300, PTE_PRESENT)] {
            let mut corrupt = dst;
            corrupt[idx] ^= bit;
            assert_eq!(audit_kernel_half(&src, &corrupt, 0, USER_ENTRY, &FRAMES),
                Err(GraftError::AuditMismatch));
        }
        let mut corrupt = dst;
        corrupt[0] ^= 2;
        assert_eq!(audit_kernel_half(&src, &corrupt, 0, USER_ENTRY, &FRAMES),
            Err(GraftError::UnexpectedLowMapping));
    }
}
