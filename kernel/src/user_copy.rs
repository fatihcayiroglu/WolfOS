//! Bounded page-admission contract before COPY_FROM_USER/COPY_TO_USER.
//!
//! A user pointer is untrusted even if canonical. This no_std pure part
//! checks a single page, offset overflow, PRESENT/U/S and W^X rules,
//! physical-frame OWNERSHIP and requested read/write permission.
//! The actual QEMU caller also checks each of 4 live page-table ancestors
//! against independently allocated PMM-owned frames before using HHDM.
//! No cross-page support, COW, swap, demand paging or general memory mapper.

pub const PRESENT: u64 = 1;
pub const WRITE: u64 = 2;
pub const USER: u64 = 4;
pub const NX: u64 = 1 << 63;
pub const FRAME_MASK: u64 = 0x000f_ffff_ffff_f000;
pub const PAGE: u64 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAccessError {
    Empty, TooLong, Overflow, OutsidePage, NotPresent, Supervisor,
    ReadOnly, ExecutableWritable, WrongFrame,
}

/// Returns frame offset for a single bounded memory operation, not an
/// HHDM pointer. Caller MUST additionally validate the LIVE CR3 and all
/// ancestors, and use its independently owned physical frame lease.
pub fn admit(
    start: u64, len: usize, page_va: u64, leaf: u64,
    expected_owned_phys: u64, write: bool,
) -> Result<usize, UserAccessError> {
    if len == 0 { return Err(UserAccessError::Empty) }
    if len > 64 { return Err(UserAccessError::TooLong) }
    let end = start.checked_add(len as u64).ok_or(UserAccessError::Overflow)?;
    let page_end = page_va.checked_add(PAGE).ok_or(UserAccessError::Overflow)?;
    if page_va & (PAGE - 1) != 0
        || start < page_va || end > page_end
    { return Err(UserAccessError::OutsidePage) }
    if leaf & PRESENT == 0 { return Err(UserAccessError::NotPresent) }
    if leaf & USER == 0 { return Err(UserAccessError::Supervisor) }
    if write && leaf & WRITE == 0 { return Err(UserAccessError::ReadOnly) }
    if leaf & WRITE != 0 && leaf & NX == 0 {
        return Err(UserAccessError::ExecutableWritable)
    }
    if expected_owned_phys == 0 || expected_owned_phys & (PAGE - 1) != 0
        || leaf & FRAME_MASK != expected_owned_phys
    { return Err(UserAccessError::WrongFrame) }
    Ok((start - page_va) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approved_read_only_text_and_nx_data() {
        let base = 0x80_0000_0000u64;
        let code = PRESENT | USER | 0x2000;
        let data = PRESENT | USER | WRITE | NX | 0x3000;
        assert_eq!(admit(base + 0x1000, 13, base + 0x1000, code, 0x2000, false), Ok(0));
        assert_eq!(admit(base + 0x3001, 8, base + 0x3000, data, 0x3000, true), Ok(1));
        assert_eq!(admit(base + 0x1000, 8, base + 0x1000, code, 0x2000, true),
            Err(UserAccessError::ReadOnly));
    }
    #[test]
    fn malicious_kernel_null_cross_page_and_overflow_are_rejected() {
        let base = 0x80_0000_0000u64;
        let page = base + 0x1000;
        let leaf = PRESENT | USER | 0x2000;
        for (addr, len) in [(0, 8), (0xffff800000000000, 8),
            (page + 4095, 2), (u64::MAX, 8), (page + 4096, 1)] {
            assert!(admit(addr, len, page, leaf, 0x2000, false).is_err());
        }
        assert_eq!(admit(page, 0, page, leaf, 0x2000, false), Err(UserAccessError::Empty));
        assert_eq!(admit(page, 65, page, leaf, 0x2000, false), Err(UserAccessError::TooLong));
    }
    #[test]
    fn forged_leaf_and_invalid_permissions_fail() {
        let page = 0x10000;
        for (pte, err) in [
            (USER | 0x2000, UserAccessError::NotPresent),
            (PRESENT | 0x2000, UserAccessError::Supervisor),
            (PRESENT | USER | WRITE | 0x2000, UserAccessError::ExecutableWritable),
            (PRESENT | USER | 0x3000, UserAccessError::WrongFrame),
        ] {
            assert_eq!(admit(page, 5, page, pte, 0x2000, false), Err(err));
        }
    }
}
