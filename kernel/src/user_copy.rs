//! P2 x86-64 user buffer validation, for a private 4-level 4-KiB CR3.
//!
//! Core page walk is pure and host-testable. Both read and write require
//! PRESENT+USER at ALL 4 levels; writes also require WRITABLE at ALL levels.
//! No huge pages, no supervisor high-half, no unchecked overflow, no
//! acceptance of noncanonical user addresses, no zero address, no partial
//! destination writes on a rejected multi-page range.
//!
//! The physical-memory reader/writer is supplied by the caller, not by
//! dereferencing an attacker-supplied user VA. A production implementation
//! must also pin page-table frames, validate owned physical leaf frames,
//! enforce task-CR3 identity, and exclude concurrent remap/unmap races.
//! The P2 QEMU experiment supplies such a *seven owned frames only*
//! allowlist and runs BSP-only with interrupts disabled.

pub const PAGE: u64 = 4096;
pub const MAX_COPY: usize = 256;
const PRESENT: u64 = 1;
const WRITE: u64 = 2;
const USER: u64 = 4;
const HUGE: u64 = 128;
const ADDRESS: u64 = 0x000f_ffff_ffff_f000;
const USER_START: u64 = 0x10000;
const USER_END: u64 = 0x0000_8000_0000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyError {
    InvalidRange, Oversized, InvalidPageTable, NotPresent,
    Supervisor, ReadOnly, UnsupportedHugePage, BadPhysical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access { Read, Write }

fn checked_range(addr: u64, len: usize) -> Result<(), CopyError> {
    if len > MAX_COPY { return Err(CopyError::Oversized) }
    if addr < USER_START || addr >= USER_END {
        return Err(CopyError::InvalidRange)
    }
    let end = addr.checked_add(len as u64).ok_or(CopyError::InvalidRange)?;
    if end > USER_END { return Err(CopyError::InvalidRange) }
    Ok(())
}

/// Translate one user byte using current process's already-audited CR3.
/// Every table read is performed via an externally validated PHYSICAL
/// provider; the provider must not accept arbitrary unowned frames.
pub fn walk(
    root: u64,
    user_addr: u64,
    access: Access,
    mut entry: impl FnMut(u64) -> Option<u64>,
) -> Result<u64, CopyError> {
    checked_range(user_addr, 1)?;
    if root == 0 || root & 4095 != 0 || root >= (1u64 << 52) {
        return Err(CopyError::InvalidPageTable)
    }
    let mut table = root;
    for (level, shift) in [39u32, 30, 21, 12].into_iter().enumerate() {
        let idx = (user_addr >> shift) & 511;
        let ptr = table.checked_add(idx * 8).ok_or(CopyError::BadPhysical)?;
        let val = entry(ptr).ok_or(CopyError::BadPhysical)?;
        if val & PRESENT == 0 { return Err(CopyError::NotPresent) }
        if val & USER == 0 { return Err(CopyError::Supervisor) }
        if access == Access::Write && val & WRITE == 0 {
            return Err(CopyError::ReadOnly)
        }
        if level != 3 && val & HUGE != 0 {
            return Err(CopyError::UnsupportedHugePage)
        }
        table = val & ADDRESS;
        if table == 0 || table >= (1u64 << 52) {
            return Err(CopyError::BadPhysical)
        }
    }
    table.checked_add(user_addr & 4095).ok_or(CopyError::BadPhysical)
}

/// All physical memory reads/writes are performed through a caller owned
/// provider, never through the raw user VA. Two-pass address validation
/// prevents a partly overwritten destination on invalid later pages.
pub fn copy_from(
    root: u64,
    addr: u64,
    dst: &mut [u8],
    mut pte: impl FnMut(u64) -> Option<u64>,
    mut read: impl FnMut(u64) -> Option<u8>,
) -> Result<(), CopyError> {
    checked_range(addr, dst.len())?;
    for i in 0..dst.len() {
        let phys = walk(root, addr + i as u64, Access::Read, &mut pte)?;
        if read(phys).is_none() { return Err(CopyError::BadPhysical) }
    }
    for (i, b) in dst.iter_mut().enumerate() {
        let phys = walk(root, addr + i as u64, Access::Read, &mut pte)?;
        *b = read(phys).ok_or(CopyError::BadPhysical)?;
    }
    Ok(())
}

pub fn copy_to(
    root: u64,
    addr: u64,
    src: &[u8],
    mut pte: impl FnMut(u64) -> Option<u64>,
    mut access: impl FnMut(u64, Option<u8>) -> Option<u8>,
) -> Result<(), CopyError> {
    checked_range(addr, src.len())?;
    for i in 0..src.len() {
        let phys = walk(root, addr + i as u64, Access::Write, &mut pte)?;
        if access(phys, None).is_none() { return Err(CopyError::BadPhysical) }
    }
    for (i, b) in src.iter().copied().enumerate() {
        let phys = walk(root, addr + i as u64, Access::Write, &mut pte)?;
        access(phys, Some(b)).ok_or(CopyError::BadPhysical)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Pages { tables: [[u64;512];4], data: [u8;4096] }
    impl Pages {
        fn new() -> Self {
            let mut tables = [[0;512];4];
            tables[0][0] = 0x2000 | 7;
            tables[1][0] = 0x3000 | 7;
            tables[2][2] = 0x4000 | 7;
            tables[3][1] = 0x5000 | 5; // read-only text
            tables[3][3] = 0x6000 | 7; // RW data
            Self { tables, data: [0;4096] }
        }
        fn pte(&self, addr: u64) -> Option<u64> {
            if !(0x1000..0x5000).contains(&addr) { return None }
            let level = ((addr - 0x1000) / 4096) as usize;
            let slot = ((addr & 4095) / 8) as usize;
            self.tables.get(level)?.get(slot).copied()
        }
    }
    #[test]
    fn validates_every_level_and_all_permission_bits() {
        let mut p = Pages::new();
        assert_eq!(walk(0x1000,0x401000,Access::Read,|x|p.pte(x)),Ok(0x5000));
        assert_eq!(walk(0x1000,0x401000,Access::Write,|x|p.pte(x)),Err(CopyError::ReadOnly));
        assert_eq!(walk(0x1000,0x403000,Access::Write,|x|p.pte(x)),Ok(0x6000));
        for level in 0..4 {
            let loc = [0,0,2,3][level];
            let old = p.tables[level][loc];
            p.tables[level][loc] &= !USER;
            assert_eq!(walk(0x1000,0x403000,Access::Read,|x|p.pte(x)),Err(CopyError::Supervisor));
            p.tables[level][loc] = old;
            p.tables[level][loc] &= !WRITE;
            assert_eq!(walk(0x1000,0x403000,Access::Write,|x|p.pte(x)),Err(CopyError::ReadOnly));
            p.tables[level][loc] = old;
            p.tables[level][loc] &= !PRESENT;
            assert_eq!(walk(0x1000,0x403000,Access::Read,|x|p.pte(x)),Err(CopyError::NotPresent));
            p.tables[level][loc] = old;
        }
        p.tables[1][0] |= HUGE;
        assert_eq!(walk(0x1000,0x403000,Access::Read,|x|p.pte(x)),Err(CopyError::UnsupportedHugePage));
    }
    #[test]
    fn reject_supervisor_high_half_overflow_null_and_overlong() {
        let p = Pages::new();
        for x in [0,0x1000,0xffff_8000_0000_0000,u64::MAX,0x8000_0000_0000] {
            assert_eq!(walk(0x1000,x,Access::Read,|a|p.pte(a)),Err(CopyError::InvalidRange));
        }
        assert_eq!(walk(0,0x401000,Access::Read,|a|p.pte(a)),Err(CopyError::InvalidPageTable));
        assert_eq!(checked_range(0x7fff_ffff_ffff,2),Err(CopyError::InvalidRange));
        assert_eq!(checked_range(0x401000,MAX_COPY+1),Err(CopyError::Oversized));
    }
    #[test]
    fn invalid_second_page_is_checked_before_any_destination_mutation() {
        let p=Pages::new();
        let mut out=[0xa5u8;3];
        let result=copy_from(0x1000,0x401ffe,&mut out,|a|p.pte(a),|_|Some(55));
        assert_eq!(result,Err(CopyError::NotPresent));
        assert_eq!(out,[0xa5;3]);
    }
    #[test]
    fn copy_to_readonly_rejected_and_data_readback() {
        let mut p=Pages::new();
        let result=copy_to(0x1000,0x401000,b"oops",|a|p.pte(a),|_,_|Some(0));
        assert_eq!(result,Err(CopyError::ReadOnly));
        let ptes=p.tables;
        copy_to(0x1000,0x403000,b"safe",
            |a|{ let level=((a-0x1000)/4096) as usize;let slot=((a & 4095)/8) as usize;ptes.get(level)?.get(slot).copied() },
            |phys,write|{let idx=usize::try_from(phys.checked_sub(0x6000)?).ok()?;let cell=p.data.get_mut(idx)?;if let Some(byte)=write {*cell=byte};Some(*cell)}
        ).unwrap();
        let mut out=[0u8;4];
        copy_from(0x1000,0x403000,&mut out,|a|p.pte(a),
            |phys|p.data.get(usize::try_from(phys.checked_sub(0x6000)?).ok()?).copied()).unwrap();
        assert_eq!(&out,b"safe");
    }
}
