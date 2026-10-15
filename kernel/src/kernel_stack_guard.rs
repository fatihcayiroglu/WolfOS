//! Checked x86-64 4-level *isolated kernel test* stack mapping.
//!
//! Two never-present virtual guards surround FOUR separately PMM-owned
//! mapped 4-KiB supervisor pages. Physical pages need NOT be contiguous.
//! A HHDM alias to physical pages remains present: this proves accesses to
//! the *dedicated guard virtual address* fault, NOT that no other alias exists.
//! The temporary slot is intentionally LOW canonical (never a Ring3 stack),
//! U/S=0 on every new level; production requires a high-half VMM arena.
pub const PAGE: u64 = 4096;
pub const STACK_PAGES: usize = 4;
pub const OWNED: usize = 7; // new PDPT + PD + PT + four independent stack pages
pub const ENTRIES: usize = 512;
pub const BASE: u64 = 0x0000_5000_0000_0000; // distinct from P1 0x4000... slot
pub const LOWER_GUARD: u64 = BASE;
pub const STACK_BOTTOM: u64 = BASE + PAGE;
pub const STACK_TOP: u64 = BASE + 5 * PAGE;
pub const UPPER_GUARD: u64 = STACK_TOP;
pub const ROOT_INDEX: usize = ((BASE >> 39) & 511) as usize;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const PHYS_MASK: u64 = 0x000f_ffff_ffff_f000;
const MAX_PHYS: u64 = 1 << 52;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardError {
    InvalidRoot, BadFrame, DuplicateFrame, TargetAlreadyMapped,
    BadTable, BadGuard, WrongLeaf, UnexpectedAlias,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardPlan {
    pub pages: [u64; OWNED],
}

impl GuardPlan {
    pub fn new(pages: [u64; OWNED], boot_root: u64)
        -> Result<Self, GuardError>
    {
        if boot_root == 0 || boot_root & (PAGE - 1) != 0
            || boot_root >= MAX_PHYS { return Err(GuardError::InvalidRoot) }
        for (i, &frame) in pages.iter().enumerate() {
            if frame == 0 || frame >= MAX_PHYS || frame & (PAGE - 1) != 0 {
                return Err(GuardError::BadFrame)
            }
            if frame == boot_root || pages[..i].contains(&frame) {
                return Err(GuardError::DuplicateFrame)
            }
        }
        Ok(Self { pages })
    }

    pub fn expected(physical: u64) -> u64 {
        physical | PRESENT | WRITABLE // deliberately NO U/S permission
    }

    /// All checks before writing the live root. Caller must ensure
    /// exclusive ownership, interrupts masked, no AP/scheduler users and
    /// HHDM access to the private PMM frames.
    pub fn populate(
        &self, root: &mut [u64; ENTRIES],
        pdpt: &mut [u64; ENTRIES],
        pd: &mut [u64; ENTRIES],
        pt: &mut [u64; ENTRIES],
    ) -> Result<(), GuardError> {
        if root[ROOT_INDEX] != 0 { return Err(GuardError::TargetAlreadyMapped) }
        if pdpt.iter().chain(pd).chain(pt).any(|x| *x != 0) {
            return Err(GuardError::BadTable)
        }
        // Only the final store to the active PML4 publishes new mappings;
        // all child entries are set up privately before that store.
        for (i, p) in self.pages[3..].iter().copied().enumerate() {
            pt[i + 1] = Self::expected(p); // guard entries 0 and 5 untouched
        }
        pd[0] = Self::expected(self.pages[2]);
        pdpt[0] = Self::expected(self.pages[1]);
        root[ROOT_INDEX] = Self::expected(self.pages[0]);
        Ok(())
    }

    /// Independently audit upper/root disjointness and guard non-presence.
    pub fn audit(
        &self, root: &[u64; ENTRIES],
        pdpt: &[u64; ENTRIES],
        pd: &[u64; ENTRIES],
        pt: &[u64; ENTRIES],
    ) -> Result<(), GuardError> {
        if root[ROOT_INDEX] != Self::expected(self.pages[0])
            || pdpt[0] != Self::expected(self.pages[1])
            || pd[0] != Self::expected(self.pages[2])
            || root[ROOT_INDEX] & USER != 0
        { return Err(GuardError::BadTable) }
        if pdpt[1..].iter().chain(pd[1..]).any(|x| *x != 0)
            || pt[6..].iter().any(|x| *x != 0) {
            return Err(GuardError::UnexpectedAlias)
        }
        if pt[0] != 0 || pt[5] != 0 { return Err(GuardError::BadGuard) }
        for i in 0..STACK_PAGES {
            if pt[i+1] != Self::expected(self.pages[i+3])
                || pt[i+1] & USER != 0 || pt[i+1] & PHYS_MASK != self.pages[i+3] {
                return Err(GuardError::WrongLeaf)
            }
        }
        Ok(())
    }

    /// Unpublish all child mappings before releasing their PMM frames.
    /// Caller must perform one architectural TLB invalidation per leaf
    /// after this returns and before any page can reenter the PMM.
    pub fn unpublish(
        &self, root: &mut [u64; ENTRIES],
        pdpt: &mut [u64; ENTRIES],
        pd: &mut [u64; ENTRIES],
        pt: &mut [u64; ENTRIES],
    ) -> Result<(), GuardError> {
        self.audit(root,pdpt,pd,pt)?;
        root[ROOT_INDEX] = 0;
        pdpt[0] = 0;
        pd[0] = 0;
        for i in 1..=STACK_PAGES { pt[i] = 0 }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pages() -> [u64;OWNED] {
        [0x1000,0x2000,0x3000,0xa000,0x20000,0x18000,0x50000]
    }
    fn arrays() -> [[u64;ENTRIES];4] { [[0;ENTRIES];4] }
    #[test]
    fn leaves_two_guards_unmapped_and_pages_supervisor_only() {
        let p=GuardPlan::new(pages(),0x9000).unwrap();
        let [mut root,mut pdpt,mut pd,mut pt]=arrays();
        p.populate(&mut root,&mut pdpt,&mut pd,&mut pt).unwrap();
        assert_eq!(p.audit(&root,&pdpt,&pd,&pt),Ok(()));
        assert_eq!(pt[0],0); assert_eq!(pt[5],0);
        assert!(pt[1..5].iter().all(|p| p & USER == 0));
        p.unpublish(&mut root,&mut pdpt,&mut pd,&mut pt).unwrap();
        assert_eq!(root[ROOT_INDEX],0);
        assert_eq!(pt[1..5],[0u64;4]);
    }
    #[test]
    fn alias_frame_or_dirty_target_denied_without_publishing() {
        let mut fr=pages(); fr[6]=fr[3];
        assert_eq!(GuardPlan::new(fr,0x9000),Err(GuardError::DuplicateFrame));
        fr=pages(); fr[2]=0x9000;
        assert_eq!(GuardPlan::new(fr,0x9000),Err(GuardError::DuplicateFrame));
        fr=pages(); fr[2]=123;
        assert_eq!(GuardPlan::new(fr,0x9000),Err(GuardError::BadFrame));
        let p=GuardPlan::new(pages(),0x9000).unwrap();
        let [mut root,mut pdpt,mut pd,mut pt]=arrays();
        root[ROOT_INDEX]=1;
        assert_eq!(p.populate(&mut root,&mut pdpt,&mut pd,&mut pt),
            Err(GuardError::TargetAlreadyMapped));
        assert!(pt.iter().all(|x| *x==0));
        root[ROOT_INDEX]=0; pt[55]=0x9003;
        assert_eq!(p.populate(&mut root,&mut pdpt,&mut pd,&mut pt),
            Err(GuardError::BadTable));
        assert_eq!(root[ROOT_INDEX],0);
    }
    #[test]
    fn audits_detect_reenabled_guard_and_user_escalation() {
        let p=GuardPlan::new(pages(),0x9000).unwrap();
        let [mut root,mut pdpt,mut pd,mut pt]=arrays();
        p.populate(&mut root,&mut pdpt,&mut pd,&mut pt).unwrap();
        pt[0]=GuardPlan::expected(0x60000);
        assert_eq!(p.audit(&root,&pdpt,&pd,&pt),Err(GuardError::BadGuard));
        pt[0]=0; pt[3]|=USER;
        assert_eq!(p.audit(&root,&pdpt,&pd,&pt),Err(GuardError::WrongLeaf));
        pt[3]&=!USER;
        root[ROOT_INDEX]|=USER;
        assert_eq!(p.audit(&root,&pdpt,&pd,&pt),Err(GuardError::BadTable));
    }
}
