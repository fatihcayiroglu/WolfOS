//! Fixed two-PID supervisor stack virtual arena, not a general VMM.
//!
//! Three PMM page-table frames establish an independently reserved HIGH
//! canonical PML4 slot. Two separately owned stacks each have [nonpresent
//! guard, four PRESENT|RW supervisor leaves, nonpresent guard]. The eight
//! leaf frames need not be physically adjacent. Bootloader HHDM aliases
//! deliberately remain and are NOT themselves guarded.
//!
//! The only live-CR3 mutation is publication into a verified empty root
//! entry and a later complete unpublication while BSP IF=0 and APs parked.
//! No CPU uses these as its actual RSP/TSS.RSP0 in this phase.
pub const PAGE: u64 = 4096;
pub const STACK_PAGES: usize = 4;
pub const SLOTS: usize = 2;
pub const PT_ENTRIES: usize = 512;
pub const TABLE_PAGES: usize = 3;
pub const OWNED: usize = TABLE_PAGES + SLOTS * STACK_PAGES;
pub const BASE: u64 = 0xffff_d000_0000_0000;
pub const ROOT_INDEX: usize = ((BASE >> 39) & 511) as usize;
pub const SLOT_STRIDE: u64 = (STACK_PAGES as u64 + 2) * PAGE;
const P: u64 = 1;
const RW: u64 = 2;
const USER: u64 = 4;
const A: u64 = 1 << 5;
const D: u64 = 1 << 6;
const MAX_PHYS: u64 = 1 << 52;

pub fn lower_guard(slot: usize) -> u64 { BASE + slot as u64 * SLOT_STRIDE }
pub fn bottom(slot: usize) -> u64 { lower_guard(slot) + PAGE }
pub fn top(slot: usize) -> u64 { bottom(slot) + STACK_PAGES as u64 * PAGE }
pub fn upper_guard(slot: usize) -> u64 { top(slot) }
fn at(slot: usize) -> usize { slot * (STACK_PAGES+2) }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArenaError {
    BadRoot, BadFrame, DuplicateFrame, DuplicatePid, Capacity,
    RootOccupied, DirtyTables, MissingPid, StaleHandle,
    Published, NotPublished, BadTable, BadGuard, WrongLeaf, Busy,
    GenerationExhausted,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handle { pub slot: usize, pub generation: u64, pub pid: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stack {
    pub handle: Handle,
    pub frames: [u64; STACK_PAGES],
    pub bottom: u64,
    pub top: u64,
}
#[derive(Clone, Copy)]
struct Entry { generation: u64, stack: Option<Stack> }
impl Entry {
    const fn new() -> Self { Self { generation: 0, stack: None } }
}
pub struct GuardedArena {
    tables: [u64; TABLE_PAGES],
    root: u64,
    entries: [Entry; SLOTS],
    published: bool,
}
impl GuardedArena {
    pub fn new(tables: [u64; TABLE_PAGES], root: u64) -> Result<Self,ArenaError> {
        if root == 0 || root & (PAGE-1) != 0 || root >= MAX_PHYS
            || ROOT_INDEX < 256 || ROOT_INDEX >= 511 {
            return Err(ArenaError::BadRoot)
        }
        for (i,&p) in tables.iter().enumerate() {
            if p == 0 || p & (PAGE-1) != 0 || p >= MAX_PHYS {
                return Err(ArenaError::BadFrame)
            }
            if p == root || tables[..i].contains(&p) {
                return Err(ArenaError::DuplicateFrame)
            }
        }
        Ok(Self { tables,root,entries: [const { Entry::new() }; SLOTS],published:false })
    }
    pub fn occupied(&self) -> usize {
        self.entries.iter().filter(|e| e.stack.is_some()).count()
    }
    pub fn table_frames(&self) -> [u64;TABLE_PAGES] { self.tables }

    pub fn reserve(&mut self,pid:u64,frames:[u64;STACK_PAGES])
        -> Result<Stack,ArenaError>
    {
        if self.published { return Err(ArenaError::Published) }
        if pid == 0 { return Err(ArenaError::MissingPid) }
        if self.entries.iter().filter_map(|e| e.stack)
            .any(|stack| stack.handle.pid == pid) {
            return Err(ArenaError::DuplicatePid)
        }
        for (i,&phys) in frames.iter().enumerate() {
            if phys == 0 || phys & (PAGE-1) != 0 || phys >= MAX_PHYS {
                return Err(ArenaError::BadFrame)
            }
            if phys == self.root || self.tables.contains(&phys)
                || frames[..i].contains(&phys)
                || self.entries.iter().filter_map(|e| e.stack)
                    .any(|s| s.frames.contains(&phys)) {
                return Err(ArenaError::DuplicateFrame)
            }
        }
        let (slot,entry)=self.entries.iter_mut().enumerate()
            .find(|(_,e)|e.stack.is_none()).ok_or(ArenaError::Capacity)?;
        let generation=entry.generation.checked_add(1)
            .ok_or(ArenaError::GenerationExhausted)?;
        let stack=Stack {
            handle:Handle{slot,generation,pid},frames,
            bottom:bottom(slot),top:top(slot),
        };
        entry.generation=generation;
        entry.stack=Some(stack);
        Ok(stack)
    }
    pub fn inspect(&self,h:Handle)->Result<Stack,ArenaError> {
        let e=self.entries.get(h.slot).ok_or(ArenaError::StaleHandle)?;
        if e.generation!=h.generation || h.generation==0 {
            return Err(ArenaError::StaleHandle)
        }
        match e.stack {
            Some(s) if s.handle==h => Ok(s),
            _=>Err(ArenaError::StaleHandle)
        }
    }
    fn expected(p:u64)->u64 { p | P | RW }
    fn matches(e:u64,p:u64,leaf:bool)->bool {
        e & !(A | if leaf{D}else{0}) == Self::expected(p)
    }
    fn all_ready(&self)->Result<(),ArenaError> {
        if self.occupied()!=SLOTS { return Err(ArenaError::MissingPid) }
        Ok(())
    }

    /// SAFETY: caller uniquely owns all four page-table slice aliases,
    /// has proved empty PML4 slot and holds BSP IF=0; no AP touches it.
    pub fn publish(
        &mut self,root:&mut [u64;PT_ENTRIES],pdpt:&mut [u64;PT_ENTRIES],
        pd:&mut [u64;PT_ENTRIES],pt:&mut [u64;PT_ENTRIES],
    )->Result<(),ArenaError> {
        if self.published { return Err(ArenaError::Published) }
        self.all_ready()?;
        if root[ROOT_INDEX]!=0 {return Err(ArenaError::RootOccupied)}
        if pdpt.iter().chain(pd.iter()).chain(pt.iter()).any(|x|*x!=0){
            return Err(ArenaError::DirtyTables)
        }
        for slot in 0..SLOTS {
            let stack=self.entries[slot].stack.ok_or(ArenaError::MissingPid)?;
            for leaf in 0..STACK_PAGES {
                pt[at(slot)+1+leaf]=Self::expected(stack.frames[leaf]);
            }
        }
        // Both guards for each stack remain ZERO, including adjacent
        // guards for consecutive slots (5 and 6).
        pd[0]=Self::expected(self.tables[2]);
        pdpt[0]=Self::expected(self.tables[1]);
        root[ROOT_INDEX]=Self::expected(self.tables[0]); // LAST store
        self.published=true;
        Ok(())
    }
    pub fn audit(
        &self,root:&[u64;PT_ENTRIES],pdpt:&[u64;PT_ENTRIES],
        pd:&[u64;PT_ENTRIES],pt:&[u64;PT_ENTRIES],
    )->Result<(),ArenaError>{
        if !self.published{return Err(ArenaError::NotPublished)}
        if !Self::matches(root[ROOT_INDEX],self.tables[0],false)
            || !Self::matches(pdpt[0],self.tables[1],false)
            || !Self::matches(pd[0],self.tables[2],false)
            || root[ROOT_INDEX]&USER!=0 {
            return Err(ArenaError::BadTable)
        }
        if pdpt[1..].iter().chain(pd[1..].iter()).any(|x|*x!=0)
            || pt[SLOTS*(STACK_PAGES+2)..].iter().any(|x|*x!=0) {
            return Err(ArenaError::BadTable)
        }
        for slot in 0..SLOTS {
            let s=self.entries[slot].stack.ok_or(ArenaError::MissingPid)?;
            let index=at(slot);
            if pt[index]!=0 || pt[index+STACK_PAGES+1]!=0 {
                return Err(ArenaError::BadGuard)
            }
            for leaf in 0..STACK_PAGES {
                if !Self::matches(pt[index+leaf+1],s.frames[leaf],true) {
                    return Err(ArenaError::WrongLeaf)
                }
            }
        }
        Ok(())
    }
    /// Unpublish first, then caller MUST flush every mapped/guard VA
    /// before freeing/retiring PMM frames, on an independent supervisor RSP.
    pub fn unpublish(
        &mut self,root:&mut [u64;PT_ENTRIES],pdpt:&mut [u64;PT_ENTRIES],
        pd:&mut [u64;PT_ENTRIES],pt:&mut [u64;PT_ENTRIES],
    )->Result<(),ArenaError>{
        self.audit(root,pdpt,pd,pt)?;
        root[ROOT_INDEX]=0;
        pdpt[0]=0;
        pd[0]=0;
        for p in &mut pt[..SLOTS*(STACK_PAGES+2)] {*p=0}
        self.published=false;
        Ok(())
    }

    /// # Safety
    /// Caller must verify the PML4 entry is absent, all CPU TLB entries
    /// invalidated, all tasks/scheduler stopped, no live RSP/TSS use and
    /// owning PID revoked. The returned frames can then be freed once.
    pub unsafe fn retire_after_quiescence(&mut self,h:Handle)
        ->Result<[u64;STACK_PAGES],ArenaError>{
        if self.published {return Err(ArenaError::Busy)}
        let s=self.inspect(h)?;
        self.entries[h.slot].stack=None;
        Ok(s.frames)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn arena()->GuardedArena {
        GuardedArena::new([0x1000,0x2000,0x3000],0x9000).unwrap()
    }
    fn frames(a:u64)->[u64;4]{
        [a,a+0x5000,a+0x2000,a+0xa000] // intentionally noncontiguous
    }
    #[test]
    fn two_pids_have_distinct_high_half_guarded_stacks(){
        let mut a=arena();
        let x=a.reserve(1,frames(0x10000)).unwrap();
        let y=a.reserve(2,frames(0x30000)).unwrap();
        assert!(x.bottom>=0xffff_8000_0000_0000);
        assert!(x.top<y.bottom);
        assert_eq!(x.top,upper_guard(0));
        assert_eq!(y.bottom,lower_guard(1)+PAGE);
        let [mut root,mut pdpt,mut pd,mut pt]=[[0u64;PT_ENTRIES];4];
        a.publish(&mut root,&mut pdpt,&mut pd,&mut pt).unwrap();
        assert_eq!(a.audit(&root,&pdpt,&pd,&pt),Ok(()));
        for i in [0,5,6,11]{assert_eq!(pt[i],0)}
        for i in [1,2,3,4,7,8,9,10]{assert_eq!(pt[i]&USER,0)}
        // Architectural CPU A/D bits do not invalidate honest ownership.
        root[ROOT_INDEX]|=A; pdpt[0]|=A; pd[0]|=A;
        for i in [1,2,3,4,7,8,9,10]{pt[i]|=A|D;}
        assert_eq!(a.audit(&root,&pdpt,&pd,&pt),Ok(()));
        assert_eq!(unsafe{a.retire_after_quiescence(x.handle)},Err(ArenaError::Busy));
        a.unpublish(&mut root,&mut pdpt,&mut pd,&mut pt).unwrap();
        assert_eq!(root[ROOT_INDEX],0);
        assert_eq!(unsafe{a.retire_after_quiescence(x.handle)},Ok(x.frames));
        assert_eq!(unsafe{a.retire_after_quiescence(y.handle)},Ok(y.frames));
        let next=a.reserve(3,frames(0x10000)).unwrap();
        assert_eq!(next.handle.slot,0);
        assert_eq!(next.handle.generation,x.handle.generation+1);
        assert_eq!(a.inspect(x.handle),Err(ArenaError::StaleHandle));
    }
    #[test]
    fn refuses_cross_pid_alias_and_exhaustion_transactionally(){
        let mut a=arena();
        let x=a.reserve(1,frames(0x10000)).unwrap();
        assert_eq!(a.reserve(1,frames(0x30000)),Err(ArenaError::DuplicatePid));
        let mut overlap=frames(0x30000);overlap[1]=x.frames[3];
        assert_eq!(a.reserve(2,overlap),Err(ArenaError::DuplicateFrame));
        overlap=frames(0x30000);overlap[0]=a.table_frames()[0];
        assert_eq!(a.reserve(2,overlap),Err(ArenaError::DuplicateFrame));
        assert_eq!(a.occupied(),1);
        a.reserve(2,frames(0x30000)).unwrap();
        assert_eq!(a.reserve(3,frames(0x50000)),Err(ArenaError::Capacity));
    }
    #[test]
    fn no_partial_pte_publication_on_dirty_root_or_invalid_tables(){
        let mut a=arena();
        a.reserve(1,frames(0x10000)).unwrap();
        a.reserve(2,frames(0x30000)).unwrap();
        let [mut root,mut pdpt,mut pd,mut pt]=[[0u64;PT_ENTRIES];4];
        root[ROOT_INDEX]=1;
        assert_eq!(a.publish(&mut root,&mut pdpt,&mut pd,&mut pt),
            Err(ArenaError::RootOccupied));
        assert!(pt.iter().all(|x|*x==0));
        root[ROOT_INDEX]=0;pt[50]=1;
        assert_eq!(a.publish(&mut root,&mut pdpt,&mut pd,&mut pt),
            Err(ArenaError::DirtyTables));
        assert_eq!(root[ROOT_INDEX],0);
    }
    #[test]
    fn reenabled_guard_and_changed_user_permission_are_detected(){
        let mut a=arena();
        a.reserve(1,frames(0x10000)).unwrap();
        a.reserve(2,frames(0x30000)).unwrap();
        let [mut root,mut pdpt,mut pd,mut pt]=[[0u64;PT_ENTRIES];4];
        a.publish(&mut root,&mut pdpt,&mut pd,&mut pt).unwrap();
        pt[6]=3;
        assert_eq!(a.audit(&root,&pdpt,&pd,&pt),Err(ArenaError::BadGuard));
        pt[6]=0;pt[7]|=USER;
        assert_eq!(a.audit(&root,&pdpt,&pd,&pt),Err(ArenaError::WrongLeaf));
    }
}
