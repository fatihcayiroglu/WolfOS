//! Pure owner/permission contract for a future BSP xAPIC mapping shared
//! into per-process *supervisor* high-half roots. No MMIO or IRQ writes.
//!
//! A lower-half APIC alias in the boot page table is NOT accessible in
//! independently sanitized userspace CR3 roots. Use one dedicated high
//! canonical PML4 slot, verify U/S=0 at EVERY page-table level, and make
//! device memory uncacheable (PCD|PWT). No executable mappings.
pub const TIMER_VA:u64=0xffff_c800_0000_0000;
pub const ROOT_INDEX:usize=((TIMER_VA>>39)&511) as usize;
pub const STACK_ROOT_INDEX:usize=((0xffff_d000_0000_0000u64>>39)&511) as usize;
const PRESENT:u64=1;const RW:u64=2;const USER:u64=4;
const PWT:u64=8;const PCD:u64=16;const LARGE:u64=128;
const NX:u64=1<<63;const ADDRESS:u64=0x000f_ffff_ffff_f000;
const A:u64=1<<5;const D:u64=1<<6;
const PHYS_LIMIT:u64=1<<52;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum MappingError{
    InvalidVirtualSlot,Occupied,FrameAlignment,OwnedFrameAlias,
    UnsafePageTableFlags,UnsafeDeviceFlags,KernelRootMismatch,
    UserAccessible,RootNotPublished,
}
fn valid_pa(p:u64)->bool{p!=0&&p&4095==0&&p<PHYS_LIMIT}
fn table_ok(e:u64,pa:u64)->bool{
    (e&!(A)==pa|PRESENT|RW)&&e&USER==0&&e&LARGE==0
}
fn device_ok(e:u64,pa:u64)->bool{
    (e&!(A|D))==pa|PRESENT|RW|PWT|PCD|NX
        &&e&USER==0&&e&LARGE==0
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct ApicMapping {
    /// Exclusively owned PMM table frames: PDPT, PD and PT.
    pub tables:[u64;3],
    /// Validated IA32_APIC_BASE physical page, NOT PMM-owned RAM.
    pub mmio_pa:u64,
}
impl ApicMapping {
    pub fn new(tables:[u64;3],mmio_pa:u64,active_roots:&[u64])
        ->Result<Self,MappingError>
    {
        if ROOT_INDEX<256||ROOT_INDEX>=511
            ||ROOT_INDEX==STACK_ROOT_INDEX{
            return Err(MappingError::InvalidVirtualSlot)
        }
        if !valid_pa(mmio_pa)||tables.iter().any(|p|!valid_pa(*p)){
            return Err(MappingError::FrameAlignment)
        }
        for(i,&p)in tables.iter().enumerate(){
            if p==mmio_pa||active_roots.contains(&p)
                ||tables[..i].contains(&p) {
                return Err(MappingError::OwnedFrameAlias)
            }
        }
        if active_roots.contains(&mmio_pa){
            return Err(MappingError::OwnedFrameAlias)
        }
        Ok(Self{tables,mmio_pa})
    }
    /// Caller separately proves the MMIO page is NOT managed RAM, that
    /// xAPIC (rather than x2APIC) is enabled, and holds exclusive BSP IF=0.
    pub fn publish(&self,boot:&mut[u64;512],pdpt:&mut[u64;512],
       pd:&mut[u64;512],pt:&mut[u64;512])->Result<(),MappingError>
    {
        if boot[ROOT_INDEX]!=0||pdpt.iter().any(|e|*e!=0)
           ||pd.iter().any(|e|*e!=0)||pt.iter().any(|e|*e!=0){
            return Err(MappingError::Occupied)
        }
        // Four exact levels. This is NOT a general-purpose page mapper.
        boot[ROOT_INDEX]=self.tables[0]|PRESENT|RW;
        pdpt[0]=self.tables[1]|PRESENT|RW;
        pd[0]=self.tables[2]|PRESENT|RW;
        pt[0]=self.mmio_pa|PRESENT|RW|PWT|PCD|NX;
        Ok(())
    }
    pub fn audit(&self,boot:&[u64;512],pdpt:&[u64;512],
       pd:&[u64;512],pt:&[u64;512])->Result<(),MappingError>
    {
        if !table_ok(boot[ROOT_INDEX],self.tables[0])||
           !table_ok(pdpt[0],self.tables[1])||
           !table_ok(pd[0],self.tables[2]){
            return Err(MappingError::UnsafePageTableFlags)
        }
        if !device_ok(pt[0],self.mmio_pa){
            return Err(MappingError::UnsafeDeviceFlags)
        }
        if pdpt[1..].iter().any(|e|*e!=0)||
           pd[1..].iter().any(|e|*e!=0)||
           pt[1..].iter().any(|e|*e!=0){
            return Err(MappingError::UnsafePageTableFlags)
        }
        Ok(())
    }
    /// A copied process root must share the exact *supervisor* APIC
    /// hierarchy: never allow U/S on the PML4 root nor a foreign table.
    pub fn audit_process_root(&self,boot:&[u64;512],
       private:&[u64;512])->Result<(),MappingError>{
        if !table_ok(boot[ROOT_INDEX],self.tables[0]){
            return Err(MappingError::RootNotPublished)
        }
        if private[ROOT_INDEX]&USER!=0{return Err(MappingError::UserAccessible)}
        if private[ROOT_INDEX]!=boot[ROOT_INDEX]{
            return Err(MappingError::KernelRootMismatch)
        }
        Ok(())
    }
    /// Must be called ONLY after all private CR3 roots are no longer
    /// active and no processor can access this device alias.
    pub fn unpublish(&self,boot:&mut[u64;512],pdpt:&mut[u64;512],
      pd:&mut[u64;512],pt:&mut[u64;512])->Result<(),MappingError>{
        self.audit(boot,pdpt,pd,pt)?;
        boot[ROOT_INDEX]=0;
        pdpt[0]=0;pd[0]=0;pt[0]=0;
        Ok(())
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    fn frames()->ApicMapping {
        ApicMapping::new([0x1000,0x2000,0x3000],0xfee0_0000,&[0x5000,0x6000]).unwrap()
    }
    #[test]
    fn isolated_canonical_slot_and_supervisor_uncached_nx_leaf(){
        assert_ne!(ROOT_INDEX,STACK_ROOT_INDEX);
        assert!((256..511).contains(&ROOT_INDEX));
        let m=frames();
        let(mut boot,mut a,mut b,mut c)=([0;512],[0;512],[0;512],[0;512]);
        m.publish(&mut boot,&mut a,&mut b,&mut c).unwrap();
        assert_eq!(m.audit(&boot,&a,&b,&c),Ok(()));
        let mut guest=[0;512];guest[ROOT_INDEX]=boot[ROOT_INDEX];
        assert_eq!(m.audit_process_root(&boot,&guest),Ok(()));
        m.unpublish(&mut boot,&mut a,&mut b,&mut c).unwrap();
        assert_eq!(boot[ROOT_INDEX],0);
    }
    #[test]
    fn rejects_alias_dirty_and_malformed_table_pages(){
        assert_eq!(ApicMapping::new([0x1001,0x2000,0x3000],0xfee0_0000,&[]),
            Err(MappingError::FrameAlignment));
        assert_eq!(ApicMapping::new([0x1000,0x1000,0x3000],0xfee0_0000,&[]),
            Err(MappingError::OwnedFrameAlias));
        let m=frames();
        let(mut root,mut a,mut b,mut c)=([0;512],[0;512],[0;512],[0;512]);
        root[ROOT_INDEX]=1;
        assert_eq!(m.publish(&mut root,&mut a,&mut b,&mut c),
            Err(MappingError::Occupied));
        root[ROOT_INDEX]=0;c[2]=1;
        assert_eq!(m.publish(&mut root,&mut a,&mut b,&mut c),
            Err(MappingError::Occupied));
    }
    #[test]
    fn rejects_user_executable_cacheable_wrong_and_extra_mappings(){
        let m=frames();
        let(mut root,mut a,mut b,mut c)=([0;512],[0;512],[0;512],[0;512]);
        m.publish(&mut root,&mut a,&mut b,&mut c).unwrap();
        c[0]|=USER;assert_eq!(m.audit(&root,&a,&b,&c),Err(MappingError::UnsafeDeviceFlags));
        c[0]&=!USER;c[0]&=!NX;
        assert_eq!(m.audit(&root,&a,&b,&c),Err(MappingError::UnsafeDeviceFlags));
        c[0]|=NX;c[0]&=!PCD;
        assert_eq!(m.audit(&root,&a,&b,&c),Err(MappingError::UnsafeDeviceFlags));
        c[0]|=PCD;c[1]=1;
        assert_eq!(m.audit(&root,&a,&b,&c),Err(MappingError::UnsafePageTableFlags));
        c[1]=0;root[ROOT_INDEX]|=USER;
        assert_eq!(m.audit(&root,&a,&b,&c),Err(MappingError::UnsafePageTableFlags));
        root[ROOT_INDEX]&=!USER;
        let mut guest=[0;512];guest[ROOT_INDEX]=root[ROOT_INDEX]|USER;
        assert_eq!(m.audit_process_root(&root,&guest),Err(MappingError::UserAccessible));
        guest[ROOT_INDEX]=0x7000|PRESENT|RW;
        assert_eq!(m.audit_process_root(&root,&guest),Err(MappingError::KernelRootMismatch));
    }
}
