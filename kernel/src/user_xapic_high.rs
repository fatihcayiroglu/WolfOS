//! Isolated BSP xAPIC high-half uncached 4KiB MMIO mapping.
//! Unlike the old low-half smoke alias, this supervisor-only PML4 entry
//! is inherited into BOTH private Ring3 CR3 roots, so real IRQ EOI can
//! execute after the processor changed CR3 without mapping MMIO to user.
#[cfg(not(test))]
use core::ptr;
pub const VA:u64=0xffff_e000_0000_1000;
pub const ROOT_INDEX:usize=((VA>>39)&0x1ff) as usize;
const P:u64=1;const W:u64=2;const U:u64=4;
const PWT:u64=8;const PCD:u64=16;const NX:u64=1<<63;
pub const MMIO_FLAGS:u64=P|W|PWT|PCD|NX;

#[derive(Debug,PartialEq,Eq)]
pub enum Error{WrongSlot,InvalidFrame,InvalidMmio,Busy,Missing,UserAccessible}

pub fn validate(boot_entry:u64,mmio_phys:u64,frames:[u64;3])
    ->Result<(),Error>{
    if ROOT_INDEX<256||ROOT_INDEX>=511{return Err(Error::WrongSlot)}
    if boot_entry!=0{return Err(Error::Busy)}
    if mmio_phys==0||mmio_phys&4095!=0{return Err(Error::InvalidMmio)}
    for i in 0..3{
        if frames[i]==0||frames[i]&4095!=0||
           frames[i]==mmio_phys||
           frames[..i].contains(&frames[i]){
            return Err(Error::InvalidFrame)
        }
    }
    Ok(())
}
/// The caller must verify the physical xAPIC MMIO base against CPUID,
/// IA32_APIC_BASE and the firmware RAM map before calling this.
///
/// # Safety
/// Exclusive BSP; IF=0, no live private roots yet, PMM owns all 3 frames,
/// HHDM maps all frames as writable supervisor, and root slot is unused.
#[cfg(not(test))]
pub unsafe fn publish(hhdm:u64,boot_root:u64,mmio_phys:u64,
    frames:[u64;3])->Result<(),Error>{
    let root=unsafe{&mut *((hhdm+boot_root) as *mut [u64;512])};
    validate(root[ROOT_INDEX],mmio_phys,frames)?;
    let pdpt=unsafe{&mut *((hhdm+frames[0]) as *mut [u64;512])};
    let pd=unsafe{&mut *((hhdm+frames[1]) as *mut [u64;512])};
    let pt=unsafe{&mut *((hhdm+frames[2]) as *mut [u64;512])};
    // SAFETY: three inactive, PMM-exclusive, page-aligned writable pages.
    unsafe{
        ptr::write_bytes(pdpt.as_mut_ptr(),0,512);
        ptr::write_bytes(pd.as_mut_ptr(),0,512);
        ptr::write_bytes(pt.as_mut_ptr(),0,512);
    }
    pdpt[0]=frames[1]|P|W|NX;
    pd[0]=frames[2]|P|W|NX;
    pt[1]=mmio_phys|MMIO_FLAGS;
    root[ROOT_INDEX]=frames[0]|P|W|NX;
    x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(VA));
    if root[ROOT_INDEX]&U!=0 || pt[1]&U!=0{
        return Err(Error::UserAccessible)
    }
    Ok(())
}
/// Read a register only through the verified permanent uncached supervisor
/// alias. The address MUST be mapped before call in the active CR3.
///
/// # Safety
/// BSP xAPIC, high mapping verified, 16-byte aligned register index.
#[cfg(not(test))]
pub unsafe fn read(offset:usize)->u32{
    unsafe{((VA as usize+offset) as *const u32).read_volatile()}
}
/// # Safety
/// Same as read(); exclusively owned and genuine xAPIC in MMIO mode.
#[cfg(not(test))]
pub unsafe fn write(offset:usize,value:u32){
    unsafe{((VA as usize+offset) as *mut u32).write_volatile(value);}
}
/// Remove high MMIO tree ONLY after local timer masked, BSP IF=0, boot CR3
/// restored, and all private user roots are quiescent.
///
/// # Safety
/// Caller ensures no IRQ/CPU can reference high MMIO and frames pinned.
#[cfg(not(test))]
pub unsafe fn unpublish(hhdm:u64,boot_root:u64,frames:[u64;3])
    ->Result<(),Error>{
    let root=unsafe{&mut *((hhdm+boot_root) as *mut [u64;512])};
    if root[ROOT_INDEX] != (frames[0]|P|W|NX){
        return Err(Error::Missing)
    }
    root[ROOT_INDEX]=0;
    x86_64::instructions::tlb::flush(x86_64::VirtAddr::new(VA));
    Ok(())
}
#[cfg(test)]
mod tests{
    use super::*;
    #[test]
    fn high_canonical_exclusive_supervisor_index(){
        assert!(ROOT_INDEX>=256&&ROOT_INDEX<511);
        assert_eq!(VA&4095,0);
        assert_eq!(MMIO_FLAGS&U,0);
        assert_ne!(MMIO_FLAGS&(PCD|PWT),0);
        assert_ne!(MMIO_FLAGS&NX,0);
    }
    #[test]
    fn exclude_boot_alias_bad_physical_and_slot_reuse(){
        let f=[0x1000,0x2000,0x3000];
        assert_eq!(validate(0,0xfee00000,f),Ok(()));
        assert_eq!(validate(1,0xfee00000,f),Err(Error::Busy));
        assert_eq!(validate(0,0xfee00001,f),Err(Error::InvalidMmio));
        assert_eq!(validate(0,0xfee00000,[0x1000,0x1000,0x3000]),Err(Error::InvalidFrame));
        assert_eq!(validate(0,0xfee00000,[0,0x2000,0x3000]),Err(Error::InvalidFrame));
        assert_eq!(validate(0,0xfee00000,[0x1001,0x2000,0x3000]),Err(Error::InvalidFrame));
    }
}
