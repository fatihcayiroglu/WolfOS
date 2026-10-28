//! Independent, PID-owned legacy x87/SSE FXSAVE64 images for a bounded set
//! of users. Production two-slot semantics remain backward compatible.
//!
//! This is a BSP-only *preflight*, NOT a Ring3 context scheduler. Hardware
//! save/restore is only allowed after CPUID FXSR/SSE2 verification, while
//! IF=0 and CR0/CR4 already configured by the caller. A 512-byte FXSAVE64
//! image excludes AVX upper YMM, AVX-512 and other XSAVE components.
//! Never use this bank on CPUs with a different xstate/XCR0 contract.
use core::arch::asm;
use core::mem::{align_of, size_of};

pub const IMAGE_BYTES:usize=512;
pub const XMM0_OFFSET:usize=160;
pub const BANK_CAPACITY:usize=2;
pub const FOUR_PID_BANK_CAPACITY:usize=4;

#[repr(C,align(16))]
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct FxImage{bytes:[u8;IMAGE_BYTES]}
impl FxImage{
    pub const fn empty()->Self{Self{bytes:[0;IMAGE_BYTES]}}
    /// Capture the currently valid legacy x87/SSE baseline before any
    /// per-PID image is seeded. CR0/CR4, FXSR and exclusive BSP CPU state
    /// must already have been validated by the caller.
    ///
    /// # Safety
    /// IF=0, BSP exclusive, CPUID FXSR/SSE2, CR0.EM=TS=0, CR4.OSFXSR=1.
    pub unsafe fn capture_baseline()->Self{
        let mut result=Self::empty();
        unsafe{
            asm!("fxsave64 [{}]",in(reg)&mut result,options(nostack));
        }
        result
    }
    pub fn xmm0(&self)->u64{
        let mut data=[0u8;8];
        data.copy_from_slice(&self.bytes[XMM0_OFFSET..XMM0_OFFSET+8]);
        u64::from_le_bytes(data)
    }
    pub fn set_xmm0(&mut self,v:u64){
        self.bytes[XMM0_OFFSET..XMM0_OFFSET+8].copy_from_slice(&v.to_le_bytes())
    }
    pub fn aligned(&self)->bool{(self as *const Self as usize)&15==0}
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum FxError{
    BadPid, DuplicatePid, Capacity, BadBaseline, StaleHandle,
    ActiveSlot, NotActive, AlreadyActive, RetirementWhileActive,
    GenerationOverflow,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct FxHandle{pub slot:usize,pub generation:u64,pub pid:u64}

#[derive(Clone,Copy)]
struct Slot{
    pid:u64,
    generation:u64,
    live:bool,
    image:FxImage,
}
impl Slot{const fn new()->Self{
    Self{pid:0,generation:0,live:false,image:FxImage::empty()}
}}
pub struct FxBank<const CAPACITY:usize>{
    slots:[Slot;CAPACITY],
    active:Option<usize>,
}
/// Retain the existing, QEMU-verified two-PID hardware path without a change.
pub type UserFxBank=FxBank<BANK_CAPACITY>;
/// Four-PID candidate bank for the next isolated Ring3 hardware milestone.
pub type FourPidFxBank=FxBank<FOUR_PID_BANK_CAPACITY>;
impl<const CAPACITY:usize> FxBank<CAPACITY>{
    pub const fn new()->Self{
        Self{slots:[const{Slot::new()};CAPACITY],active:None}
    }
    pub fn occupied(&self)->usize{self.slots.iter().filter(|s|s.live).count()}
    pub fn active_pid(&self)->Option<u64>{
        self.active.map(|idx|self.slots[idx].pid)
    }
    pub fn prepare(&mut self,pid:u64,baseline:&FxImage)->Result<FxHandle,FxError>{
        if pid==0{return Err(FxError::BadPid)}
        if !baseline.aligned(){return Err(FxError::BadBaseline)}
        if self.slots.iter().any(|s|s.live&&s.pid==pid){
            return Err(FxError::DuplicatePid)
        }
        let (idx,slot)=self.slots.iter_mut().enumerate()
            .find(|(_,s)|!s.live).ok_or(FxError::Capacity)?;
        let generation=slot.generation.checked_add(1)
            .ok_or(FxError::GenerationOverflow)?;
        slot.pid=pid;
        slot.generation=generation;
        slot.live=true;
        slot.image=*baseline;
        Ok(FxHandle{slot:idx,generation,pid})
    }
    fn checked(&self,h:FxHandle)->Result<usize,FxError>{
        let s=self.slots.get(h.slot).ok_or(FxError::StaleHandle)?;
        if !s.live||s.pid!=h.pid||h.pid==0||
            s.generation!=h.generation||h.generation==0{
            return Err(FxError::StaleHandle)
        }
        Ok(h.slot)
    }
    pub fn image_xmm0(&self,h:FxHandle)->Result<u64,FxError>{
        Ok(self.slots[self.checked(h)?].image.xmm0())
    }
    pub fn seed_xmm0(&mut self,h:FxHandle,value:u64)->Result<(),FxError>{
        let idx=self.checked(h)?;
        if self.active==Some(idx){return Err(FxError::ActiveSlot)}
        self.slots[idx].image.set_xmm0(value);
        Ok(())
    }
    /// Save current BSP FX state into its PID image, then restore the next
    /// PID's image. Never called in an IRQ handler or after user context
    /// ownership migrates to an AP. Caller MUST enforce IF=0 and OSFXSR.
    ///
    /// # Safety
    /// Exclusively BSP, no concurrent task, no Rust SIMD assumptions,
    /// FXSR/SSE supported and enabled, all images seeded from real FXSAVE64.
    pub unsafe fn switch_to(&mut self,h:FxHandle)->Result<u64,FxError>{
        let next=self.checked(h)?;
        if self.active==Some(next){return Err(FxError::AlreadyActive)}
        if let Some(old)=self.active{
            // SAFETY: aligned owned destination for exactly 512 writable bytes.
            unsafe{
                asm!("fxsave64 [{}]",
                    in(reg) &mut self.slots[old].image,
                    options(nostack));
            }
        }
        // SAFETY: the image originates from a hardware-valid baseline with
        // only the low XMM0 lane changed, preserving MXCSR masks.
        unsafe{
            asm!("fxrstor64 [{}]",
                in(reg) &self.slots[next].image,
                options(nostack));
        }
        self.active=Some(next);
        Ok(self.slots[next].image.xmm0())
    }
    /// Capture the final active PID before restoring original BSP FX state.
    /// The caller must restore its original FX state separately.
    ///
    /// # Safety
    /// Same BSP-only, IF=0, enabled FXSR and exclusive image contract.
    pub unsafe fn suspend(&mut self,h:FxHandle)->Result<u64,FxError>{
        let idx=self.checked(h)?;
        if self.active!=Some(idx){return Err(FxError::NotActive)}
        unsafe{
            asm!("fxsave64 [{}]",
                in(reg) &mut self.slots[idx].image,
                options(nostack));
        }
        self.active=None;
        Ok(self.slots[idx].image.xmm0())
    }
    /// Retire ONLY after the owning process is no longer live and hardware
    /// no longer uses the saved image. All 512 bytes are overwritten before
    /// this slot may be minted for another PID. This method does not itself
    /// prove the caller's external ProcessTable lifecycle state.
    pub fn retire_quiescent(&mut self,h:FxHandle)->Result<bool,FxError>{
        let idx=self.checked(h)?;
        if self.active==Some(idx){return Err(FxError::RetirementWhileActive)}
        let slot=&mut self.slots[idx];
        for word in 0..IMAGE_BYTES/8 {
            // SAFETY: 16-byte aligned image contains 64 u64 words; exclusively
            // owned by this inactive slot. Volatile wipe cannot be removed.
            unsafe{
                core::ptr::write_volatile(
                    slot.image.bytes.as_mut_ptr().cast::<u64>().add(word),0
                );
            }
        }
        let clean=slot.image.bytes.iter().all(|b|*b==0);
        slot.live=false;
        slot.pid=0;
        Ok(clean)
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    fn baseline()->FxImage {
        let mut b=FxImage::empty();
        b.bytes[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        b
    }
    #[test]
    fn alignment_and_hardware_legacy_offsets(){
        assert_eq!(size_of::<FxImage>(),512);
        assert_eq!(align_of::<FxImage>(),16);
        let b=baseline();assert!(b.aligned());
        assert_eq!(b.xmm0(),0);
    }
    #[test]
    fn unique_pids_capacity_and_inactive_seeding(){
        let mut b=UserFxBank::new();let f=baseline();
        assert_eq!(b.prepare(0,&f),Err(FxError::BadPid));
        let a=b.prepare(1,&f).unwrap();
        assert_eq!(b.prepare(1,&f),Err(FxError::DuplicatePid));
        let c=b.prepare(2,&f).unwrap();
        assert_eq!(b.prepare(3,&f),Err(FxError::Capacity));
        b.seed_xmm0(a,0x1111).unwrap();
        b.seed_xmm0(c,0x2222).unwrap();
        assert_eq!(b.image_xmm0(a),Ok(0x1111));
        assert_eq!(b.image_xmm0(c),Ok(0x2222));
        assert_eq!(b.occupied(),2);
    }
    #[test]
    fn retirement_wipes_and_stale_tokens_never_retarget(){
        let mut b=UserFxBank::new();let f=baseline();
        let a=b.prepare(1,&f).unwrap();
        b.seed_xmm0(a,0xdead_beef).unwrap();
        assert_eq!(b.retire_quiescent(a),Ok(true));
        assert_eq!(b.image_xmm0(a),Err(FxError::StaleHandle));
        let newer=b.prepare(4,&f).unwrap();
        assert_eq!(newer.slot,a.slot);
        assert_eq!(newer.generation,a.generation+1);
        assert_eq!(b.seed_xmm0(a,7),Err(FxError::StaleHandle));
        assert_eq!(b.retire_quiescent(a),Err(FxError::StaleHandle));
        assert_eq!(b.image_xmm0(newer),Ok(0));
    }
    #[test]
    fn four_pids_have_independent_legacy_xmm0_images_and_exact_capacity() {
        let mut bank=FourPidFxBank::new();
        let image=baseline();
        let ids=[1u64,2,3,4];
        let handles=ids.map(|pid|bank.prepare(pid,&image).unwrap());
        assert_eq!(bank.occupied(),4);
        assert_eq!(bank.prepare(5,&image),Err(FxError::Capacity));
        for (i,h) in handles.iter().enumerate() {
            bank.seed_xmm0(*h,0xfeed_0000+i as u64).unwrap();
        }
        for (i,h) in handles.iter().enumerate() {
            assert_eq!(bank.image_xmm0(*h),Ok(0xfeed_0000+i as u64));
        }
        assert_eq!(bank.image_xmm0(FxHandle{pid:4,..handles[0]}),
                   Err(FxError::StaleHandle));
        for h in handles {
            assert_eq!(bank.retire_quiescent(h),Ok(true));
        }
        assert_eq!(bank.occupied(),0);
    }
    #[test]
    fn four_pid_reuse_requires_fresh_generation_and_zeroed_fx_image() {
        let mut bank=FourPidFxBank::new();
        let image=baseline();
        let handles=[1u64,2,3,4].map(|pid|bank.prepare(pid,&image).unwrap());
        bank.seed_xmm0(handles[2],0xbeef_cafe).unwrap();
        assert_eq!(bank.retire_quiescent(handles[2]),Ok(true));
        let newer=bank.prepare(9,&image).unwrap();
        assert_eq!(newer.slot,handles[2].slot);
        assert_eq!(newer.generation,handles[2].generation+1);
        assert_eq!(bank.image_xmm0(newer),Ok(0),
                   "retired PID's private SSE state must never leak into replacement");
        assert_eq!(bank.seed_xmm0(handles[2],5),Err(FxError::StaleHandle));
        assert_eq!(bank.retire_quiescent(handles[2]),Err(FxError::StaleHandle));
        for h in [handles[0],handles[1],handles[3],newer] {
            assert_eq!(bank.retire_quiescent(h),Ok(true));
        }
        assert_eq!(bank.occupied(),0);
    }
    #[test]
    fn zero_capacity_four_bank_api_cannot_admit() {
        let mut bank=FxBank::<0>::new();
        assert_eq!(bank.prepare(1,&baseline()),Err(FxError::Capacity));
        assert_eq!(bank.occupied(),0);
        assert_eq!(bank.active_pid(),None);
    }
    #[test]
    fn invalid_tokens_never_mutate_another_pids_image(){
        let mut b=UserFxBank::new();let f=baseline();
        let a=b.prepare(11,&f).unwrap();let c=b.prepare(22,&f).unwrap();
        b.seed_xmm0(c,0x55).unwrap();
        assert_eq!(b.seed_xmm0(FxHandle{pid:22,..a},7),Err(FxError::StaleHandle));
        assert_eq!(b.image_xmm0(c),Ok(0x55));
        assert_eq!(b.retire_quiescent(a),Ok(true));
        assert_eq!(b.retire_quiescent(c),Ok(true));
        assert_eq!(b.occupied(),0);
    }
}
