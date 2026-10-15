//! P2 interruptible-Ring3 acceptance checks for a future timer scheduler.
//!
//! Pure, no_std, no MMIO and no user dereference. This is an *evidence
//! checker*, not a claim that a local APIC timer IRQ was delivered. It must
//! be used after CPU privileged-state / private page walk validation.
//! The existing IF=0 INT80 ABI remains unchanged for every earlier flavor.
pub const USER_LOW:u64=0x1_0000;
pub const USER_HIGH:u64=0x0000_8000_0000_0000;
pub const KERNEL_LOW:u64=0xffff_8000_0000_0000;
pub const FRAME_BYTES:u64=160;
pub const LEGACY_ALLOWED:u64=0x2|(1<<0)|(1<<2)|(1<<4)|(1<<6)|(1<<7)|(1<<11);
pub const IF:u64=1<<9;
const PAGE:u64=4096;
const PHYS_END:u64=1<<52;

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Reject {
    InvalidPid, StalePid, WrongCr3, InvalidOwnerRoot,
    WrongTssStack, InvalidGuardStack, WrongTrapFrame,
    PrivilegedSelector, BadUserAddress, UnsafeUserFlags,
    CpuInterruptsMasked, WrongCpuFpuOwner,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Evidence {
    pub pid:u64,
    pub expected_pid:u64,
    pub actual_cr3:u64,
    pub owned_cr3:u64,
    pub actual_rsp0:u64,
    pub owned_stack_bottom:u64,
    pub owned_stack_top:u64,
    pub actual_frame_address:u64,
    pub user_rip:u64,
    pub user_rsp:u64,
    pub user_cs:u64,
    pub user_ss:u64,
    pub user_rflags:u64,
    pub fpu_owner_pid:u64,
}

pub fn safe_irq_user_flags(flags:u64)->bool{
    flags & (IF|2) == IF|2
        && flags & !(LEGACY_ALLOWED|IF)==0
}
pub fn validate(e:Evidence)->Result<(),Reject>{
    if e.pid==0 || e.expected_pid==0{return Err(Reject::InvalidPid)}
    if e.pid!=e.expected_pid{return Err(Reject::StalePid)}
    if e.owned_cr3==0||e.owned_cr3>=PHYS_END||
       e.owned_cr3&(PAGE-1)!=0{return Err(Reject::InvalidOwnerRoot)}
    if e.actual_cr3!=e.owned_cr3{return Err(Reject::WrongCr3)}
    if e.owned_stack_bottom<KERNEL_LOW||
        e.owned_stack_bottom&(PAGE-1)!=0||
        e.owned_stack_bottom.checked_add(4*PAGE)!=Some(e.owned_stack_top)||
        e.owned_stack_top&15!=0{
        return Err(Reject::InvalidGuardStack)
    }
    if e.actual_rsp0!=e.owned_stack_top{
        return Err(Reject::WrongTssStack)
    }
    if e.actual_frame_address!=
        e.owned_stack_top.checked_sub(FRAME_BYTES).ok_or(Reject::WrongTrapFrame)?{
        return Err(Reject::WrongTrapFrame)
    }
    if e.user_cs>u16::MAX as u64||e.user_ss>u16::MAX as u64||
        e.user_cs&7!=3||e.user_ss&7!=3||
        e.user_cs>>3==e.user_ss>>3||
        e.user_cs&4!=0||e.user_ss&4!=0||
        e.user_cs>>3==0||e.user_ss>>3==0{
        return Err(Reject::PrivilegedSelector)
    }
    if !(USER_LOW..USER_HIGH).contains(&e.user_rip)||
       !(USER_LOW..USER_HIGH).contains(&e.user_rsp){
        return Err(Reject::BadUserAddress)
    }
    if e.user_rflags&IF==0{return Err(Reject::CpuInterruptsMasked)}
    if !safe_irq_user_flags(e.user_rflags){
        return Err(Reject::UnsafeUserFlags)
    }
    if e.fpu_owner_pid!=e.pid{return Err(Reject::WrongCpuFpuOwner)}
    Ok(())
}

#[cfg(test)]
mod tests{
    use super::*;
    fn sample()->Evidence{
        Evidence{
            pid:1,expected_pid:1,
            actual_cr3:0x1000,owned_cr3:0x1000,
            actual_rsp0:0xffff_d000_0000_5000,
            owned_stack_bottom:0xffff_d000_0000_1000,
            owned_stack_top:0xffff_d000_0000_5000,
            actual_frame_address:0xffff_d000_0000_4f60,
            user_rip:0x401088,user_rsp:0x405000,
            user_cs:0x2b,user_ss:0x23,
            user_rflags:0x202,
            fpu_owner_pid:1,
        }
    }
    #[test]
    fn only_cpl3_if_enabled_unprivileged_resume_is_accepted(){
        assert_eq!(validate(sample()),Ok(()));
        assert!(safe_irq_user_flags(0x202));
        assert!(safe_irq_user_flags(0x8d7|0x200));
    }
    #[test]
    fn reject_wrong_pid_and_wrong_root(){
        let mut e=sample();e.pid=2;
        assert_eq!(validate(e),Err(Reject::StalePid));
        e=sample();e.actual_cr3=0x2000;
        assert_eq!(validate(e),Err(Reject::WrongCr3));
        e=sample();e.owned_cr3=0x1001;e.actual_cr3=0x1001;
        assert_eq!(validate(e),Err(Reject::InvalidOwnerRoot));
    }
    #[test]
    fn deny_unguarded_or_wrong_tss_or_forged_frame(){
        let mut e=sample();e.owned_stack_bottom+=PAGE;
        assert_eq!(validate(e),Err(Reject::InvalidGuardStack));
        e=sample();e.actual_rsp0-=PAGE;
        assert_eq!(validate(e),Err(Reject::WrongTssStack));
        e=sample();e.actual_frame_address-=8;
        assert_eq!(validate(e),Err(Reject::WrongTrapFrame));
    }
    #[test]
    fn refuse_kernel_privilege_bad_selectors_and_noncanonical_addresses(){
        let mut e=sample();e.user_cs=8;
        assert_eq!(validate(e),Err(Reject::PrivilegedSelector));
        e=sample();e.user_ss=0x2b;
        assert_eq!(validate(e),Err(Reject::PrivilegedSelector));
        e=sample();e.user_rip=KERNEL_LOW;
        assert_eq!(validate(e),Err(Reject::BadUserAddress));
        e=sample();e.user_rsp=USER_HIGH;
        assert_eq!(validate(e),Err(Reject::BadUserAddress));
    }
    #[test]
    fn fail_closed_for_masked_timer_and_unsafe_user_flags(){
        let mut e=sample();e.user_rflags=2;
        assert_eq!(validate(e),Err(Reject::CpuInterruptsMasked));
        for bad in [0,0x200,0x302,0x602,0x1202,0x2202,
                    0x4202,0x10202,0x20202,u64::MAX]{
            e=sample();e.user_rflags=bad;
            assert!(validate(e).is_err(),"bad flags {bad:#x}");
        }
        e=sample();e.fpu_owner_pid=2;
        assert_eq!(validate(e),Err(Reject::WrongCpuFpuOwner));
    }
}
