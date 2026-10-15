//! P2: fail-closed x86-64 CPL3 entry-frame contract.
//!
//! This module does NOT execute IRETQ or change privilege levels.
//! It checks the metadata that a future safe transition mechanism must
//! produce: distinct CPL3 code/data selectors, mapped lower-half RIP/RSP,
//! canonical 16-byte-aligned supervisor RSP0, and restricted RFLAGS.
//!
//! A future implementation MUST additionally prove the target user pages
//! are mapped and supervisor code is mapped under the target CR3, confirm
//! TR/actual TSS.RSP0, install safe fault/return paths and execute CPL3
//! tests in QEMU. A validated frame alone is NOT an isolation proof.

pub const USER_MIN: u64 = 0x1_0000;
pub const USER_END: u64 = 0x0000_8000_0000_0000;
const KERNEL_HALF_START: u64 = 0xffff_8000_0000_0000;
const RFLAGS_FIXED: u64 = 1 << 1;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ring3Entry {
    pub rip: u64,
    pub user_rsp: u64,
    pub kernel_rsp0: u64,
    pub user_cs: u16,
    pub user_ss: u16,
    pub rflags: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryError {
    InvalidInstructionPointer,
    InvalidUserStack,
    InvalidKernelStack,
    InvalidUserSelectors,
    InvalidFlags,
}

pub fn validate(frame: Ring3Entry) -> Result<(), EntryError> {
    if !(USER_MIN..USER_END).contains(&frame.rip) {
        return Err(EntryError::InvalidInstructionPointer);
    }
    // The initial stack top may be immediately ABOVE the last mapped page.
    // The stack itself must not be empty, kernel-owned or unaligned.
    if frame.user_rsp <= USER_MIN
        || frame.user_rsp >= USER_END
        || frame.user_rsp % 16 != 0
    {
        return Err(EntryError::InvalidUserStack);
    }
    if frame.kernel_rsp0 < KERNEL_HALF_START || frame.kernel_rsp0 % 16 != 0 {
        return Err(EntryError::InvalidKernelStack);
    }
    // No LDT selector (TI=1), never GDT NULL; selectors must be distinct
    // RPL3 selectors. The actual GDT descriptors must be checked separately.
    let cs_index = frame.user_cs >> 3;
    let ss_index = frame.user_ss >> 3;
    if cs_index == 0 || ss_index == 0 || cs_index == ss_index
        || frame.user_cs & 7 != 3 || frame.user_ss & 7 != 3
    {
        return Err(EntryError::InvalidUserSelectors);
    }
    // First bootstrap entry must start with exactly reserved bit 1 set:
    // IF=0, IOPL=0, DF=0, TF=0, NT=0, RF=0, VM=0 and no unknown bits.
    if frame.rflags != RFLAGS_FIXED {
        return Err(EntryError::InvalidFlags);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Ring3Entry {
        Ring3Entry {
            rip: 0x401100,
            user_rsp: 0x405000,
            kernel_rsp0: 0xffff_8000_0001_8000,
            user_cs: 0x2b,
            user_ss: 0x23,
            rflags: 0x2,
        }
    }

    #[test]
    fn checks_strict_known_good_trampoline_metadata() {
        assert_eq!(validate(fixture()), Ok(()));
    }

    #[test]
    fn prohibits_kernel_rip_and_noncanonical_and_low_addresses() {
        for rip in [0, 0xffff, USER_END, u64::MAX, 0xffff_ffff_8000_0000] {
            let mut entry = fixture();
            entry.rip = rip;
            assert_eq!(validate(entry), Err(EntryError::InvalidInstructionPointer));
        }
    }

    #[test]
    fn prohibits_unaligned_or_supervisor_or_empty_user_stacks() {
        for rsp in [0, USER_MIN, 0x404001, USER_END, USER_END + 16, u64::MAX] {
            let mut entry = fixture();
            entry.user_rsp = rsp;
            assert_eq!(validate(entry), Err(EntryError::InvalidUserStack));
        }
    }

    #[test]
    fn prohibits_bad_rsp0() {
        for rsp0 in [0, USER_END - 16, 0xffff_7000_0000_0000,
            0xffff_8000_0001_8001] {
            let mut entry = fixture();
            entry.kernel_rsp0 = rsp0;
            assert_eq!(validate(entry), Err(EntryError::InvalidKernelStack));
        }
    }

    #[test]
    fn prohibits_cpl0_cpl1_ldt_null_and_alias_user_selectors() {
        for (cs, ss) in [(0x28, 0x23), (0x2b, 0x20), (0, 0x23),
            (0x2b, 0x2b), (0x2f, 0x23), (0x2b, 0x27)] {
            let mut entry = fixture();
            entry.user_cs = cs;
            entry.user_ss = ss;
            assert_eq!(validate(entry), Err(EntryError::InvalidUserSelectors));
        }
    }

    #[test]
    fn rejects_unsafe_iret_flags() {
        for flags in [0, 0x202, 0x402, 0x1002, 0x2002, 0x4002, 0x10002, 0x20002, 0x40002, 0x40000_0002] {
            let mut entry = fixture();
            entry.rflags = flags;
            assert_eq!(validate(entry), Err(EntryError::InvalidFlags));
        }
    }
}
