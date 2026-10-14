//! Pure validation for a SUSPENDED x86-64 ABI stack-switch frame.
//!
//! The real cross-AP context-transfer QEMU smoke reuses one fixed, mapped,
//! kernel-only 16 KiB stack. Ownership MUST be quiescent before the saved
//! RSP crosses processors. The stack is not copied and its mapping/CR3
//! stays identical on all QEMU APs. This is not a userspace/Ring-3 context,
//! an IRQ trap-frame migration, or generic kernel task lifetime management.

pub const STACK_BYTES: usize = 16 * 1024;
pub const GUARD_HEADROOM: usize = 1024;
pub const SWITCH_WORDS: usize = 7; // r15,r14,r13,r12,rbp,rbx,return PC
pub const WORD_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackError {
    BadBounds,
    BadAlignment,
    OutsideStack,
    InsufficientHeadroom,
}

pub fn validate_suspended_rsp(bottom: usize, top: usize, rsp: usize)
    -> Result<(), StackError>
{
    if top.checked_sub(bottom) != Some(STACK_BYTES)
        || bottom & 15 != 0 || top & 15 != 0
    {
        return Err(StackError::BadBounds);
    }
    if rsp & (WORD_BYTES - 1) != 0 { return Err(StackError::BadAlignment); }
    if rsp < bottom || rsp >= top { return Err(StackError::OutsideStack); }
    if rsp < bottom + GUARD_HEADROOM
        || rsp.checked_add(SWITCH_WORDS * WORD_BYTES)
            .is_none_or(|end| end > top)
    {
        return Err(StackError::InsufficientHeadroom);
    }
    Ok(())
}

/// The new ABI context has six nonvolatile GPRs, its entry function's
/// return-PC and a dummy return address, aligned for standard Rust calls.
pub fn initial_rsp(bottom: usize, top: usize) -> Result<usize, StackError> {
    if top.checked_sub(bottom) != Some(STACK_BYTES)
        || bottom & 15 != 0 || top & 15 != 0
    { return Err(StackError::BadBounds); }
    let rsp = top - 8 * WORD_BYTES;
    validate_suspended_rsp(bottom, top, rsp)?;
    Ok(rsp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_context_has_valid_resume_layout() {
        let lo = 0xffff_8000_0010_0000usize;
        let hi = lo + STACK_BYTES;
        let start = initial_rsp(lo, hi).unwrap();
        assert_eq!(start, hi - 64);
        assert_eq!(start & 15, 0);
        assert_eq!(validate_suspended_rsp(lo, hi, start), Ok(()));
        assert_eq!(validate_suspended_rsp(lo, hi, start - 120), Ok(()));
    }

    #[test]
    fn rejects_non_owned_or_corrupt_resume_frames() {
        let lo = 0x1000_0000usize;
        let hi = lo + STACK_BYTES;
        assert_eq!(validate_suspended_rsp(lo, hi, 0), Err(StackError::OutsideStack));
        assert_eq!(validate_suspended_rsp(lo, hi, lo - 8),
                   Err(StackError::OutsideStack));
        assert_eq!(validate_suspended_rsp(lo, hi, hi),
                   Err(StackError::OutsideStack));
        assert_eq!(validate_suspended_rsp(lo, hi, lo + 512),
                   Err(StackError::InsufficientHeadroom));
        assert_eq!(validate_suspended_rsp(lo, hi, hi - 48),
                   Err(StackError::InsufficientHeadroom));
        assert_eq!(validate_suspended_rsp(lo, hi, hi - 66),
                   Err(StackError::BadAlignment));
    }

    #[test]
    fn rejects_bogus_stack_layout_and_integer_wrap() {
        let lo = 0x2000_0000usize;
        assert_eq!(initial_rsp(lo, lo + 4096), Err(StackError::BadBounds));
        assert_eq!(initial_rsp(lo + 1, lo + STACK_BYTES + 1),
                   Err(StackError::BadBounds));
        assert_eq!(validate_suspended_rsp(
            usize::MAX - 7, usize::MAX, usize::MAX - 16
        ), Err(StackError::BadBounds));
    }
}
