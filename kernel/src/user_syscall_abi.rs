//! P2: first bounded x86-64 INT 0x80 syscall ABI and complete GPR trap.
//!
//! ABI (only isolated QEMU flavor): RAX=syscall number, RDI=argument 0,
//! RSI=argument 1, RAX=return value. All OTHER GPRs preserved across IRETQ.
//! SYS_WOLFOS_ID (1) returns a fixed identifier, SYS_U32_ADD (2) accepts
//! only two u32 values whose sum fits u32, SYS_EXIT_ZERO (3) terminates
//! the fixed test process when arg0=arg1=0. All other syscalls return
//! -ENOSYS, bad arguments return -EINVAL, encoded as negative i64 in RAX.
//! No user pointers are EVER dereferenced, no heap or I/O API is exposed.
//!
//! The custom assembly entry saves ALL 15 GPRs before touching SysV Rust,
//! and writes ONLY saved RAX before restoring registers + IRETQ. No actual
//! kernel SYSCALL/SYSRET instruction, syscall MSRs, scheduling or real
//! processes are implemented. This is an intentionally tiny teaching ABI.

use core::mem::{align_of, offset_of, size_of};

pub const SYS_WOLFOS_ID: u64 = 1;
pub const SYS_U32_ADD: u64 = 2;
pub const SYS_EXIT_ZERO: u64 = 3;
pub const WOLFOS_ID: u64 = 0x574f_4c46;
pub const ENOSYS: u64 = (-38i64) as u64;
pub const EINVAL: u64 = (-22i64) as u64;

pub const GPR_BYTES: usize = 15 * 8;
pub const FRAME_BYTES: usize = GPR_BYTES + 5 * 8;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct SavedGprs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct InterruptReturn {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct UserSyscallFrame {
    pub registers: SavedGprs,
    pub hardware: InterruptReturn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Return(u64),
    ExitZero,
}

/// Pure, deterministic, nonallocating and strict. Never follows a user ptr.
pub fn dispatch(number: u64, arg0: u64, arg1: u64) -> Outcome {
    match number {
        SYS_WOLFOS_ID => {
            if arg0 == 0 && arg1 == 0 {
                Outcome::Return(WOLFOS_ID)
            } else {
                Outcome::Return(EINVAL)
            }
        },
        SYS_U32_ADD => {
            if let (Ok(left), Ok(right)) = (u32::try_from(arg0), u32::try_from(arg1)) {
                match left.checked_add(right) {
                    Some(result) => Outcome::Return(u64::from(result)),
                    None => Outcome::Return(EINVAL),
                }
            } else {
                Outcome::Return(EINVAL)
            }
        },
        SYS_EXIT_ZERO => {
            if arg0 == 0 && arg1 == 0 {
                Outcome::ExitZero
            } else {
                Outcome::Return(EINVAL)
            }
        },
        _ => Outcome::Return(ENOSYS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembler_push_sequence_matches_all_offsets() {
        assert_eq!(size_of::<SavedGprs>(), GPR_BYTES);
        assert_eq!(align_of::<UserSyscallFrame>(), 8);
        assert_eq!(size_of::<InterruptReturn>(), 40);
        assert_eq!(size_of::<UserSyscallFrame>(), FRAME_BYTES);
        assert_eq!(offset_of!(SavedGprs, r15), 0);
        assert_eq!(offset_of!(SavedGprs, r14), 8);
        assert_eq!(offset_of!(SavedGprs, r13), 16);
        assert_eq!(offset_of!(SavedGprs, r12), 24);
        assert_eq!(offset_of!(SavedGprs, r11), 32);
        assert_eq!(offset_of!(SavedGprs, r10), 40);
        assert_eq!(offset_of!(SavedGprs, r9), 48);
        assert_eq!(offset_of!(SavedGprs, r8), 56);
        assert_eq!(offset_of!(SavedGprs, rbp), 64);
        assert_eq!(offset_of!(SavedGprs, rdi), 72);
        assert_eq!(offset_of!(SavedGprs, rsi), 80);
        assert_eq!(offset_of!(SavedGprs, rdx), 88);
        assert_eq!(offset_of!(SavedGprs, rcx), 96);
        assert_eq!(offset_of!(SavedGprs, rbx), 104);
        assert_eq!(offset_of!(SavedGprs, rax), 112);
        assert_eq!(offset_of!(UserSyscallFrame, hardware), 120);
        assert_eq!(offset_of!(InterruptReturn, rip), 0);
        assert_eq!(offset_of!(InterruptReturn, cs), 8);
        assert_eq!(offset_of!(InterruptReturn, rflags), 16);
        assert_eq!(offset_of!(InterruptReturn, rsp), 24);
        assert_eq!(offset_of!(InterruptReturn, ss), 32);
    }

    #[test]
    fn kernel_id_only_accepts_zeroed_arguments() {
        assert_eq!(dispatch(1, 0, 0), Outcome::Return(WOLFOS_ID));
        assert_eq!(dispatch(1, 1, 0), Outcome::Return(EINVAL));
        assert_eq!(dispatch(1, 0, 1), Outcome::Return(EINVAL));
    }

    #[test]
    fn u32_sum_is_exact_and_overflow_fails_closed() {
        assert_eq!(dispatch(2, 7, 35), Outcome::Return(42));
        assert_eq!(dispatch(2, u32::MAX as u64, 0), Outcome::Return(u32::MAX as u64));
        assert_eq!(dispatch(2, u32::MAX as u64, 1), Outcome::Return(EINVAL));
        assert_eq!(dispatch(2, u64::MAX, 1), Outcome::Return(EINVAL));
        assert_eq!(dispatch(2, 1, u64::MAX), Outcome::Return(EINVAL));
    }

    #[test]
    fn exit_requires_valid_zero_status_and_no_unused_args() {
        assert_eq!(dispatch(3, 0, 0), Outcome::ExitZero);
        assert_eq!(dispatch(3, 1, 0), Outcome::Return(EINVAL));
        assert_eq!(dispatch(3, 0, 1), Outcome::Return(EINVAL));
    }

    #[test]
    fn unknown_numbers_are_deterministic_errors() {
        for number in [0, 4, 255, 0x7fff, u64::MAX] {
            assert_eq!(dispatch(number, u64::MAX, u64::MAX), Outcome::Return(ENOSYS));
        }
        assert_eq!(ENOSYS as i64, -38);
        assert_eq!(EINVAL as i64, -22);
    }
}
