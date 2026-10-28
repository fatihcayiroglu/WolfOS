//! BSP x86-64 kernel IRQ stack-frame model for the QEMU-only APIC timer
//! assembly entry. The frame is read by the handler and restored in place;
//! **no switching to another saved frame or preemptive task exists**.
//!
//! The intended push order is rax, rbx, rcx, rdx, rsi, rdi, rbp,
//! r8, r9, r10, r11, r12, r13, r14, r15. Hardware provides the
//! architectural return frame below these saves.
//!
//! IMPORTANT: the active assembly path must pass actual 1/4-vCPU QEMU
//! interrupt+IRETQ tests. The stack layout is not enough to support task
//! switches: FPU/SIMD, FS/GS, CR3, debug state, per-task stacks and robust
//! IRQ-safe scheduler locking need separate design and validation.

use core::mem::{align_of, offset_of, size_of};

pub const GPR_COUNT: usize = 15;
pub const SAVED_GPR_BYTES: usize = GPR_COUNT * 8;
pub const HARDWARE_FRAME_BYTES: usize = 5 * 8;
pub const TOTAL_FRAME_BYTES: usize = SAVED_GPR_BYTES + HARDWARE_FRAME_BYTES;
pub const STACK_CANARY_HEADROOM: u64 = 512;
const RFLAGS_MUST_BE_ONE: u64 = 1 << 1;
const RFLAGS_IF: u64 = 1 << 9;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

/// Architectural 64-bit interrupt return fields for this kernel-only
/// contract. A future assembly entry MUST prove actual platform ordering
/// and address alignment in a separate QEMU acceptance test.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HardwareReturnFrame {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KernelTrapFrame {
    pub registers: SavedGprs,
    pub hardware: HardwareReturnFrame,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeError {
    InvalidStackRange,
    StackOverflowOrCorruption,
    FrameMisaligned,
    InvalidKernelSelector,
    InvalidInstructionPointer,
    InvalidSavedStackPointer,
    InterruptsNotEnabled,
    InvalidRflags,
}

/// Pure sanity checks for a proposed saved CPL0, same-address-space frame.
///
/// Caller MUST separately prove that the stack range is kernel-owned, the
/// registers actually came from an IRQ assembly entry, and any extended
/// processor state needed by the interrupted code is preserved. No pointers
/// are dereferenced or CPU state modified by this function.
pub fn validate_kernel_resume(
    frame_address: u64,
    stack_bottom: u64,
    stack_end: u64,
    expected_kernel_cs: u16,
    frame: &KernelTrapFrame,
) -> Result<(), ResumeError> {
    if stack_bottom >= stack_end
        || stack_bottom.checked_add(STACK_CANARY_HEADROOM)
            .is_none_or(|guard| guard >= stack_end)
    {
        return Err(ResumeError::InvalidStackRange);
    }
    if frame_address & 7 != 0 {
        return Err(ResumeError::FrameMisaligned);
    }
    let frame_end = frame_address.checked_add(TOTAL_FRAME_BYTES as u64)
        .ok_or(ResumeError::StackOverflowOrCorruption)?;
    if frame_address < stack_bottom + STACK_CANARY_HEADROOM
        || frame_end > stack_end
    {
        return Err(ResumeError::StackOverflowOrCorruption);
    }

    let cs = frame.hardware.cs;
    if expected_kernel_cs == 0
        || expected_kernel_cs & 3 != 0
        || cs != u64::from(expected_kernel_cs)
    {
        return Err(ResumeError::InvalidKernelSelector);
    }
    if frame.hardware.rip == 0 {
        return Err(ResumeError::InvalidInstructionPointer);
    }
    if frame.hardware.rsp & 7 != 0
        || frame.hardware.rsp < frame_end
        || frame.hardware.rsp > stack_end
    {
        return Err(ResumeError::InvalidSavedStackPointer);
    }
    if frame.hardware.rflags & RFLAGS_MUST_BE_ONE == 0 {
        return Err(ResumeError::InvalidRflags);
    }
    if frame.hardware.rflags & RFLAGS_IF == 0 {
        return Err(ResumeError::InterruptsNotEnabled);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const STACK_BOTTOM: u64 = 0x4_0000;
    const STACK_END: u64 = 0x4_4000;
    const SAVED_AT: u64 = STACK_END - 0x200;

    fn valid_frame() -> KernelTrapFrame {
        KernelTrapFrame {
            registers: SavedGprs::default(),
            hardware: HardwareReturnFrame {
                rip: 0xffff_ffff_8000_1000,
                cs: 0x8,
                rflags: 0x202,
                rsp: STACK_END - 0x100,
                ss: 0x10,
            },
        }
    }

    #[test]
    fn all_15_saved_gprs_have_exact_reverse_push_offsets() {
        assert_eq!(size_of::<SavedGprs>(), SAVED_GPR_BYTES);
        assert_eq!(align_of::<SavedGprs>(), 8);
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
    }

    #[test]
    fn architectural_return_frame_has_no_padding() {
        assert_eq!(size_of::<HardwareReturnFrame>(), HARDWARE_FRAME_BYTES);
        assert_eq!(offset_of!(KernelTrapFrame, hardware), SAVED_GPR_BYTES);
        assert_eq!(offset_of!(HardwareReturnFrame, rip), 0);
        assert_eq!(offset_of!(HardwareReturnFrame, cs), 8);
        assert_eq!(offset_of!(HardwareReturnFrame, rflags), 16);
        assert_eq!(offset_of!(HardwareReturnFrame, rsp), 24);
        assert_eq!(offset_of!(HardwareReturnFrame, ss), 32);
        assert_eq!(size_of::<KernelTrapFrame>(), TOTAL_FRAME_BYTES);
        assert_eq!(align_of::<KernelTrapFrame>(), 8);
    }

    #[test]
    fn valid_same_cpu_kernel_frame_is_accepted() {
        assert_eq!(validate_kernel_resume(
            SAVED_AT, STACK_BOTTOM, STACK_END, 0x8, &valid_frame()
        ), Ok(()));
    }

    #[test]
    fn frame_bounds_and_alignment_fail_closed() {
        let frame = valid_frame();
        assert_eq!(validate_kernel_resume(
            SAVED_AT, STACK_END, STACK_END, 0x8, &frame
        ), Err(ResumeError::InvalidStackRange));
        assert_eq!(validate_kernel_resume(
            SAVED_AT + 1, STACK_BOTTOM, STACK_END, 0x8, &frame
        ), Err(ResumeError::FrameMisaligned));
        assert_eq!(validate_kernel_resume(
            STACK_BOTTOM + 8, STACK_BOTTOM, STACK_END, 0x8, &frame
        ), Err(ResumeError::StackOverflowOrCorruption));
        assert_eq!(validate_kernel_resume(
            u64::MAX - 7, STACK_BOTTOM, STACK_END, 0x8, &frame
        ), Err(ResumeError::StackOverflowOrCorruption));
        assert_eq!(validate_kernel_resume(
            SAVED_AT, STACK_BOTTOM, STACK_BOTTOM + 500, 0x8, &frame
        ), Err(ResumeError::InvalidStackRange));
    }

    #[test]
    fn return_privilege_and_interrupt_state_fail_closed() {
        let mut frame = valid_frame();
        frame.hardware.cs = 0x1b;
        assert_eq!(validate_kernel_resume(
            SAVED_AT, STACK_BOTTOM, STACK_END, 0x8, &frame
        ), Err(ResumeError::InvalidKernelSelector));
        frame = valid_frame();
        frame.hardware.rip = 0;
        assert_eq!(validate_kernel_resume(
            SAVED_AT, STACK_BOTTOM, STACK_END, 0x8, &frame
        ), Err(ResumeError::InvalidInstructionPointer));
        frame = valid_frame();
        frame.hardware.rsp = SAVED_AT;
        assert_eq!(validate_kernel_resume(
            SAVED_AT, STACK_BOTTOM, STACK_END, 0x8, &frame
        ), Err(ResumeError::InvalidSavedStackPointer));
        frame = valid_frame();
        frame.hardware.rflags = 0x200;
        assert_eq!(validate_kernel_resume(
            SAVED_AT, STACK_BOTTOM, STACK_END, 0x8, &frame
        ), Err(ResumeError::InvalidRflags));
        frame.hardware.rflags = 0x2;
        assert_eq!(validate_kernel_resume(
            SAVED_AT, STACK_BOTTOM, STACK_END, 0x8, &frame
        ), Err(ResumeError::InterruptsNotEnabled));
    }
}
