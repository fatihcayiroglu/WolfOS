//! Pure validation of an x86-64 kernel interrupt's architectural frame.
//!
//! This validates observations only. It does NOT save general-purpose registers,
//! SIMD/FPU, FS/GS, CR3 or the entire task context, and cannot resume/switch
//! interrupted tasks. Hardware-frame capture is read-only in this milestone.

pub const RFLAGS_RESERVED_ONE: u64 = 1 << 1;
pub const RFLAGS_INTERRUPT_ENABLE: u64 = 1 << 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    NullInstructionPointer,
    NullStackPointer,
    UnalignedStackPointer,
    NotKernelCode,
    InvalidFlags,
    InterruptsWereDisabled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelIrqFrame {
    pub rip: u64,
    pub rsp: u64,
    pub cs: u64,
    pub rflags: u64,
}

/// Accept only a CPL0 frame interrupted with IF=1 on a 64-bit kernel stack.
/// Caller is responsible for proving that these values were captured by
/// a genuine interrupt handler and that the frame remains live/readable.
pub fn validate_kernel_irq_frame(
    rip: u64,
    rsp: u64,
    cs: u64,
    rflags: u64,
) -> Result<KernelIrqFrame, FrameError> {
    if rip == 0 {
        return Err(FrameError::NullInstructionPointer);
    }
    if rsp == 0 {
        return Err(FrameError::NullStackPointer);
    }
    if rsp & 0x7 != 0 {
        return Err(FrameError::UnalignedStackPointer);
    }
    if cs == 0 || cs & 0x3 != 0 {
        return Err(FrameError::NotKernelCode);
    }
    if rflags & RFLAGS_RESERVED_ONE == 0 {
        return Err(FrameError::InvalidFlags);
    }
    if rflags & RFLAGS_INTERRUPT_ENABLE == 0 {
        return Err(FrameError::InterruptsWereDisabled);
    }
    Ok(KernelIrqFrame { rip, rsp, cs, rflags })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_kernel_timer_frame_from_interrupt_enabled_context() {
        let frame = validate_kernel_irq_frame(
            0xffff_ffff_8000_1000, 0xffff_8000_1234_5678, 0x08, 0x202
        ).unwrap();
        assert_eq!(frame.rip, 0xffff_ffff_8000_1000);
        assert_eq!(frame.rsp, 0xffff_8000_1234_5678);
        assert_eq!(frame.cs, 0x08);
        assert_eq!(frame.rflags, 0x202);
    }

    #[test]
    fn refuses_null_or_misaligned_instruction_context() {
        assert_eq!(
            validate_kernel_irq_frame(0, 0x1000, 0x08, 0x202),
            Err(FrameError::NullInstructionPointer)
        );
        assert_eq!(
            validate_kernel_irq_frame(0x1000, 0, 0x08, 0x202),
            Err(FrameError::NullStackPointer)
        );
        assert_eq!(
            validate_kernel_irq_frame(0x1000, 0x1001, 0x08, 0x202),
            Err(FrameError::UnalignedStackPointer)
        );
    }

    #[test]
    fn refuses_user_mode_or_bad_interrupt_state() {
        assert_eq!(
            validate_kernel_irq_frame(0x1000, 0x2000, 0x1b, 0x202),
            Err(FrameError::NotKernelCode)
        );
        assert_eq!(
            validate_kernel_irq_frame(0x1000, 0x2000, 0, 0x202),
            Err(FrameError::NotKernelCode)
        );
        assert_eq!(
            validate_kernel_irq_frame(0x1000, 0x2000, 0x08, 0x200),
            Err(FrameError::InvalidFlags)
        );
        assert_eq!(
            validate_kernel_irq_frame(0x1000, 0x2000, 0x08, 0x02),
            Err(FrameError::InterruptsWereDisabled)
        );
    }
}
