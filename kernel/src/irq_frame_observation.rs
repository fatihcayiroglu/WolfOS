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
    NonCanonicalInstructionPointer,
    NonCanonicalStackPointer,
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

/// A four-level PML4 address must sign-extend bit 47 into bits 63:48.
/// This is only a structural check, NOT proof that the page is mapped,
/// belongs to the kernel, or was captured by a physical IRQ handler.
const fn canonical48(addr: u64) -> bool {
    let high = addr >> 48;
    high == if (addr & (1_u64 << 47)) == 0 { 0 } else { 0xffff }
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
    if !canonical48(rip) {
        return Err(FrameError::NonCanonicalInstructionPointer);
    }
    if !canonical48(rsp) {
        return Err(FrameError::NonCanonicalStackPointer);
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
    fn refuses_noncanonical_irq_instruction_and_stack_addresses() {
        // Each hole is forbidden by the active four-level PML4 model,
        // even with an otherwise plausible CPL0 IF-enabled IRQ frame.
        for bad in [
            0x0000_8000_0000_0000,
            0x0001_0000_0000_0000,
            0xffff_7fff_ffff_fff8,
        ] {
            assert_eq!(
                validate_kernel_irq_frame(bad, 0xffff_8000_0000_1000, 0x08, 0x202),
                Err(FrameError::NonCanonicalInstructionPointer),
            );
            assert_eq!(
                validate_kernel_irq_frame(0xffff_ffff_8000_1000, bad, 0x08, 0x202),
                Err(FrameError::NonCanonicalStackPointer),
            );
        }
    }

    #[test]
    fn canonical_address_boundaries_are_not_rejected_as_holes() {
        for (rip, rsp) in [
            (0x0000_7fff_ffff_ffff, 0x0000_7fff_ffff_fff8),
            (0xffff_8000_0000_0000, 0xffff_8000_0000_0000),
        ] {
            assert_eq!(
                validate_kernel_irq_frame(rip, rsp, 0x08, 0x202),
                Ok(KernelIrqFrame { rip, rsp, cs: 0x08, rflags: 0x202 })
            );
        }
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
