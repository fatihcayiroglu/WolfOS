//! BSP-only, QEMU-only legacy x87/SSE context preservation proof.
//!
//! FXSAVE64 / FXRSTOR64 save and restore the x87/MMX environment, MXCSR and
//! 16 architectural XMM registers using a 16-byte-aligned 512-byte image.
//! This does NOT preserve AVX YMM upper lanes, AVX-512, MPX or other XSAVE
//! components. Production xstate requires CPUID leaf 0xD + XGETBV,
//! per-task XCR0 policy, sized XSAVE areas and tested interrupt behavior.
//!
//! Only the dedicated 'apic-preempt-smoke' flavor calls these functions:
//! the BSP owns every image; APs are parked and do not enable interrupts.
//! The compiler cannot assume vector state survives calls to this module.
//! The timer's SysV Rust IRQ callback must not use XMM/x87 instructions.

use core::arch::{asm, x86_64::__cpuid};
use core::cell::UnsafeCell;
use core::mem::{align_of, size_of};

pub const FX_BYTES: usize = 512;
pub const FX_TASKS: usize = 3;
pub const XMM_OFFSET: usize = 160;
pub const XMM_STRIDE: usize = 16;
pub const XMM_COUNT: usize = 16;
const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR0_TS: u64 = 1 << 3;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const FXSR_CPUID: u32 = 1 << 24;
const SSE_CPUID: u32 = 1 << 25;
const SSE2_CPUID: u32 = 1 << 26;

#[repr(C, align(16))]
#[derive(Clone)]
pub struct FxImage {
    bytes: [u8; FX_BYTES],
}

impl FxImage {
    pub const fn empty() -> Self { Self { bytes: [0; FX_BYTES] } }

    /// Inspect a low 64-bit lane from an FXSAVE image without changing FPU.
    pub fn xmm_low(&self, index: usize) -> Option<u64> {
        if index >= XMM_COUNT { return None; }
        let offset = XMM_OFFSET + index * XMM_STRIDE;
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&self.bytes[offset..offset + 8]);
        Some(u64::from_le_bytes(bytes))
    }
}

struct Owned<T>(UnsafeCell<T>);
// SAFETY: only BSP uses these cells; IRQ code is serialized by the xAPIC
// interrupt gate and runs on the same BSP. APs are parked with IF=0.
unsafe impl<T> Sync for Owned<T> {}
static ORIGINAL: Owned<FxImage> = Owned(UnsafeCell::new(FxImage::empty()));
static TASK_IMAGES: Owned<[FxImage; FX_TASKS]> =
    Owned(UnsafeCell::new([
        FxImage::empty(), FxImage::empty(), FxImage::empty()
    ]));

#[derive(Clone, Copy)]
pub struct OriginalControl {
    cr0: u64,
    cr4: u64,
}

/// CPUID feature check is done before CR0/CR4 enablement; no FPU instruction
/// is issued when the CPU cannot support the 512-byte FX image.
pub fn supported() -> bool {
    // SAFETY: CPUID leaf 1 is always implemented by x86-64 CPUs.
    let f = __cpuid(1);
    f.edx & (FXSR_CPUID | SSE_CPUID | SSE2_CPUID)
        == FXSR_CPUID | SSE_CPUID | SSE2_CPUID
}

#[inline]
unsafe fn save_raw(image: *mut FxImage) {
    // SAFETY: caller guarantees valid 16-byte aligned, writable 512 bytes
    // and CR0.EM=TS=0, CR4.OSFXSR=1 with CPUID.FXSR=1.
    unsafe { asm!("fxsave64 [{}]", in(reg) image, options(nostack)); }
}

#[inline]
unsafe fn restore_raw(image: *const FxImage) {
    // SAFETY: the image was produced by FXSAVE64 with consistent MXCSR
    // control bits; no task changes xstate policy between save and restore.
    unsafe { asm!("fxrstor64 [{}]", in(reg) image, options(nostack)); }
}

/// Configure the BSP only, save its original x87/SSE image and initialize
/// THREE task images with the same valid baseline. CALL WITH IF=0.
///
/// Safety: only the BSP can execute this after all APs have parked; no
/// user tasks, kernel XSAVE ownership, or SMP FPU management are active.
/// The caller MUST invoke leave() exactly once after all tasks stop.
pub unsafe fn enter() -> Option<OriginalControl> {
    if !supported() { return None; }
    let cr0: u64;
    let cr4: u64;
    // SAFETY: x86-64 supervisor code on BSP; IF=0, no concurrent CPU
    // modifies BSP's CR0/CR4 registers.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack));
        let next_cr0 = (cr0 | CR0_MP) & !(CR0_EM | CR0_TS);
        let next_cr4 = cr4 | CR4_OSFXSR | CR4_OSXMMEXCPT;
        asm!("mov cr0, {}", in(reg) next_cr0, options(nostack));
        asm!("mov cr4, {}", in(reg) next_cr4, options(nostack));
        let original = ORIGINAL.0.get();
        save_raw(original);
        let tasks = TASK_IMAGES.0.get();
        core::ptr::copy_nonoverlapping(original, core::ptr::addr_of_mut!((*tasks)[0]), 1);
        core::ptr::copy_nonoverlapping(original, core::ptr::addr_of_mut!((*tasks)[1]), 1);
        core::ptr::copy_nonoverlapping(original, core::ptr::addr_of_mut!((*tasks)[2]), 1);
    }
    Some(OriginalControl { cr0, cr4 })
}

/// Save the interrupted task x87/SSE image and restore the destination.
/// Must be called only AFTER both KernelTrapFrames are fully validated.
/// The Rust IRQ callback must not itself use x87/SIMD registers.
///
/// Safety: only BSP, IF=0 in the interrupt gate, both task IDs in 0..2,
/// enter() was called, and no other CPU accesses FX images.
pub unsafe fn switch(current: usize, next: usize) -> Option<u64> {
    if current >= FX_TASKS || next >= FX_TASKS || current == next {
        return None;
    }
    unsafe {
        let tasks = TASK_IMAGES.0.get();
        let source = core::ptr::addr_of_mut!((*tasks)[current]);
        let destination = core::ptr::addr_of!((*tasks)[next]);
        save_raw(source);
        let observed = (*source).xmm_low(0)?;
        restore_raw(destination);
        Some(observed)
    }
}

/// Load a distinctive low 64-bit XMM0 lane while a task is running.
/// Unsafe because the caller must own this BSP task's live FX state.
pub unsafe fn set_test_xmm0(value: u64) {
    unsafe {
        asm!("movq xmm0, {}", in(reg) value, options(nostack, preserves_flags));
    }
}

/// Read the live low 64-bit XMM0 lane on the current BSP task.
pub unsafe fn read_test_xmm0() -> u64 {
    let result: u64;
    unsafe {
        asm!("movq {}, xmm0", out(reg) result, options(nostack, preserves_flags));
    }
    result
}

/// Restore the ORIGINAL BSP x87/SSE state, then its CR0/CR4 bits.
/// Safety: preemption has stopped, IF=0, all private task stacks are inactive.
/// No further FXSAVE/FXRSTOR runs after CR4/CR0 restoration.
pub unsafe fn leave(original: OriginalControl) {
    unsafe {
        restore_raw(ORIGINAL.0.get());
        asm!("mov cr4, {}", in(reg) original.cr4, options(nostack));
        asm!("mov cr0, {}", in(reg) original.cr0, options(nostack));
    }
}

/// Evidence from quiescent FX image recycling. This is a memory operation,
/// not a CPU FXRSTOR: the scheduler has already restored its original BSP
/// state, and the next occupant of this slot has NOT been made runnable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FxRecycleProof {
    pub old_xmm0: u64,
    pub fully_scrubbed: bool,
    pub baseline_reseeded: bool,
    pub aligned: bool,
}

/// Scrub an inactive finished task's full 512-byte FX image, then reseed it
/// from the original, valid BSP FXSAVE64 image. No live XMM state is changed.
/// 
/// # Safety
/// BSP IF=0; APs parked. The interrupt scheduler has stopped, exited onto a
/// disjoint stack, and finished task's xstate image has no remaining users.
/// The caller MUST verify these conditions before calling. No cross-CPU
/// reclamation guarantee is provided here.
pub unsafe fn recycle_task_image(task: usize) -> Option<FxRecycleProof> {
    if task >= FX_TASKS { return None; }
    unsafe {
        let images = TASK_IMAGES.0.get();
        let target = core::ptr::addr_of_mut!((*images)[task]);
        let original = ORIGINAL.0.get();
        let previous = (*target).xmm_low(0)?;
        let aligned = (target as usize) & 15 == 0;
        if !aligned { return None; }
        // No FXSAVE/FXRSTOR executes during image recycling; this is an
        // explicit scrubbing operation on a logically dead task image.
        core::ptr::write_bytes(target.cast::<u8>(), 0, FX_BYTES);
        let cleared = (*target).bytes.iter().all(|byte| *byte == 0);
        core::ptr::copy_nonoverlapping(original, target, 1);
        let reseeded = (*target).bytes == (*original).bytes;
        Some(FxRecycleProof {
            old_xmm0: previous,
            fully_scrubbed: cleared,
            baseline_reseeded: reseeded,
            aligned,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fxsave_layout_is_exactly_512_bytes_and_16_byte_aligned() {
        assert_eq!(size_of::<FxImage>(), FX_BYTES);
        assert_eq!(align_of::<FxImage>(), 16);
        assert_eq!(XMM_OFFSET, 160);
        assert_eq!(XMM_OFFSET + XMM_COUNT * XMM_STRIDE, 416);
    }

    #[test]
    fn xmm_lanes_decode_exactly_and_out_of_range_is_rejected() {
        let mut image = FxImage::empty();
        assert_eq!(image.xmm_low(0), Some(0));
        assert_eq!(image.xmm_low(15), Some(0));
        let expected = 0x1234_5678_9abc_def0_u64;
        image.bytes[XMM_OFFSET..XMM_OFFSET + 8]
            .copy_from_slice(&expected.to_le_bytes());
        assert_eq!(image.xmm_low(0), Some(expected));
        let last = XMM_OFFSET + 15 * XMM_STRIDE;
        image.bytes[last..last + 8].copy_from_slice(&42_u64.to_le_bytes());
        assert_eq!(image.xmm_low(15), Some(42));
        assert_eq!(image.xmm_low(16), None);
        assert_eq!(image.xmm_low(usize::MAX), None);
    }

    #[test]
    fn distinct_context_images_never_alias() {
        let task = [FxImage::empty(), FxImage::empty(), FxImage::empty()];
        let a = core::ptr::addr_of!(task[0]) as usize;
        let b = core::ptr::addr_of!(task[1]) as usize;
        let c = core::ptr::addr_of!(task[2]) as usize;
        assert_eq!(b - a, FX_BYTES);
        assert_eq!(c - b, FX_BYTES);
        assert_eq!(a & 15, 0);
        assert_eq!(b & 15, 0);
        assert_eq!(c & 15, 0);
    }
}
