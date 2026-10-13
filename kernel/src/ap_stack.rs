//! Dedicated, permanent WolfOS-owned 32 KiB kernel stack for each secondary CPU.
//!
//! Limine gives an AP an initial bootstrap stack. Switch to an independently
//! allocated kernel stack through a tiny never-returning x86-64 trampoline.
//! There is no Rust stack frame alive across the assembly stack switch.
//! This is NOT a context switch or production scheduler: no stack guard pages,
//! stack growth, user mode or APIC interrupt delivery yet.

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use limine::mp::MpInfo;
use crate::smp::MAX_BOOT_CPUS;

pub const KERNEL_STACK_SIZE: usize = 32 * 1024;
const STACK_CANARY: u64 = 0x574F_4C46_5354_414B;

#[repr(align(16))]
struct Stack([u8; KERNEL_STACK_SIZE]);

struct StackBank(UnsafeCell<[Stack; MAX_BOOT_CPUS]>);

// SAFETY: CPU indices are checked for uniqueness by the BSP before releasing
// any AP. Exactly one AP owns each stack slot. The BSP initializes the
// canary before bootstrap and does not modify slots afterward.
unsafe impl Sync for StackBank {}

static STACKS: StackBank = StackBank(UnsafeCell::new(
    [const { Stack([0; KERNEL_STACK_SIZE]) }; MAX_BOOT_CPUS]
));

fn stack_bottom(index: usize) -> Option<usize> {
    if index >= MAX_BOOT_CPUS { return None; }
    // SAFETY: the pointer is used for address calculation only; it does not
    // create a shared or mutable Rust reference to an actively used stack.
    let ptr = unsafe { core::ptr::addr_of_mut!((*STACKS.0.get())[index]) };
    Some(ptr.cast::<u8>() as usize)
}

/// BSP only, before starting the corresponding secondary processor.
pub fn prepare(index: usize) -> Option<usize> {
    let bottom = stack_bottom(index)?;
    let top = bottom.checked_add(KERNEL_STACK_SIZE)?;
    if bottom % 16 != 0 || top % 16 != 0 { return None; }
    // SAFETY: unique slot is not yet used by the AP and backing BSS is mapped.
    unsafe { (bottom as *mut u64).write_volatile(STACK_CANARY ^ index as u64); }
    Some(top)
}

/// AP-only: fetch the already prepared stack without modifying its canary.
/// BSP initializes it before publishing the Limine MP entrypoint.
pub fn prepared_top(index: usize) -> Option<usize> {
    let bottom = stack_bottom(index)?;
    let top = bottom.checked_add(KERNEL_STACK_SIZE)?;
    // SAFETY: BSP published the initialized stack before AP execution and
    // will not modify it; this read is before the AP changes RSP.
    let found = unsafe { (bottom as *const u64).read_volatile() };
    if found != STACK_CANARY ^ index as u64 { return None; }
    Some(top)
}

/// Called from the secondary Rust entry after the assembly stack switch.
pub fn verify_active(index: usize) -> bool {
    let Some(bottom) = stack_bottom(index) else { return false; };
    let Some(top) = bottom.checked_add(KERNEL_STACK_SIZE) else { return false; };
    let rsp: usize;
    // SAFETY: reading RSP changes no processor or memory state.
    unsafe { asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)); }
    // Keep room for further Rust frames before the lower boundary.
    if rsp < bottom + 1024 || rsp >= top { return false; }
    // SAFETY: slot is exclusively owned by the calling AP; only the first
    // u64 canary is read. It is outside the active stack frame.
    unsafe {
        (bottom as *const u64).read_volatile() == (STACK_CANARY ^ index as u64)
    }
}

// System V x86-64 ABI: rdi=MpInfo*, rsi=CPU directory index, rdx=stack top.
// The trampoline aligns the stack to 16 bytes before CALL, which establishes
// the required RSP % 16 == 8 inside wolfos_ap_stack_rust. It never returns.
// No Rust code executes between modifying RSP and calling the new entry.
global_asm!(
    ".global wolfos_ap_stack_enter",
    ".type wolfos_ap_stack_enter, @function",
    "wolfos_ap_stack_enter:",
    "mov rsp, rdx",
    "and rsp, -16",
    "xor rbp, rbp",
    "call wolfos_ap_stack_rust",
    "ud2",
);

unsafe extern "C" {
    fn wolfos_ap_stack_enter(
        info: *const MpInfo,
        index: usize,
        stack_top: usize,
    ) -> !;
}

/// # Safety
/// - info must point to a live Limine MpInfo for the duration of the AP.
/// - index is the unique CPU slot whose stack was prepared by the BSP.
/// - stack_top must be the corresponding valid, 16-byte-aligned top.
/// - this function never returns to the old Limine stack.
pub unsafe fn enter(info: &MpInfo, index: usize, stack_top: usize) -> ! {
    // SAFETY: validated during BSP CPU enumeration, backing static kernel
    // stack remains allocated forever, trampoline never returns.
    unsafe { wolfos_ap_stack_enter(info as *const MpInfo, index, stack_top) }
}
