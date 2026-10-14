//! QEMU-only secondary-core timer entry and cross-core resume primitive.
//! Frame is 15 GPR pushes followed by x86-64 hardware 5-word IRETQ.
//! No IST, no CPL transition, no user processes and SAME kernel CR3.
//! Rust callback saves task FX before switching to per-AP escape frame.

use core::arch::global_asm;
use x86_64::VirtAddr;
use crate::kernel_trap_frame::KernelTrapFrame;

global_asm!(
    ".section .text",
    ".global wolfos_ap_migrate_timer_irq_entry",
    ".type wolfos_ap_migrate_timer_irq_entry,@function",
    "wolfos_ap_migrate_timer_irq_entry:",
    "push rax",
    "push rbx",
    "push rcx",
    "push rdx",
    "push rsi",
    "push rdi",
    "push rbp",
    "push r8",
    "push r9",
    "push r10",
    "push r11",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov rdi, rsp",
    "and rsp, -16",
    "cld",
    "call wolfos_ap_migrate_timer_irq_dispatch",
    "mov rsp, rax",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rbp",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rbx",
    "pop rax",
    "iretq",
    ".size wolfos_ap_migrate_timer_irq_entry, .-wolfos_ap_migrate_timer_irq_entry",

    // Saved coordinator context is a 6-GPR System V switch frame, just
    // like context_switch::switch_raw. Called from the destination AP's
    // Rust coordinator while IF=0, and returns only after its own timer
    // handler IRETQs onto its private escape stack; the escape trampoline
    // switches back to this saved coordinator RSP.
    ".global wolfos_ap_migrate_resume_saved_irq",
    ".type wolfos_ap_migrate_resume_saved_irq,@function",
    "wolfos_ap_migrate_resume_saved_irq:",
    "push rbx",
    "push rbp",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov [rdi], rsp",
    "mov rsp, rsi",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop r11",
    "pop r10",
    "pop r9",
    "pop r8",
    "pop rbp",
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop rbx",
    "pop rax",
    "iretq",
    ".size wolfos_ap_migrate_resume_saved_irq, .-wolfos_ap_migrate_resume_saved_irq",
);

unsafe extern "C" {
    fn wolfos_ap_migrate_timer_irq_entry();
    fn wolfos_ap_migrate_resume_saved_irq(
        coordinator_rsp: *mut usize,
        captured_irq: *const KernelTrapFrame,
    );
}

pub fn irq_address() -> VirtAddr {
    VirtAddr::new(wolfos_ap_migrate_timer_irq_entry as usize as u64)
}

/// # Safety
/// - Calling AP has IF=0, correct private IDT, GDT, TSS, matching CR3.
/// - Frame belongs to exactly one quiesced task, all 15 GPRs + IRET fields
///   validated against its stable live kernel stack and selector.
/// - Task FX image has been restored; no different CPU may be executing it.
/// - coordinator_rsp is a fresh, CPU-owned cell with a live Rust call chain.
/// - A later timer IRQ must escape to this same AP's coordinator stack.
pub unsafe fn resume_saved_irq(
    coordinator_rsp: *mut usize,
    captured_irq: *const KernelTrapFrame,
) {
    unsafe { wolfos_ap_migrate_resume_saved_irq(coordinator_rsp, captured_irq); }
}
