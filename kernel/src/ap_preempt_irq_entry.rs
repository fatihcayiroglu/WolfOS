//! Secondary-core ONLY x86-64 timer IRQ entry, with full GPR restoration.
//! Independent from BSP's xAPIC IRQ stub and its scheduler smoke.
//! This is QEMU-only kernel-CPL0, same-CR3, no IST, no userspace.
use core::arch::global_asm;
use x86_64::VirtAddr;

global_asm!(
    ".section .text",
    ".global wolfos_ap_preempt_irq_entry",
    ".type wolfos_ap_preempt_irq_entry, @function",
    "wolfos_ap_preempt_irq_entry:",
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
    // Pass pointer to full 15-GPR + hardware return frame.
    // Rust callback returns the SAME pointer or one owned by the same AP.
    "mov rdi, rsp",
    "and rsp, -16",
    "cld",
    "call wolfos_ap_preempt_irq_dispatch",
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
    ".size wolfos_ap_preempt_irq_entry, .-wolfos_ap_preempt_irq_entry",
);

unsafe extern "C" {
    fn wolfos_ap_preempt_irq_entry();
}
pub fn address() -> VirtAddr {
    VirtAddr::new(wolfos_ap_preempt_irq_entry as usize as u64)
}
