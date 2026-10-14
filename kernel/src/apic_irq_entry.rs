//! BSP-only xAPIC timer interrupt entry used by the isolated smoke flavors.
//!
//! Hardware pushes the architectural 64-bit interrupt return frame. The
//! assembly saves all 15 general-purpose registers in exactly the push order
//! modeled by kernel_trap_frame::SavedGprs, calls Rust with a stack pointer,
//! restores every GPR and performs IRETQ to the SAME interrupted task.
//!
//! No context switching, timer-induced scheduling, alternate stack, XSAVE,
//! CR3 switching, ring-3 support or cross-CPU use. Rust must not save a
//! pointer to this ephemeral frame. The local APIC handler must EOI.
//!
//! This contract assumes a long-mode IDT interrupt gate, kernel CPL0,
//! same-address-space execution, and no interrupt stack-table switch.

use core::arch::global_asm;
use x86_64::VirtAddr;

global_asm!(
    ".section .text",
    ".global wolfos_apic_irq_entry",
    ".type wolfos_apic_irq_entry, @function",
    "wolfos_apic_irq_entry:",
    // 15 pushes, with the last at the lowest address. Resulting RSP points
    // at SavedGprs.r15, immediately followed by hardware RIP,CS,RFLAGS,RSP,SS.
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
    // rbx was already saved: it can hold the original stack address
    // through the SysV Rust call (callee-saved under the ABI).
    "mov rdi, rsp",
    "mov rbx, rsp",
    "and rsp, -16",
    // A kernel IRQ may interrupt with DF set; SysV Rust requires DF cleared.
    // IRETQ restores the original RFLAGS including DF and IF.
    "cld",
    "call wolfos_apic_timer_irq_dispatch",
    "mov rsp, rbx",
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
    ".size wolfos_apic_irq_entry, .-wolfos_apic_irq_entry",
);

unsafe extern "C" {
    fn wolfos_apic_irq_entry();
}

pub fn address() -> VirtAddr {
    VirtAddr::new(wolfos_apic_irq_entry as usize as u64)
}
