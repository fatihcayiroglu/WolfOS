//! P2 real x86-64 CPL3 INT0x80 gate with a complete 15-GPR frame.
//!
//! CPU has already switched from user CPL3 to TSS.RSP0 supervisor stack
//! and pushed RIP/CS/RFLAGS/RSP/SS. Assembly saves all 15 GPRs, passes
//! exactly the captured GPR+hardware frame to the Rust dispatcher, then
//! restores every original GPR EXCEPT the intentionally modified RAX and
//! executes a genuine IRETQ back to the user frame. No STAC, SWAPGS,
//! syscall MSRs, fast SYSCALL/SYSRET or user pointer access.
//!
//! This entry is installed as an IDT DPL3 gate ONLY for user-syscall-smoke.

use core::arch::global_asm;
use x86_64::VirtAddr;

global_asm!(
    ".section .text",
    ".global wolfos_int80_syscall_entry",
    ".type wolfos_int80_syscall_entry, @function",
    "wolfos_int80_syscall_entry:",
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
    "call wolfos_int80_syscall_dispatch",
    // Rust returns pointer to the original checked kernel-stack frame.
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
    ".size wolfos_int80_syscall_entry, .-wolfos_int80_syscall_entry",
);

unsafe extern "C" {
    fn wolfos_int80_syscall_entry();
}

pub fn address() -> VirtAddr {
    VirtAddr::new(wolfos_int80_syscall_entry as *const () as usize as u64)
}
