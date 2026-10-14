//! BSP-only xAPIC timer interrupt entry used by the isolated smoke flavors.
//!
//! Hardware pushes the architectural 64-bit interrupt return frame. The
//! assembly saves all 15 general-purpose registers in exactly the push order
//! modeled by kernel_trap_frame::SavedGprs, calls Rust with a stack pointer,
//! restores every GPR and IRETQs to the interrupted task, except in
//! the isolated preemption smoke where it may resume a second kernel stack.
//!
//! Outside the dedicated preemption feature: no context switching, XSAVE,
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
    // Rust returns the saved trap-frame RSP to resume. Normally it
    // returns the same frame. Only the isolated preemption smoke may
    // select another already-validated task's private stack.
    "mov rdi, rsp",
    "and rsp, -16",
    // A kernel IRQ may interrupt with DF set; SysV Rust requires DF cleared.
    // IRETQ restores the original RFLAGS including DF and IF.
    "cld",
    "call wolfos_apic_timer_irq_dispatch",
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
    ".size wolfos_apic_irq_entry, .-wolfos_apic_irq_entry",
);

unsafe extern "C" {
    fn wolfos_apic_irq_entry();
}

pub fn address() -> VirtAddr {
    VirtAddr::new(wolfos_apic_irq_entry as usize as u64)
}


/// Isolated QEMU-only ABI stress function. It sets ALL 15 GPRs to distinct
/// sentinel values, performs no function calls and never voluntarily yields.
/// Real APIC IRQs must save and restore every register before returning via
/// IRETQ. Only stack-persistent callee-saved registers are changed around
/// the call; their original values are restored before returning to Rust.
///
/// The Rust IRQ callback validates all fifteen register words against the
/// constants below; an IRQ sees PROBE_ACTIVE only after initialization.
global_asm!(
    ".section .text",
    ".global wolfos_apic_gpr_probe",
    ".type wolfos_apic_gpr_probe, @function",
    "wolfos_apic_gpr_probe:",
    "push rbx",
    "push rbp",
    "push r12",
    "push r13",
    "push r14",
    "push r15",
    "mov rax, 0x101",
    "mov rbx, 0x102",
    "mov rcx, 0x103",
    "mov rdx, 0x104",
    "mov rsi, 0x105",
    "mov rdi, 0x106",
    "mov rbp, 0x107",
    "mov r8,  0x108",
    "mov r9,  0x109",
    "mov r10, 0x10a",
    "mov r11, 0x10b",
    "mov r12, 0x10c",
    "mov r13, 0x10d",
    "mov r14, 0x10e",
    "mov r15, 0x10f",
    "mov byte ptr [rip + WOLFOS_PROBE_ACTIVE], 1",
    "2:",
    "cmp qword ptr [rip + WOLFOS_PROBE_MATCH], 4",
    "jae 3f",
    "dec qword ptr [rip + WOLFOS_PROBE_SPINS]",
    "jnz 2b",
    // Bounded timeout; CPU IRQs may be missing in a broken emulator.
    "xor eax, eax",
    "jmp 4f",
    "3:",
    "mov eax, 1",
    "4:",
    "mov byte ptr [rip + WOLFOS_PROBE_ACTIVE], 0",
    "pop r15",
    "pop r14",
    "pop r13",
    "pop r12",
    "pop rbp",
    "pop rbx",
    "ret",
    ".size wolfos_apic_gpr_probe, .-wolfos_apic_gpr_probe",
);

unsafe extern "C" {
    fn wolfos_apic_gpr_probe() -> u64;
}

/// # Safety
/// Only call on the BSP in the APIC smoke with hardware timer IRQs enabled,
/// PROBE_SPINS initialized, and other CPUs parked with maskable IRQs off.
pub unsafe fn run_gpr_probe() -> bool {
    unsafe { wolfos_apic_gpr_probe() == 1 }
}
