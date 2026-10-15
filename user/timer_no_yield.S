// Two independent 64-bit ET_EXEC images assembled with WOLFOS_PID=1/2.
// CPU-bound sections never request a voluntary yield. The ONLY INT80 is EXIT(0).
// This is a host-verified fixture, NOT yet a real timer-driven QEMU smoke.
.intel_syntax noprefix
.section .text
.global _start
.global _work_begin
.global _work_end
.global _exit_return
_start:
    mov r12d, WOLFOS_PID
    movabs r14, (0x5a5a000100000000 + WOLFOS_PID)
    movq xmm0, r14
    xor r13d, r13d
work_round:
    mov ecx, 12000000
_work_begin:
    dec ecx
    jnz _work_begin
_work_end:
    // Private RW progress survives context switches under a separate CR3.
    add qword ptr [rip + progress], 1
    inc r13
    cmp r13, 16
    jb work_round

    // Verify the full CPU workload completed without a single yield.
    cmp r13, qword ptr [rip + progress]
    jne failed
    cmp r12d, WOLFOS_PID
    jne failed
    movq r15, xmm0
    cmp r15, r14
    jne failed
    mov eax, 3                   # WolfOS experimental EXIT syscall.
    xor edi, edi
    xor esi, esi
    int 0x80
_exit_return:
failed:
    ud2

.section .data
.global progress
progress:
    .quad 0
