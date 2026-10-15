// TWO separate native ELF64 ET_EXEC files, compiled independently with
// WOLFOS_PID=1 or =2. Their physical code/data/stack mappings never alias.
// The test-only voluntary yield syscall #9 is NOT a stable WolfOS ABI.
// All user accesses remain within their own mapped user RX and RW/NX pages.
.intel_syntax noprefix
.section .text
.global _start
.global _yield_return
.global _exit_return
_start:
    mov r12d, WOLFOS_PID
    movabs r14, (0x5a5a000100000000 + WOLFOS_PID)
    movq xmm0, r14
    xor r13d, r13d
loop:
    // Independently linked RW segment: a private user data value survives
    // switching to the other private CR3 and back.
    add qword ptr [rip + progress], 1
    inc r13
    mov eax, 9
    xor edi, edi
    xor esi, esi
    int 0x80
_yield_return:
    test eax, eax
    jne fail
    cmp r12d, WOLFOS_PID
    jne fail
    cmp r13, qword ptr [rip + progress]
    jne fail
    movq r15, xmm0
    cmp r15, r14
    jne fail
    cmp r13, 4
    jb loop
    // Last yield must resume normally before EXIT(0). Every process will
    // execute four independent INT80->other-PID->IRETQ round trips.
    mov eax, 3
    xor edi, edi
    xor esi, esi
    int 0x80
_exit_return:
fail:
    ud2

.section .data
.global progress
progress: .quad 0
