// Dedicated actual-CPL3 WAIT/SIGNAL/RESUME proof; two independently linked
// ELF64 ET_EXEC files. PID1 traps WAIT(event 77); PID2 traps SIGNAL(event 77).
// A matching kernel wake must restore PID1's *original* saved INT80 IRET/GPR
// frame (plus its private CR3, guarded RSP0 and FXSAVE64 state) before EXIT.
// IF=0: this proof contains no timer IRQ and must not claim any EOI.
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
    add qword ptr [rip + progress], 1
    inc r13
.if WOLFOS_PID == 1
    // SYS_WAIT_EVENT: syscall and separate event must both be authenticated.
    mov eax, 10
.else
    // Malicious or stale event delivered by real PID2 CPL3 code must
    // return an explicit error and never release PID1's blocked frame.
    // This intentionally exercises the syscall boundary, not a synthetic
    // direct kernel ledger call.
    mov eax, 11
    mov edi, 78
    xor esi, esi
    int 0x80
.global _bad_signal_return
_bad_signal_return:
    cmp eax, 1
    jne failed
    cmp r12d, WOLFOS_PID
    jne failed
    cmp r13, 1
    jne failed
    cmp qword ptr [rip + progress], 1
    jne failed
    movq r15, xmm0
    cmp r15, r14
    jne failed
    mov eax, 11
.endif
    mov edi, 77
    xor esi, esi
    int 0x80
_yield_return:
    // PID1 MUST return here after genuine cross-PID IRET, not immediately
    // from the original BLOCK syscall. PID2 resumes after PID1 EXIT.
    test eax, eax
    jne failed
    cmp r12d, WOLFOS_PID
    jne failed
    cmp r13, 1
    jne failed
    cmp qword ptr [rip + progress], 1
    jne failed
    movq r15, xmm0
    cmp r15, r14
    jne failed
    mov eax, 3
    xor edi, edi
    xor esi, esi
    int 0x80
_exit_return:
failed:
    ud2

.section .data
.global progress
progress: .quad 0
