// First independently ASSEMBLED and LINKED user-space ELF64 application.
// No code bytes are embedded into the kernel's source as a hand-built
// instruction array. GNU as+ld produce an ET_EXEC file at build time.
// All addresses are RIP-relative; the isolated QEMU loader may relocate
// the image by an entire PML4-slot offset without dynamic ELF relocations.
//
// Stable no_std WolfOS INT80 experimental ABI:
// RAX: ID=1, checked-add=2, EXIT_ZERO=3, PUTC=4.
// RDI=arg0, RSI=arg1. Return RAX only, other GPRs preserved.

.intel_syntax noprefix
.section .text
.global _start
.global _after_id
.global _after_add
.global _after_putc
.global _after_exit
_start:
    mov eax, 1
    xor edi, edi
    xor esi, esi
    int 0x80
_after_id:
    cmp eax, 0x574f4c46
    jne fail

    mov eax, 2
    mov edi, 7
    mov esi, 35
    int 0x80
_after_add:
    cmp rax, 42
    jne fail

    // Both values MUST be read from the actual separately mapped ELF
    // PT_LOAD data segment, not checked only from kernel-side HHDM.
    cmp byte ptr [rip + fixture_magic], 0x5a
    jne fail
    cmp byte ptr [rip + uninitialized], 0
    jne fail

    // Isolated genuine CPL3 file I/O guest, deliberately NOT a POSIX API.
    // Every path and destination pointer is read from real user registers.
.ifdef WOLFOS_FILE_IO_SMOKE
    // Negative: a supervisor pointer may NEVER be followed.
    movabs rdi, 0xffff800000000000
    mov esi, file_path_end - file_path
    xor edx, edx
    mov eax, 6
    int 0x80
_after_file_bad_open:
    cmp rax, -14
    jne fail

    // Positive: OPEN_RO a user RX-text path (the 4-level walker may read RX).
    lea rdi, [rip + file_path]
    mov esi, file_path_end - file_path
    xor edx, edx
    mov eax, 6
    int 0x80
_after_file_open:
    cmp rax, 256            # first VFS slot, generation one
    jne fail
    mov r12, rax            # keep opaque handle across subsequent INT80

    // Negative: READ must not write into the RX executable code page.
    mov rdi, r12
    lea rsi, [rip + hello_text]
    mov edx, 8
    mov eax, 7
    int 0x80
_after_file_bad_read:
    cmp rax, -14
    jne fail

    // Positive: READ into a real RW+NX user stack (not a kernel address).
    mov rdi, r12
    lea rsi, [rsp - 32]
    mov edx, 8
    mov eax, 7
    int 0x80
_after_file_read:
    cmp rax, 8
    jne fail
    cmp dword ptr [rsp - 32], 0x454c4946 # FILE
    jne fail
    cmp dword ptr [rsp - 28], 0x0a4b4f5f # _OK newline
    jne fail

    // EOF and clean release, then reject stale handle.
    mov rdi, r12
    lea rsi, [rsp - 32]
    mov edx, 8
    mov eax, 7
    int 0x80
_after_file_eof:
    test rax, rax
    jne fail

    mov rdi, r12
    xor esi, esi
    xor edx, edx
    mov eax, 8
    int 0x80
_after_file_close:
    test rax, rax
    jne fail

    mov rdi, r12
    xor esi, esi
    xor edx, edx
    mov eax, 8
    int 0x80
_after_file_stale_close:
    cmp rax, -9
    jne fail
_after_write:
_after_putc:
.else
    // New opt-in real user-POINTER syscall. The kernel cannot trust RDI;
    // it must WALK the live independent user CR3 and copy via HHDM.
.ifdef WOLFOS_USERCOPY_SMOKE
    lea rdi, [rip + hello_text]
    mov esi, hello_end - hello_text
    xor edx, edx      # RDX reserved: caller must initialize to zero
    mov eax, 5
    int 0x80
_after_write:
    cmp rax, hello_end - hello_text
    jne fail
_after_putc:
.else
    // Original historical single-byte PUTC regression is unchanged.
    lea rbx, [rip + hello_text]
    mov ecx, hello_end - hello_text
print_loop:
    movzx edi, byte ptr [rbx]
    mov eax, 4
    xor esi, esi
    int 0x80
_after_putc:
    cmp rax, 1
    jne fail
    inc rbx
    dec ecx
    jnz print_loop
_after_write:
.endif
.endif

.ifdef WOLFOS_USER_PF_FAULT_SMOKE
    // Genuine faulting CPL3 supervisor-address read: the CPU must raise
    // #PF rather than permit a user process to read this high-half page.
    movabs rax, 0xffff800000000000
.global _user_fault_pf
_user_fault_pf:
    mov rax, qword ptr [rax]
.else
.ifdef WOLFOS_USER_UD_FAULT_SMOKE
    // Deliberate genuine user-mode #UD; the OS must retire THIS process,
    // never pretend the kernel exception handler or INT80 returned normally.
.global _user_fault_ud
_user_fault_ud:
    ud2
.else
.ifdef WOLFOS_EXIT_STATUS_SMOKE
    // A real CPL3 task requests EXIT(42) from its saved RDI, not a
    // kernel-synthesized status. INT80 must not return after cleanup.
    mov eax, 9
    mov edi, 42
.else
    mov eax, 3
    xor edi, edi
.endif
    xor esi, esi
    int 0x80
.endif
.endif
_after_exit:
    ud2                    # EXIT must never return
fail:
    ud2                    # Wrong syscall or ELF data result must fault
hello_text:
    .ascii "Hello from WolfOS!\n"
hello_end:
file_path:
    .ascii "/tmp/msg.txt"
file_path_end:

.section .data
.global fixture_magic
fixture_magic: .byte 0x5a

.section .bss
.global uninitialized
uninitialized: .zero 64
