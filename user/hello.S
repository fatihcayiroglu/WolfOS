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

    // Print the first genuine user-visible message, byte by byte,
    // through original WolfOS PUTC syscall with no unchecked pointers.
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

    mov eax, 3
    xor edi, edi
    xor esi, esi
    int 0x80
_after_exit:
    ud2                    // EXIT must never return
fail:
    ud2                    // Any wrong syscall / ELF data result must fault
hello_text:
    .ascii "Hello from WolfOS!\n"
hello_end:

.section .data
.global fixture_magic
fixture_magic: .byte 0x5a

.section .bss
.global uninitialized
uninitialized: .zero 64
