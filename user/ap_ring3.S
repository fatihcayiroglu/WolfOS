/* WolfOS P3: independently assembled AP ET_EXEC CPL3 guest.
 * This is trusted test code, never an injected runtime kernel byte array.
 * Exactly two INT80 instructions, first returns by IRETQ.
 */
.intel_syntax noprefix
.section .text,"ax",@progbits
.global _start
.global _after_first_int80
.global _after_second_int80
_start:
    mov BYTE PTR [rip + ap_nonce], 0x11
    int 0x80
_after_first_int80:
    mov BYTE PTR [rip + ap_nonce], 0x22
    int 0x80
_after_second_int80:
    ud2

.section .data,"aw",@progbits
.global ap_nonce
ap_nonce:
    .byte 0
