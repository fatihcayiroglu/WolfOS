/* One RX PT_LOAD for genuinely executed hardware CPL3. Read-only fixture
 * bytes and zero-filled BSS tail share the RX LOAD with the code; the
 * separately allocated user stack is RW/NX and is not an ELF PT_LOAD.
 * The kernel audits the exact six-frame (4 tables + 1 LOAD + 1 stack) lease.
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);
}
SECTIONS {
    . = 0x401000;
    .text : { *(.text*) *(.rodata*) *(.data*) } :text
    .bss (NOLOAD) : { *(.bss*) } :text
    /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) }
}
