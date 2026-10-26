/* Standalone x86-64 real CPL3 ELF proof with two executable file-backed
 * leaves plus one RW+NX data/BSS leaf, and a separate RW+NX stack. The
 * second RX page contains actual CALLED guest instructions, not padding.
 * Exactly two 2-MiB PT regions and nine separately leased PMM frames.
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}
SECTIONS {
    . = 0x401000;
    .text : { *(.text) } :text
    . = 0x402000;
    .text.second_page : { *(.text.second_page) } :text
    . = 0x600000;
    .data : { *(.data*) } :data
    .bss (NOLOAD) : { *(.bss*) } :data
    /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) }
}
