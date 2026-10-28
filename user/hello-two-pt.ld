/* Isolated hardware two-PT ELF64 smoke. Exactly TWO PT_LOAD segments
 * straddle the 2-MiB 0x600000 boundary after relocation into a vacant
 * nonzero user PML4 slot. Text remains executable/read-only; data+BSS
 * and derived stack occupy a distinct PT with RW+NX leaves.
 * Never used by the normal/default OS or legacy seven-frame Ring3 test.
 */
OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)
PHDRS {
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}
SECTIONS {
    . = 0x401000;
    .text : { *(.text*) } :text
    . = 0x600000;
    .data : { *(.data*) } :data
    .bss (NOLOAD) : { *(.bss*) } :data
    /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) }
}
