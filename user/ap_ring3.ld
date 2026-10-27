/* Independent fixed-location x86-64 ET_EXEC: RX .text at 0x401000,
 * RW/NX .data at 0x402000. 0x403000 reserved for the AP user stack.
 * No dynamic loader, relocations at runtime or shared PML4 mappings.
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
    . = 0x402000;
    .data : { *(.data*) } :data
    .bss (NOLOAD) : { *(.bss*) } :data
    /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) }
}
