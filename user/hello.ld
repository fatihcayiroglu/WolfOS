/* Deliberately tiny, static ELF64 ET_EXEC: exactly two PT_LOAD ranges.
 * Text: read+execute; data+BSS: read+write, never executable.
 * No PT_INTERP, PT_DYNAMIC or runtime linker. Entry is 0x401000.
 * ELF p_vaddr=p_offset (mod 4096); the loader validates every field.
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
    . = 0x403000;
    .data : { *(.data*) } :data
    .bss (NOLOAD) : { *(.bss*) } :data
    /DISCARD/ : { *(.note*) *(.comment*) *(.eh_frame*) }
}
