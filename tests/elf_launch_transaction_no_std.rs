//! Cross-compile the public preparation contract without std or kernel hardware.
#![no_std]

#[path = "../kernel/src/active_address_space.rs"]
pub mod active_address_space;
#[path = "../kernel/src/address_space_retirement.rs"]
pub mod address_space_retirement;
#[path = "../kernel/src/elf64_page_image.rs"]
pub mod elf64_page_image;
#[path = "../kernel/src/elf64_preflight.rs"]
pub mod elf64_preflight;
#[path = "../kernel/src/elf_launch_transaction.rs"]
pub mod elf_launch_transaction;
#[path = "../kernel/src/pmm_frame_batch.rs"]
pub mod pmm_frame_batch;
#[path = "../kernel/src/saved_context_retirement.rs"]
pub mod saved_context_retirement;
#[path = "../kernel/src/user_elf_launch_layout.rs"]
pub mod user_elf_launch_layout;
#[path = "../kernel/src/user_elf_page_tables.rs"]
pub mod user_elf_page_tables;
