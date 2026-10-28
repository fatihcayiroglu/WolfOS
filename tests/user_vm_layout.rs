//! Compile the EXACT WolfOS no_std preflight and 4-level page table
//! layout under the host Rust test harness. Neither module executes images.
#[path = "../kernel/src/elf64_preflight.rs"]
mod elf64_preflight;
#[path = "../kernel/src/elf64_page_image.rs"]
mod elf64_page_image;
#[path = "../kernel/src/user_vm_layout.rs"]
mod user_vm_layout;
#[path = "../kernel/src/user_vm_multi.rs"]
mod user_vm_multi;

#[test]
fn p2_page_geometry_and_address_policy_agree() {
    assert_eq!(elf64_preflight::PAGE_BYTES, 4096);
    assert_eq!(elf64_preflight::USER_MIN, 0x1_0000);
    assert_eq!(elf64_preflight::USER_END, 0x0000_8000_0000_0000);
    assert_eq!(user_vm_layout::ENTRY_COUNT, 512);
    assert_eq!(user_vm_layout::FRAME_COUNT, 5);
    assert!(user_vm_layout::indices(0x401000).is_ok());
    assert!(user_vm_layout::indices(elf64_preflight::USER_END).is_err());
}

#[test]
fn user_multi_shares_same_elf_lower_half_policy() {
    assert_eq!(user_vm_multi::MAX_PAGES, 4);
    assert_eq!(user_vm_multi::TABLE_FRAMES, 4);
    assert!(user_vm_layout::indices(0x404000).is_ok());
}
