//! Host negative ELF64 acceptance tests against the INDEPENDENT output
//! assembled from user/hello.S and user/hello.ld. No fake ELF header; runs
//! the actual existing kernel's strict preflight and page materializer.
#[path = "../kernel/src/elf64_preflight.rs"]
mod elf64_preflight;
#[path = "../kernel/src/elf64_page_image.rs"]
mod elf64_page_image;

fn artifact() -> Vec<u8> {
    std::fs::read("out/wolfos-user-hello.elf")
        .expect("Makefile must independently assemble/link user/hello.S")
}
fn valid_plan() -> (Vec<u8>, elf64_preflight::ImagePlan) {
    let file = artifact();
    let plan = elf64_preflight::preflight(&file).expect("real GNU ld image must validate");
    (file, plan)
}
fn write32(file: &mut [u8], at: usize, v: u32) {
    file[at..at+4].copy_from_slice(&v.to_le_bytes());
}

#[test]
fn real_linked_elf_has_exact_two_load_segments_and_user_entry() {
    let (_file, plan) = valid_plan();
    assert_eq!(plan.len, 2);
    assert_eq!(plan.entry, 0x401000);
    let code = plan.segments[0].unwrap();
    let data = plan.segments[1].unwrap();
    assert_eq!((code.page_start, code.page_end), (0x401000, 0x402000));
    assert_eq!((code.writable, code.executable), (false, true));
    assert!(code.file_size > 100 && code.file_size < 4096);
    assert_eq!(code.file_size, code.memory_size);
    assert_eq!((data.page_start, data.page_end), (0x403000, 0x404000));
    assert_eq!((data.writable, data.executable), (true, false));
    assert_eq!((data.file_size, data.memory_size), (1, 65));
}

#[test]
fn materialized_real_file_has_user_hello_text_valid_data_and_zero_bss() {
    let (file, plan) = valid_plan();
    let mut text = [0x55u8; 4096];
    let mut data = [0x55u8; 4096];
    let image = elf64_page_image::materialize(
        &file, &plan.segments[0].unwrap(), 0x401000, &mut text
    ).unwrap();
    let data_image = elf64_page_image::materialize(
        &file, &plan.segments[1].unwrap(), 0x403000, &mut data
    ).unwrap();
    assert_eq!(image.copied, plan.segments[0].unwrap().file_size as usize);
    assert_eq!(data_image.copied, 1);
    assert_eq!(text[0..2], [0xb8, 0x01]);
    assert!(text.windows(b"Hello from WolfOS!\n".len())
        .any(|w| w == b"Hello from WolfOS!\n"));
    assert_eq!(data[0], 0x5a);
    assert!(data[1..].iter().all(|b| *b == 0));
    assert!(text[image.copied..].iter().all(|b| *b == 0));
}

#[test]
fn corrupted_real_executable_identity_and_permissions_are_rejected() {
    let (file, _) = valid_plan();
    let mut bad = file.clone();
    bad[0] = 0;
    assert_eq!(elf64_preflight::preflight(&bad),
        Err(elf64_preflight::ElfError::Magic));
    let mut bad = file.clone();
    write32(&mut bad, 64+4, 7); // PT_LOAD text becomes RWX
    assert_eq!(elf64_preflight::preflight(&bad),
        Err(elf64_preflight::ElfError::InvalidPermissions));
    let mut bad = file.clone();
    write32(&mut bad, 64+56+4, 5); // data accidentally becomes RX
    // Generic preflight allows RX; runtime's expected data layout will
    // additionally reject this. It must not be silently called RW/NX.
    let plan = elf64_preflight::preflight(&bad).unwrap();
    assert!(!plan.segments[1].unwrap().writable);
    let mut bad = file.clone();
    bad.truncate(64+56);
    assert_eq!(elf64_preflight::preflight(&bad),
        Err(elf64_preflight::ElfError::ProgramTable));
}

#[test]
fn forged_file_extent_would_not_modify_owned_page_on_failure() {
    let (mut file, plan) = valid_plan();
    let mut page = [0xa5u8; 4096];
    let mut forged = plan.segments[0].unwrap();
    forged.file_offset = u64::MAX;
    assert_eq!(elf64_page_image::materialize(&file, &forged, 0x401000, &mut page),
        Err(elf64_page_image::MaterializeError::InvalidFile));
    assert!(page.iter().all(|x| *x == 0xa5));
    file[4] = 1;
    assert_eq!(elf64_preflight::preflight(&file),
        Err(elf64_preflight::ElfError::UnsupportedIdentity));
}
