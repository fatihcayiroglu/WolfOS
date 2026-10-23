//! Exercise the exact no_std shadow-image admission path under host Rust.
#[path = "../kernel/src/elf64_preflight.rs"]
mod elf64_preflight;
#[path = "../kernel/src/elf64_page_image.rs"]
mod elf64_page_image;
#[path = "../kernel/src/user_vm_layout.rs"]
mod user_vm_layout;
#[path = "../kernel/src/user_vm_multi.rs"]
mod user_vm_multi;
#[path = "../kernel/src/user_image_admission.rs"]
mod user_image_admission;

use elf64_page_image::{materialize, PageAuditError, PAGE_SIZE};
use user_image_admission::{audit_staged_image, AdmissionError, BackingPage};
use user_vm_multi::{MultiError, UserPage, ElfBindingError};
use user_vm_layout::{ENTRY_COUNT, PRESENT};

const TABLES: [u64; 4] = [0x10_000, 0x11_000, 0x12_000, 0x13_000];
const PAGES: [UserPage; 2] = [
    UserPage { virtual_address: 0x401000, physical_frame: 0x14_000,
        writable: false, executable: true },
    UserPage { virtual_address: 0x402000, physical_frame: 0x15_000,
        writable: true, executable: false },
];

fn elf() -> [u8; 512] {
    let mut b = [0u8; 512];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4..7].copy_from_slice(&[2, 1, 1]);
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&62u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&0x401100u64.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&1u16.to_le_bytes());
    b[64..68].copy_from_slice(&1u32.to_le_bytes()); // LOAD
    b[68..72].copy_from_slice(&5u32.to_le_bytes()); // RX
    b[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    b[80..88].copy_from_slice(&0x401100u64.to_le_bytes());
    b[96..104].copy_from_slice(&8u64.to_le_bytes());
    b[104..112].copy_from_slice(&0x500u64.to_le_bytes());
    b[112..120].copy_from_slice(&4096u64.to_le_bytes());
    b[0x100..0x108].copy_from_slice(&[0x90, 1, 2, 3, 4, 5, 6, 0xc3]);
    b
}

#[test]
fn staged_admission_binds_pte_frames_file_bytes_and_stack_together() {
    let bytes = elf();
    let segment = elf64_preflight::preflight(&bytes).unwrap().segments[0].unwrap();
    let mut code = [0xa5u8; PAGE_SIZE];
    let mut stack = [0u8; PAGE_SIZE];
    materialize(&bytes, &segment, 0x401000, &mut code).unwrap();
    let mut bank = [[0u64; ENTRY_COUNT]; 4];
    let [root, pdpt, pd, pt] = &mut bank;
    user_vm_multi::populate(root, pdpt, pd, pt, TABLES, &PAGES).unwrap();
    let expected = elf64_preflight::preflight(&bytes).unwrap();

    let audit = |source: &[u8], code: &[u8; PAGE_SIZE], stack: &[u8; PAGE_SIZE],
                 mapping: &[UserPage], code_phys: u64| {
        let [root, pdpt, pd, pt] = &bank;
        audit_staged_image(
            source, 0x402000, TABLES, mapping, root, pdpt, pd, pt,
            &[BackingPage { virtual_address: 0x401000,
                physical_frame: code_phys, bytes: code }],
            BackingPage { virtual_address: 0x402000,
                physical_frame: PAGES[1].physical_frame, bytes: stack },
        )
    };

    assert_eq!(audit(&bytes, &code, &stack, &PAGES, PAGES[0].physical_frame), Ok(expected));

    // Content integrity: a byte flipped AFTER a successful page copy is fatal.
    code[0x100] ^= 1;
    assert_eq!(audit(&bytes, &code, &stack, &PAGES, PAGES[0].physical_frame),
        Err(AdmissionError::FileBytes(PageAuditError::ContentMismatch {
            index: 0, offset: 0x100,
        })));
    code[0x100] ^= 1;
    // A modified source ELF must fail too, even if old PMM bytes remain.
    let mut changed = bytes;
    changed[0x100] ^= 1;
    assert_eq!(audit(&changed, &code, &stack, &PAGES, PAGES[0].physical_frame),
        Err(AdmissionError::FileBytes(PageAuditError::ContentMismatch {
            index: 0, offset: 0x100,
        })));
    stack[13] = 1;
    assert_eq!(audit(&bytes, &code, &stack, &PAGES, PAGES[0].physical_frame),
        Err(AdmissionError::StackBytes(13)));
    stack[13] = 0;
    assert_eq!(audit(&bytes, &code, &stack, &PAGES, PAGES[0].physical_frame), Ok(expected));

    // Metadata alone cannot substitute a different physical backing frame.
    assert_eq!(audit(&bytes, &code, &stack, &PAGES, PAGES[1].physical_frame),
        Err(AdmissionError::BackingMismatch));
    assert_eq!(audit(&bytes, &code, &stack, &PAGES[..1], PAGES[0].physical_frame),
        Err(AdmissionError::Mapping(ElfBindingError::MissingOrExtraPage)));

    let [root, pdpt, pd, pt] = &bank;
    assert_eq!(audit_staged_image(
        &bytes, 0x402000, TABLES, &PAGES, root, pdpt, pd, pt, &[],
        BackingPage { virtual_address: 0x402000,
            physical_frame: PAGES[1].physical_frame, bytes: &stack },
    ), Err(AdmissionError::BackingCount));
    assert_eq!(audit_staged_image(
        &bytes, 0x402000, TABLES, &PAGES, root, pdpt, pd, pt,
        &[BackingPage { virtual_address: 0x401000,
            physical_frame: PAGES[0].physical_frame, bytes: &stack }],
        BackingPage { virtual_address: 0x402000,
            physical_frame: PAGES[1].physical_frame, bytes: &stack },
    ), Err(AdmissionError::BackingMismatch));
    // Read-only checks never alter either page-table state or file buffers.
    assert_eq!(bank[0][0] & PRESENT, PRESENT);
    assert_eq!(audit(&bytes, &code, &stack, &PAGES, PAGES[0].physical_frame), Ok(expected));
}

#[test]
fn changed_real_pte_is_rejected_even_when_all_backing_bytes_are_valid() {
    let bytes = elf();
    let segment = elf64_preflight::preflight(&bytes).unwrap().segments[0].unwrap();
    let mut code = [0u8; PAGE_SIZE];
    let stack = [0u8; PAGE_SIZE];
    materialize(&bytes, &segment, 0x401000, &mut code).unwrap();
    let mut bank = [[0u64; ENTRY_COUNT]; 4];
    let [root, pdpt, pd, pt] = &mut bank;
    user_vm_multi::populate(root, pdpt, pd, pt, TABLES, &PAGES).unwrap();
    bank[3][1] |= user_vm_layout::WRITABLE; // impossible RWX upgrade
    let [root, pdpt, pd, pt] = &bank;
    assert_eq!(audit_staged_image(
        &bytes, 0x402000, TABLES, &PAGES, root, pdpt, pd, pt,
        &[BackingPage { virtual_address: 0x401000,
            physical_frame: PAGES[0].physical_frame, bytes: &code }],
        BackingPage { virtual_address: 0x402000,
            physical_frame: PAGES[1].physical_frame, bytes: &stack },
    ), Err(AdmissionError::Mapping(
        ElfBindingError::PhysicalOrRoot(MultiError::MismatchedLayout))));
}
