//! Compile the actual no_std two-PT PTE and ELF layout modules on the host.
#[path = "../kernel/src/elf64_preflight.rs"]
mod elf64_preflight;
#[path = "../kernel/src/elf64_page_image.rs"]
mod elf64_page_image;
#[path = "../kernel/src/user_vm_layout.rs"]
mod user_vm_layout;
#[path = "../kernel/src/user_vm_multi.rs"]
mod user_vm_multi;
#[path = "../kernel/src/user_elf_launch_layout.rs"]
mod user_elf_launch_layout;
#[path = "../kernel/src/user_vm_two_pt.rs"]
mod user_vm_two_pt;

use user_vm_multi::UserPage;
use user_vm_layout::{ENTRY_COUNT, NX, PRESENT, USER, WRITABLE};
use user_vm_two_pt::{TwoPtError, TwoPtElfError, TABLE_FRAMES};

const FRAMES: [u64; TABLE_FRAMES] =
    [0x10_000, 0x11_000, 0x12_000, 0x13_000, 0x14_000];
const PAGES: [UserPage; 3] = [
    UserPage { virtual_address: 0x5ff000, physical_frame: 0x15_000,
        writable: false, executable: true },
    UserPage { virtual_address: 0x600000, physical_frame: 0x16_000,
        writable: true, executable: false },
    UserPage { virtual_address: 0x601000, physical_frame: 0x17_000,
        writable: true, executable: false },
];
type Bank = [[u64; ENTRY_COUNT]; TABLE_FRAMES];
fn bank() -> Bank { [[0; ENTRY_COUNT]; TABLE_FRAMES] }

fn populate(bank: &mut Bank, pages: &[UserPage])
    -> Result<(), TwoPtError>
{
    let [root, pdpt, pd, pt0, pt1] = bank;
    user_vm_two_pt::populate(root, pdpt, pd, pt0, pt1, FRAMES, pages)
}
fn audit(bank: &Bank, pages: &[UserPage]) -> Result<(), TwoPtError> {
    let [root, pdpt, pd, pt0, pt1] = bank;
    user_vm_two_pt::audit(root, pdpt, pd, pt0, pt1, FRAMES, pages)
}

fn image() -> [u8; 512] {
    let mut b = [0u8; 512];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4..7].copy_from_slice(&[2, 1, 1]);
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&62u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&0x5ff100u64.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&2u16.to_le_bytes());
    // RX segment ends at the next 2-MiB table boundary.
    b[64..68].copy_from_slice(&1u32.to_le_bytes());
    b[68..72].copy_from_slice(&5u32.to_le_bytes());
    b[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    b[80..88].copy_from_slice(&0x5ff100u64.to_le_bytes());
    b[96..104].copy_from_slice(&8u64.to_le_bytes());
    b[104..112].copy_from_slice(&0xf00u64.to_le_bytes());
    b[112..120].copy_from_slice(&4096u64.to_le_bytes());
    // RW data + BSS starts in the SECOND 2-MiB table.
    b[120..124].copy_from_slice(&1u32.to_le_bytes());
    b[124..128].copy_from_slice(&6u32.to_le_bytes());
    b[128..136].copy_from_slice(&0x180u64.to_le_bytes());
    b[136..144].copy_from_slice(&0x600180u64.to_le_bytes());
    b[152..160].copy_from_slice(&1u64.to_le_bytes());
    b[160..168].copy_from_slice(&0xe80u64.to_le_bytes());
    b[168..176].copy_from_slice(&4096u64.to_le_bytes());
    b[0x100] = 0xc3;
    b[0x180] = 0x5a;
    b
}

#[test]
fn two_distinct_pds_route_pages_to_independently_owned_pt_frames() {
    let mut t = bank();
    populate(&mut t, &PAGES).unwrap();
    assert_eq!(audit(&t, &PAGES), Ok(()));
    assert_eq!(t[0][0], FRAMES[1] | PRESENT | USER | WRITABLE);
    assert_eq!(t[1][0], FRAMES[2] | PRESENT | USER | WRITABLE);
    assert_eq!(t[2][2], FRAMES[3] | PRESENT | USER | WRITABLE);
    assert_eq!(t[2][3], FRAMES[4] | PRESENT | USER | WRITABLE);
    assert_eq!(t[3][511], PAGES[0].physical_frame | PRESENT | USER);
    assert_eq!(t[4][0], PAGES[1].physical_frame | PRESENT | USER | WRITABLE | NX);
    assert_eq!(t[4][1], PAGES[2].physical_frame | PRESENT | USER | WRITABLE | NX);
    assert!(t[0][256..].iter().all(|entry| *entry == 0));
    assert_eq!(t[3].iter().filter(|p| **p != 0).count(), 1);
    assert_eq!(t[4].iter().filter(|p| **p != 0).count(), 2);
}

#[test]
fn exact_elf_byte_derived_mapping_includes_separate_stack() {
    let bytes = image();
    assert_eq!(user_elf_launch_layout::plan_static_image(&bytes),
        Err(user_elf_launch_layout::LaunchError::CrossesPageTable));
    let layout = user_vm_two_pt::validate_elf_bindings(&bytes, FRAMES, &PAGES).unwrap();
    assert_eq!(layout.len, 3);
    assert_eq!(layout.stack_page, 0x601000);
    assert_eq!(layout.leaves[0].unwrap().source_segment, Some(0));
    assert_eq!(layout.leaves[1].unwrap().source_segment, Some(1));
    assert_eq!(layout.leaves[2].unwrap().source_segment, None);
    let mut t = bank();
    populate(&mut t, &PAGES).unwrap();
    let [root, pdpt, pd, pt0, pt1] = &t;
    assert_eq!(user_vm_two_pt::audit_elf_bindings(
        &bytes, root, pdpt, pd, pt0, pt1, FRAMES, &PAGES,
    ), Ok(layout));
    let mut wrong = PAGES;
    wrong[2].executable = true; // stack executable forbidden by the ELF contract
    assert_eq!(user_vm_two_pt::validate_elf_bindings(
        &bytes, FRAMES, &wrong,
    ), Err(TwoPtElfError::PermissionMismatch));
    assert_eq!(user_vm_two_pt::validate_elf_bindings(
        &bytes, FRAMES, &PAGES[..2],
    ), Err(TwoPtElfError::MissingOrExtraPage));
    wrong = PAGES;
    wrong[1].virtual_address = 0x602000;
    assert_eq!(user_vm_two_pt::validate_elf_bindings(
        &bytes, FRAMES, &wrong,
    ), Err(TwoPtElfError::MissingOrExtraPage));
}

#[test]
fn prevalidation_rejects_invalid_layout_without_any_partial_write() {
    let initial = bank();
    let cases = [
        {
            let mut p = PAGES;
            p[2].physical_frame = p[1].physical_frame;
            p
        },
        {
            let mut p = PAGES;
            p[2].virtual_address = p[1].virtual_address;
            p
        },
        {
            let mut p = PAGES;
            p[0].writable = true;
            p
        },
        {
            let mut p = PAGES;
            p[2].virtual_address = 0x801000;
            p // third distinct PT region
        },
        {
            let mut p = PAGES;
            p[2].virtual_address = 0x4000_1000;
            p // different 1-GiB directory
        },
        {
            let mut p = PAGES;
            p[2].physical_frame = FRAMES[4]; // alias reserved PT frame
            p
        },
    ];
    for case in cases {
        let mut t = initial;
        assert!(populate(&mut t, &case).is_err());
        assert_eq!(t, initial);
    }
    let mut t = bank();
    let mut reused_frames = FRAMES;
    reused_frames[4] = FRAMES[3];
    let [r, a, d, x, y] = &mut t;
    assert_eq!(user_vm_two_pt::populate(r, a, d, x, y,
        reused_frames, &PAGES), Err(TwoPtError::AliasedPhysicalFrame));
    assert_eq!(t, initial);
}

#[test]
fn any_hidden_alias_permission_escalation_or_swapped_frame_fails_audit() {
    let mut t = bank();
    populate(&mut t, &PAGES).unwrap();
    let initial = t;
    t[0][510] = 0x2000 | PRESENT | USER;
    assert_eq!(audit(&t, &PAGES), Err(TwoPtError::MismatchedLayout));
    t = initial;
    t[3][511] |= WRITABLE; // RX -> RWX
    assert_eq!(audit(&t, &PAGES), Err(TwoPtError::MismatchedLayout));
    t = initial;
    t[4][0] &= !NX; // writable data becomes executable
    assert_eq!(audit(&t, &PAGES), Err(TwoPtError::MismatchedLayout));
    t = initial;
    t[2][3] = FRAMES[3] | PRESENT | USER | WRITABLE;
    assert_eq!(audit(&t, &PAGES), Err(TwoPtError::MismatchedLayout));
    t = initial;
    t[4][255] = PAGES[1].physical_frame | PRESENT | USER;
    assert_eq!(audit(&t, &PAGES), Err(TwoPtError::MismatchedLayout));
    t = initial;
    t[3][511] ^= 0x1000; // physical frame swap
    assert_eq!(audit(&t, &PAGES), Err(TwoPtError::MismatchedLayout));
    assert_eq!(audit(&initial, &PAGES), Ok(()));
}

#[test]
fn dirty_destination_must_not_be_overwritten() {
    let mut t = bank();
    t[4][22] = 0xaabb;
    let initial = t;
    assert_eq!(populate(&mut t, &PAGES), Err(TwoPtError::DirtyDestination));
    assert_eq!(t, initial);
}

#[test]
fn unused_second_pt_remains_zero_in_one_region_while_all_frames_stay_unique() {
    let pages = [
        UserPage { virtual_address: 0x401000, physical_frame: 0x15_000,
            writable: false, executable: true },
        UserPage { virtual_address: 0x402000, physical_frame: 0x16_000,
            writable: true, executable: false },
    ];
    let mut t = bank();
    populate(&mut t, &pages).unwrap();
    assert_eq!(audit(&t, &pages), Ok(()));
    assert!(t[4].iter().all(|p| *p == 0));
    assert_eq!(t[2][2], FRAMES[3] | PRESENT | USER | WRITABLE);
    assert_eq!(t[2].iter().filter(|p| **p != 0).count(), 1);
}
