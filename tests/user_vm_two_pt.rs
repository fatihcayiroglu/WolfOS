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
#[path = "../kernel/src/user_elf_two_pt_stager.rs"]
mod user_elf_two_pt_stager;
#[path = "../kernel/src/user_image_admission.rs"]
mod user_image_admission;

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

fn admitted_two_pt(
    bytes: &[u8], t: &Bank, mapped: &[UserPage],
    code: &[u8; elf64_page_image::PAGE_SIZE],
    data: &[u8; elf64_page_image::PAGE_SIZE],
    stack: &[u8; elf64_page_image::PAGE_SIZE],
) -> Result<user_elf_launch_layout::StaticLaunchLayout,
            user_image_admission::TwoPtAdmissionError> {
    let [root, pdpt, pd, pt0, pt1] = t;
    let files = [
        user_image_admission::BackingPage {
            virtual_address: 0x5ff000,
            physical_frame: PAGES[0].physical_frame, bytes: code,
        },
        user_image_admission::BackingPage {
            virtual_address: 0x600000,
            physical_frame: PAGES[1].physical_frame, bytes: data,
        },
    ];
    user_image_admission::audit_two_pt_staged_image(
        bytes, FRAMES, mapped, root, pdpt, pd, pt0, pt1, &files,
        user_image_admission::BackingPage {
            virtual_address: 0x601000,
            physical_frame: PAGES[2].physical_frame, bytes: stack,
        },
    )
}

#[test]
fn two_pt_admission_binds_exact_elf_bytes_all_ptes_and_private_stack() {
    use user_image_admission::{BackingPage, TwoPtAdmissionError as E};
    use elf64_page_image::{materialize, PageAuditError, PAGE_SIZE};

    let bytes = image();
    let expected = user_elf_launch_layout::plan_two_pt_image(&bytes).unwrap();
    let text = expected.image.segments[0].unwrap();
    let writable = expected.image.segments[1].unwrap();
    let mut rx = [0xa5u8; PAGE_SIZE];
    let mut rw = [0xa5u8; PAGE_SIZE];
    let mut stack = [0u8; PAGE_SIZE];
    materialize(&bytes, &text, 0x5ff000, &mut rx).unwrap();
    materialize(&bytes, &writable, 0x600000, &mut rw).unwrap();
    let mut t = bank();
    populate(&mut t, &PAGES).unwrap();

    assert_eq!(admitted_two_pt(&bytes, &t, &PAGES, &rx, &rw, &stack),
        Ok(expected));

    rw[0x180] ^= 1;
    assert_eq!(admitted_two_pt(&bytes, &t, &PAGES, &rx, &rw, &stack),
        Err(E::FileBytes(PageAuditError::ContentMismatch {
            index: 0, offset: 0x180,
        })));
    rw[0x180] ^= 1;
    rx[0x100] ^= 1;
    assert_eq!(admitted_two_pt(&bytes, &t, &PAGES, &rx, &rw, &stack),
        Err(E::FileBytes(PageAuditError::ContentMismatch {
            index: 0, offset: 0x100,
        })));
    rx[0x100] ^= 1;
    stack[17] = 1;
    assert_eq!(admitted_two_pt(&bytes, &t, &PAGES, &rx, &rw, &stack),
        Err(E::StackBytes(17)));
    stack[17] = 0;

    let mut changed = bytes;
    changed[0x180] ^= 1; // Source bytes changed after staging.
    assert_eq!(admitted_two_pt(&changed, &t, &PAGES, &rx, &rw, &stack),
        Err(E::FileBytes(PageAuditError::ContentMismatch {
            index: 0, offset: 0x180,
        })));

    // A forged PTE mapping cannot be admitted merely because both buffers
    // still contain the proper immutable ELF bytes.
    t[4][0] &= !NX;
    assert_eq!(admitted_two_pt(&bytes, &t, &PAGES, &rx, &rw, &stack),
        Err(E::Mapping(TwoPtElfError::Mapping(TwoPtError::MismatchedLayout))));
    t[4][0] |= NX;
    assert_eq!(admitted_two_pt(&bytes, &t, &PAGES, &rx, &rw, &stack),
        Ok(expected));

    let [root, pdpt, pd, pt0, pt1] = &t;
    let b0 = BackingPage { virtual_address: 0x5ff000,
        physical_frame: PAGES[0].physical_frame, bytes: &rx };
    let b1 = BackingPage { virtual_address: 0x600000,
        physical_frame: PAGES[1].physical_frame, bytes: &rw };
    let stack_backing = BackingPage { virtual_address: 0x601000,
        physical_frame: PAGES[2].physical_frame, bytes: &stack };
    let verify = |files: &[BackingPage<'_>], st: BackingPage<'_>| {
        user_image_admission::audit_two_pt_staged_image(
            &bytes, FRAMES, &PAGES, root, pdpt, pd, pt0, pt1, files, st,
        )
    };
    assert_eq!(verify(&[b0], stack_backing), Err(E::BackingCount));
    assert_eq!(verify(&[b0, b0], stack_backing), Err(E::BackingMismatch));
    assert_eq!(verify(&[b1, b0], stack_backing), Ok(expected));
    assert_eq!(verify(&[
        BackingPage { physical_frame: PAGES[1].physical_frame, ..b0 }, b1
    ], stack_backing), Err(E::BackingMismatch));
    assert_eq!(verify(&[b0, b1],
        BackingPage { bytes: &rx, ..stack_backing }),
        Err(E::BackingMismatch));
    assert_eq!(admitted_two_pt(&bytes, &t, &PAGES[..2], &rx, &rw, &stack),
        Err(E::Mapping(TwoPtElfError::MissingOrExtraPage)));
}

fn relocated_pages(slot: usize) -> [UserPage; 3] {
    let base = (slot as u64) << 39;
    let mut pages = PAGES;
    for page in &mut pages {
        page.virtual_address += base;
    }
    pages
}

#[test]
fn relocated_elf_requires_one_nonzero_vacant_user_pml4_slot_and_exact_flags() {
    for slot in [1usize, 17, 255] {
        let pages = relocated_pages(slot);
        let expected = user_vm_two_pt::validate_relocated_elf_bindings(
            &image(), slot, FRAMES, &pages,
        ).unwrap();
        assert_eq!(expected.source,
            user_elf_launch_layout::plan_two_pt_image(&image()).unwrap());
        assert_eq!(expected.user_pml4_slot, slot);
        assert_eq!(expected.entry, ((slot as u64) << 39) + 0x5ff100);
        assert_eq!(expected.stack_page, ((slot as u64) << 39) + 0x601000);
        let mut t = bank();
        populate(&mut t, &pages).unwrap();
        assert_eq!(t[0][slot], FRAMES[1] | PRESENT | USER | WRITABLE);
        assert_eq!(t[0][0], 0); // do not shadow the boot low slot
        let [root, pdpt, pd, pt0, pt1] = &t;
        assert_eq!(user_vm_two_pt::audit_relocated_elf_bindings(
            &image(), slot, root, pdpt, pd, pt0, pt1, FRAMES, &pages,
        ), Ok(expected));
        let mut wrong = pages;
        wrong[1].executable = true;
        assert_eq!(user_vm_two_pt::validate_relocated_elf_bindings(
            &image(), slot, FRAMES, &wrong,
        ), Err(TwoPtElfError::PermissionMismatch));
        wrong = pages;
        wrong[0].virtual_address += 1u64 << 39;
        assert_eq!(user_vm_two_pt::validate_relocated_elf_bindings(
            &image(), slot, FRAMES, &wrong,
        ), Err(TwoPtElfError::MissingOrExtraPage));
        t[0][slot] ^= USER; // actual permission downgrade detected
        let [root, pdpt, pd, pt0, pt1] = &t;
        assert_eq!(user_vm_two_pt::audit_relocated_elf_bindings(
            &image(), slot, root, pdpt, pd, pt0, pt1, FRAMES, &pages,
        ), Err(TwoPtElfError::Mapping(TwoPtError::MismatchedLayout)));
    }
    assert_eq!(user_vm_two_pt::validate_relocated_elf_bindings(
        &image(), 0, FRAMES, &PAGES,
    ), Err(TwoPtElfError::InvalidUserSlot));
    assert_eq!(user_vm_two_pt::validate_relocated_elf_bindings(
        &image(), 256, FRAMES, &PAGES,
    ), Err(TwoPtElfError::InvalidUserSlot));
}

#[test]
fn relocated_two_pt_admission_keeps_file_offsets_unrelocated() {
    use elf64_page_image::{materialize, PageAuditError, PAGE_SIZE};
    use user_image_admission::{
        BackingPage, TwoPtAdmissionError as E,
    };
    let bytes = image();
    let plan = user_elf_launch_layout::plan_two_pt_image(&bytes).unwrap();
    let mut code = [0xa5; PAGE_SIZE];
    let mut data = [0xa5; PAGE_SIZE];
    let mut stack = [0u8; PAGE_SIZE];
    materialize(&bytes, &plan.image.segments[0].unwrap(),
        0x5ff000, &mut code).unwrap();
    materialize(&bytes, &plan.image.segments[1].unwrap(),
        0x600000, &mut data).unwrap();
    let slot = 7;
    let pages = relocated_pages(slot);
    let base = (slot as u64) << 39;
    let mut t = bank();
    populate(&mut t, &pages).unwrap();
    let verify = |bank: &Bank, code: &[u8; PAGE_SIZE],
                  data: &[u8; PAGE_SIZE], stack: &[u8; PAGE_SIZE]| {
        let [root, pdpt, pd, pt0, pt1] = bank;
        user_image_admission::audit_relocated_two_pt_staged_image(
            &bytes, slot, FRAMES, &pages, root, pdpt, pd, pt0, pt1,
            &[
                BackingPage { virtual_address: base + 0x5ff000,
                    physical_frame: pages[0].physical_frame, bytes: code },
                BackingPage { virtual_address: base + 0x600000,
                    physical_frame: pages[1].physical_frame, bytes: data },
            ],
            BackingPage { virtual_address: base + 0x601000,
                physical_frame: pages[2].physical_frame, bytes: stack },
        )
    };
    let expected = user_vm_two_pt::validate_relocated_elf_bindings(
        &bytes, slot, FRAMES, &pages,
    ).unwrap();
    assert_eq!(verify(&t, &code, &data, &stack), Ok(expected));
    data[0x180] ^= 1;
    assert_eq!(verify(&t, &code, &data, &stack),
        Err(E::FileBytes(PageAuditError::ContentMismatch {
            index: 0, offset: 0x180,
        })));
    data[0x180] ^= 1;
    stack[31] = 1;
    assert_eq!(verify(&t, &code, &data, &stack), Err(E::StackBytes(31)));
    stack[31] = 0;
    t[4][0] &= !NX;
    assert_eq!(verify(&t, &code, &data, &stack),
        Err(E::Mapping(TwoPtElfError::Mapping(TwoPtError::MismatchedLayout))));
    t[4][0] |= NX;
    assert_eq!(verify(&t, &code, &data, &stack), Ok(expected));
}

#[test]
fn derived_relocated_page_manifest_uses_only_elf_leaves_and_owned_frames() {
    let bytes = image();
    for slot in [1usize, 17, 255] {
        let manifest = user_vm_two_pt::derive_relocated_elf_pages(
            &bytes, slot, FRAMES, &[0x15_000, 0x16_000, 0x17_000],
        ).unwrap();
        assert_eq!(manifest.pages(), &relocated_pages(slot));
        assert_eq!(manifest.load_pages(), 2);
        assert_eq!(manifest.layout.entry, ((slot as u64) << 39) + 0x5ff100);
        assert_eq!(manifest.layout.stack_page, ((slot as u64) << 39) + 0x601000);
        let mut t = bank();
        populate(&mut t, manifest.pages()).unwrap();
        let [root, pdpt, pd, pt0, pt1] = &t;
        assert_eq!(
            user_vm_two_pt::audit_relocated_elf_bindings(
                &bytes, slot, root, pdpt, pd, pt0, pt1, FRAMES, manifest.pages(),
            ),
            Ok(manifest.layout),
        );
    }
}

#[test]
fn derived_manifest_supports_three_load_pages_across_two_page_tables() {
    let mut bytes = image();
    bytes[24..32].copy_from_slice(&0x5fe100u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&0x5fe100u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x1100u64.to_le_bytes());
    let immutable = bytes;
    let frames = [0x15_000, 0x16_000, 0x17_000, 0x18_000];
    let manifest = user_vm_two_pt::derive_relocated_elf_pages(
        &bytes, 7, FRAMES, &frames,
    ).unwrap();
    assert_eq!(manifest.load_pages(), 3);
    assert_eq!(manifest.layout.source.len, 4);
    assert_eq!(manifest.layout.entry, (7u64 << 39) + 0x5fe100);
    assert_eq!(manifest.layout.stack_page, (7u64 << 39) + 0x601000);
    assert_eq!(
        manifest.pages().iter().map(|p| p.virtual_address - (7u64 << 39))
            .collect::<Vec<u64>>(),
        [0x5fe000, 0x5ff000, 0x600000, 0x601000],
    );
    assert_eq!(manifest.pages().iter().map(|p| p.physical_frame)
        .collect::<Vec<u64>>(), frames);
    assert_eq!(
        manifest.pages().iter().map(|p| (p.writable, p.executable))
            .collect::<Vec<_>>(),
        [(false, true), (false, true), (true, false), (true, false)],
    );
    let mut t = bank();
    populate(&mut t, manifest.pages()).unwrap();
    let [root, pdpt, pd, pt0, pt1] = &t;
    assert_eq!(pt0.iter().filter(|pte| **pte != 0).count(), 2);
    assert_eq!(pt1.iter().filter(|pte| **pte != 0).count(), 2);
    assert_eq!(
        user_vm_two_pt::audit_relocated_elf_bindings(
            &bytes, 7, root, pdpt, pd, pt0, pt1, FRAMES, manifest.pages(),
        ),
        Ok(manifest.layout),
    );
    assert_eq!(bytes, immutable); // staging metadata never edits ELF bytes
}

#[test]
fn derived_manifest_rejects_invalid_slots_frame_counts_aliases_and_offsets() {
    let bytes = image();
    let frames = [0x15_000, 0x16_000, 0x17_000];
    let derive = |slot, data: &[u64]| {
        user_vm_two_pt::derive_relocated_elf_pages(&bytes, slot, FRAMES, data)
    };
    assert!(matches!(derive(0, &frames), Err(TwoPtElfError::InvalidUserSlot)));
    assert!(matches!(derive(256, &frames), Err(TwoPtElfError::InvalidUserSlot)));
    assert!(matches!(derive(511, &frames), Err(TwoPtElfError::InvalidUserSlot)));
    assert!(matches!(derive(1, &frames[..2]),
        Err(TwoPtElfError::MissingOrExtraPage)));
    assert!(matches!(derive(1, &[0x15_000, 0x16_000, 0x17_000, 0x18_000]),
        Err(TwoPtElfError::MissingOrExtraPage)));
    for bad in [
        [0x15_000, 0x15_000, 0x17_000],
        [FRAMES[2], 0x16_000, 0x17_000],
        [0x15_001, 0x16_000, 0x17_000],
        [0, 0x16_000, 0x17_000],
        [1 << 52, 0x16_000, 0x17_000],
    ] {
        assert!(matches!(derive(1, &bad),
            Err(TwoPtElfError::Mapping(
                TwoPtError::AliasedPhysicalFrame | TwoPtError::InvalidPhysicalFrame
            ))), "bad frames {bad:?} accepted");
    }
    let mut malformed = bytes;
    malformed[0] = 0;
    assert!(matches!(user_vm_two_pt::derive_relocated_elf_pages(
        &malformed, 1, FRAMES, &frames,
    ), Err(TwoPtElfError::Image(_))));
    let mut three_regions = bytes;
    // RX spans PD regions 2 and 3; RW data introduces a third region 4.
    three_regions[104..112].copy_from_slice(&0x1000u64.to_le_bytes());
    three_regions[136..144].copy_from_slice(&0x801180u64.to_le_bytes());
    assert!(matches!(user_vm_two_pt::derive_relocated_elf_pages(
        &three_regions, 1, FRAMES, &frames,
    ), Err(TwoPtElfError::Image(
        user_elf_launch_layout::LaunchError::TooManyPageTables
    ))));
}


#[test]
fn atomic_stager_executes_byte_derived_one_two_and_three_load_leaf_plans() {
    use user_elf_two_pt_stager::stage_relocated_two_pt_elf;
    let bytes = image();
    let mut rx = [0u8; 4096];
    let mut data = [0u8; 4096];
    let mut stack = [0u8; 4096];
    let mut dest = [&mut rx, &mut data];
    let admitted = stage_relocated_two_pt_elf(
        &bytes, 2, FRAMES, &[0x15_000, 0x16_000, 0x17_000],
        &mut dest, &mut stack,
    ).unwrap();
    assert_eq!(admitted.manifest.load_pages(), 2);
    assert_eq!(admitted.copied[0].unwrap().copied, 8);
    assert_eq!(admitted.copied[1].unwrap().copied, 1);
    assert_eq!(admitted.copied[2], None);
    assert_eq!(rx[0x100], 0xc3);
    assert_eq!(data[0x180], 0x5a);
    assert!(stack.iter().all(|b| *b == 0));
    assert_eq!(admitted.manifest.pages().len(), 3);

    let mut three = bytes;
    three[24..32].copy_from_slice(&0x5fe100u64.to_le_bytes());
    three[80..88].copy_from_slice(&0x5fe100u64.to_le_bytes());
    three[104..112].copy_from_slice(&0x1100u64.to_le_bytes());
    let mut first = [0u8; 4096];
    let mut second = [0u8; 4096];
    let mut data3 = [0u8; 4096];
    let mut stack3 = [0u8; 4096];
    let mut dest3 = [&mut first, &mut second, &mut data3];
    let staged3 = stage_relocated_two_pt_elf(
        &three, 7, FRAMES, &[0x15_000, 0x16_000, 0x17_000, 0x18_000],
        &mut dest3, &mut stack3,
    ).unwrap();
    assert_eq!(staged3.manifest.load_pages(), 3);
    assert_eq!(staged3.copied[0].unwrap().copied, 8);
    assert_eq!(staged3.copied[1].unwrap().copied, 0);
    assert_eq!(staged3.copied[2].unwrap().copied, 1);
    assert_eq!(first[0x100], 0xc3);
    assert!(second.iter().all(|b| *b == 0));
    assert_eq!(data3[0x180], 0x5a);
    assert!(stack3.iter().all(|b| *b == 0));

    let mut one = bytes;
    one[56..58].copy_from_slice(&1u16.to_le_bytes());
    let mut rx1 = [0u8; 4096];
    let mut stack1 = [0u8; 4096];
    let mut dest1 = [&mut rx1];
    let staged1 = stage_relocated_two_pt_elf(
        &one, 255, FRAMES, &[0x15_000, 0x16_000],
        &mut dest1, &mut stack1,
    ).unwrap();
    assert_eq!(staged1.manifest.load_pages(), 1);
    assert_eq!(staged1.copied[0].unwrap().copied, 8);
    assert_eq!(staged1.copied[1], None);
    assert_eq!(rx1[0x100], 0xc3);
    assert_eq!(staged1.manifest.pages().len(), 2);
}

#[test]
fn atomic_stager_rejects_dirty_stack_wrong_frame_count_and_aliases_without_writes() {
    use user_elf_two_pt_stager::{stage_relocated_two_pt_elf, StageError};
    let bytes = image();
    let mut rx = [0u8; 4096];
    let mut data = [0u8; 4096];
    let mut stack = [0u8; 4096];
    stack[99] = 0xa5;
    {
        let mut dest = [&mut rx, &mut data];
        assert_eq!(stage_relocated_two_pt_elf(
            &bytes, 1, FRAMES, &[0x15_000, 0x16_000, 0x17_000],
            &mut dest, &mut stack,
        ), Err(StageError::DirtyOwnedFrame));
    }
    assert!(rx.iter().all(|b| *b == 0));
    assert!(data.iter().all(|b| *b == 0));
    assert_eq!(stack[99], 0xa5);
    stack[99] = 0;
    {
        let mut dest = [&mut rx, &mut data];
        assert!(matches!(stage_relocated_two_pt_elf(
            &bytes, 1, FRAMES, &[0x15_000, 0x15_000, 0x17_000],
            &mut dest, &mut stack,
        ), Err(StageError::Manifest(_))));
        assert!(matches!(stage_relocated_two_pt_elf(
            &bytes, 1, FRAMES, &[0x15_000, 0x16_000],
            &mut dest, &mut stack,
        ), Err(StageError::Manifest(_))));
        assert_eq!(stage_relocated_two_pt_elf(
            &bytes, 1, FRAMES, &[0x15_000, 0x16_000, 0x17_000],
            &mut dest[..1], &mut stack,
        ), Err(StageError::BackingCount));
    }
    assert!(rx.iter().all(|b| *b == 0));
    assert!(data.iter().all(|b| *b == 0));
    assert!(stack.iter().all(|b| *b == 0));
}

#[test]
fn bounded_batch_inspects_all_file_ranges_and_duplicate_va_before_any_write() {
    use elf64_page_image::{materialize_bounded, MaterializeError};
    let bytes = image();
    let plan = elf64_preflight::preflight(&bytes).unwrap();
    let text = plan.segments[0].unwrap();
    let data = plan.segments[1].unwrap();
    let mut bad = data;
    bad.file_offset = u64::MAX;
    let mut rx = [0xa5u8; 4096];
    let mut rw = [0x5au8; 4096];
    {
        let mut dest = [&mut rx, &mut rw];
        assert_eq!(materialize_bounded::<3>(
            &bytes, &[(&text, 0x5ff000), (&bad, 0x600000)], &mut dest,
        ), Err(MaterializeError::InvalidFile));
        assert_eq!(materialize_bounded::<3>(
            &bytes, &[(&text, 0x5ff000), (&data, 0x5ff000)], &mut dest,
        ), Err(MaterializeError::DuplicateVirtualPage));
        assert_eq!(materialize_bounded::<3>(
            &bytes, &[(&text, 0x5ff000)], &mut dest,
        ), Err(MaterializeError::InvalidSegment));
    }
    assert!(rx.iter().all(|b| *b == 0xa5));
    assert!(rw.iter().all(|b| *b == 0x5a));
}
