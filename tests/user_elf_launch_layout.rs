//! Host tests for byte-derived, bounded, allocation-free static ELF launch layout.
#[path = "../kernel/src/elf64_preflight.rs"]
mod elf64_preflight;
#[path = "../kernel/src/user_elf_launch_layout.rs"]
mod user_elf_launch_layout;

use elf64_preflight::{ElfError, PAGE_BYTES, USER_END};
use user_elf_launch_layout::{plan_static_image, plan_two_pt_image, plan_one_pt_with_budget, plan_two_pt_with_budget, LaunchError, LaunchLeaf};

fn fixture(text_page: u64, text_pages: u64, data_page: u64, data_pages: u64) -> [u8; 512] {
    let mut elf = [0u8; 512];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4..7].copy_from_slice(&[2, 1, 1]);
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86-64
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[24..32].copy_from_slice(&(text_page + 0x100).to_le_bytes());
    elf[32..40].copy_from_slice(&64u64.to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[54..56].copy_from_slice(&56u16.to_le_bytes());
    elf[56..58].copy_from_slice(&2u16.to_le_bytes());

    elf[64..68].copy_from_slice(&1u32.to_le_bytes());
    elf[68..72].copy_from_slice(&5u32.to_le_bytes()); // read + execute
    elf[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    elf[80..88].copy_from_slice(&(text_page + 0x100).to_le_bytes());
    elf[96..104].copy_from_slice(&8u64.to_le_bytes());
    elf[104..112].copy_from_slice(&(text_pages * PAGE_BYTES - 0x100).to_le_bytes());
    elf[112..120].copy_from_slice(&PAGE_BYTES.to_le_bytes());

    elf[120..124].copy_from_slice(&1u32.to_le_bytes());
    elf[124..128].copy_from_slice(&6u32.to_le_bytes()); // read + write, NX
    elf[128..136].copy_from_slice(&0x180u64.to_le_bytes());
    elf[136..144].copy_from_slice(&(data_page + 0x180).to_le_bytes());
    elf[152..160].copy_from_slice(&1u64.to_le_bytes());
    elf[160..168].copy_from_slice(&(data_pages * PAGE_BYTES - 0x180).to_le_bytes());
    elf[168..176].copy_from_slice(&PAGE_BYTES.to_le_bytes());
    elf[0x100] = 0xc3;
    elf[0x180] = 0x5a;
    elf
}

#[test]
fn disjoint_text_data_and_stack_are_derived_without_mutating_elf() {
    let elf = fixture(0x401000, 1, 0x403000, 1);
    let original = elf;
    let layout = plan_static_image(&elf).unwrap();
    assert_eq!(layout.image.entry, 0x401100);
    assert_eq!(layout.load_pages(), 2);
    assert_eq!(layout.len, 3);
    assert_eq!(layout.stack_page, 0x404000);
    assert_eq!(layout.leaves[0], Some(LaunchLeaf {
        virtual_address: 0x401000, source_segment: Some(0),
        writable: false, executable: true,
    }));
    assert_eq!(layout.leaves[1], Some(LaunchLeaf {
        virtual_address: 0x403000, source_segment: Some(1),
        writable: true, executable: false,
    }));
    assert_eq!(layout.leaves[2], Some(LaunchLeaf {
        virtual_address: 0x404000, source_segment: None,
        writable: true, executable: false,
    }));
    assert!(layout.leaves[3].is_none());
    assert_eq!(elf, original);
}

#[test]
fn extra_bss_only_load_page_is_accounted_for() {
    let elf = fixture(0x401000, 2, 0x403000, 1);
    let layout = plan_static_image(&elf).unwrap();
    assert_eq!(layout.load_pages(), 3);
    assert_eq!(layout.len, 4);
    assert_eq!(layout.leaves[1].unwrap().virtual_address, 0x402000);
    assert_eq!(layout.leaves[1].unwrap().source_segment, Some(0));
    assert_eq!(layout.leaves[3].unwrap().source_segment, None);
    assert_eq!(layout.stack_page, 0x404000);
}

#[test]
fn program_header_order_cannot_change_stack_high_water_mark() {
    let mut elf = fixture(0x401000, 1, 0x403000, 1);
    let first: [u8; 56] = elf[64..120].try_into().unwrap();
    let second: [u8; 56] = elf[120..176].try_into().unwrap();
    elf[64..120].copy_from_slice(&second);
    elf[120..176].copy_from_slice(&first);
    let layout = plan_static_image(&elf).unwrap();
    assert_eq!(layout.stack_page, 0x404000);
    assert_eq!(layout.leaves[0].unwrap().source_segment, Some(0));
    assert_eq!(layout.leaves[0].unwrap().virtual_address, 0x403000);
    assert_eq!(layout.leaves[1].unwrap().source_segment, Some(1));
    assert_eq!(layout.leaves[1].unwrap().virtual_address, 0x401000);
}

#[test]
fn refuse_oversized_cross_table_and_stack_boundary_images() {
    assert_eq!(
        plan_static_image(&fixture(0x401000, 3, 0x404000, 1)),
        Err(LaunchError::TooManyLoadPages),
    );
    assert_eq!(
        plan_static_image(&fixture(0x401000, 1, 0x601000, 1)),
        Err(LaunchError::CrossesPageTable),
    );
    assert_eq!(
        plan_static_image(&fixture(0x5fe000, 1, 0x5ff000, 1)),
        Err(LaunchError::CrossesPageTable),
    );
    assert_eq!(
        plan_static_image(&fixture(USER_END - 0x3000, 1, USER_END - 0x1000, 1)),
        Err(LaunchError::StackOutOfRange),
    );
}

#[test]
fn malformed_or_writable_executable_elf_is_never_admitted() {
    let mut elf = fixture(0x401000, 1, 0x403000, 1);
    elf[0] = 0;
    assert_eq!(plan_static_image(&elf), Err(LaunchError::Elf(ElfError::Magic)));
    elf[0] = 0x7f;
    elf[68..72].copy_from_slice(&7u32.to_le_bytes());
    assert_eq!(
        plan_static_image(&elf),
        Err(LaunchError::Elf(ElfError::InvalidPermissions)),
    );
}

#[test]
fn bounded_two_pt_plan_admits_real_boundary_crossing_without_weakening_one_pt() {
    let bytes = fixture(0x5ff000, 1, 0x600000, 1);
    assert_eq!(plan_static_image(&bytes), Err(LaunchError::CrossesPageTable));
    let layout = plan_two_pt_image(&bytes).unwrap();
    assert_eq!(layout.load_pages(), 2);
    assert_eq!(layout.stack_page, 0x601000);
    assert_eq!(layout.leaves[0].unwrap().virtual_address, 0x5ff000);
    assert_eq!(layout.leaves[1].unwrap().virtual_address, 0x600000);
    assert_eq!(layout.leaves[2].unwrap().virtual_address, 0x601000);
    assert_eq!(layout.leaves[2].unwrap().executable, false);
}

#[test]
fn two_pt_plan_never_crosses_one_gigabyte_or_adds_a_third_pt() {
    assert_eq!(
        plan_two_pt_image(&fixture(0x3ffff000, 1, 0x40000000, 1)),
        Err(LaunchError::CrossesPageDirectory),
    );
    let mut bytes = fixture(0x401000, 1, 0x601000, 1);
    bytes[56..58].copy_from_slice(&3u16.to_le_bytes());
    bytes[176..180].copy_from_slice(&1u32.to_le_bytes()); // third PT_LOAD
    bytes[180..184].copy_from_slice(&6u32.to_le_bytes()); // RW+NX
    bytes[184..192].copy_from_slice(&0x1c0u64.to_le_bytes());
    bytes[192..200].copy_from_slice(&0x8011c0u64.to_le_bytes());
    bytes[208..216].copy_from_slice(&1u64.to_le_bytes());
    bytes[216..224].copy_from_slice(&0xe40u64.to_le_bytes());
    bytes[224..232].copy_from_slice(&4096u64.to_le_bytes());
    bytes[0x1c0] = 3;
    assert_eq!(plan_two_pt_image(&bytes), Err(LaunchError::TooManyPageTables));
}

#[test]
fn exact_prelease_budget_tracks_one_two_and_three_elf_load_pages() {
    // One-PT gate: two ELF leaves + the independent stack + four tables.
    let bytes = fixture(0x401000, 1, 0x403000, 1);
    let one_pt = plan_one_pt_with_budget(&bytes).unwrap();
    assert_eq!(one_pt.layout, plan_static_image(&bytes).unwrap());
    assert_eq!(one_pt.frames.table_frames, 4);
    assert_eq!(one_pt.frames.load_frames, 2);
    assert_eq!(one_pt.frames.stack_frames, 1);
    assert_eq!(one_pt.frames.leaf_frames, 3);
    assert_eq!(one_pt.frames.total_frames, 7);
    assert!(one_pt.frames.matches_exact_lease(4, 7));
    assert!(!one_pt.frames.matches_exact_lease(5, 7));
    assert!(!one_pt.frames.matches_exact_lease(4, 8));

    // Same ELF with the two-PT runtime budget requires five table frames.
    let two_pt = plan_two_pt_with_budget(&bytes).unwrap();
    assert_eq!(two_pt.layout, plan_two_pt_image(&bytes).unwrap());
    assert_eq!(two_pt.frames.table_frames, 5);
    assert_eq!(two_pt.frames.load_frames, 2);
    assert_eq!(two_pt.frames.leaf_frames, 3);
    assert_eq!(two_pt.frames.total_frames, 8);
    assert!(two_pt.frames.matches_exact_lease(5, 8));
    assert!(!two_pt.frames.matches_exact_lease(5, 9));

    // Two RX pages and one RW page across two 2-MiB table regions:
    // five table frames plus three LOAD leaves and one NX stack = nine.
    let three = fixture(0x5fe000, 2, 0x600000, 1);
    let plan = plan_two_pt_with_budget(&three).unwrap();
    assert_eq!(plan.layout.load_pages(), 3);
    assert_eq!(plan.frames.table_frames, 5);
    assert_eq!(plan.frames.load_frames, 3);
    assert_eq!(plan.frames.stack_frames, 1);
    assert_eq!(plan.frames.leaf_frames, 4);
    assert_eq!(plan.frames.total_frames, 9);
    assert!(plan.frames.matches_exact_lease(5, 9));
    assert!(!plan.frames.matches_exact_lease(5, 8));
    assert_eq!(plan_one_pt_with_budget(&three),
        Err(LaunchError::CrossesPageTable));

    // A single-LOAD ELF within one PT needs only six PMM frames in total.
    let mut one_pt_elf = bytes;
    one_pt_elf[56..58].copy_from_slice(&1u16.to_le_bytes());
    let sole = plan_one_pt_with_budget(&one_pt_elf).unwrap();
    assert_eq!(sole.frames.load_frames, 1);
    assert_eq!(sole.frames.leaf_frames, 2);
    assert_eq!(sole.frames.table_frames, 4);
    assert_eq!(sole.frames.total_frames, 6);
    assert!(sole.frames.matches_exact_lease(4, 6));

    // An ELF with only one executable LOAD still reserves a separate stack.
    let mut one = fixture(0x5ff000, 1, 0x600000, 1);
    one[56..58].copy_from_slice(&1u16.to_le_bytes());
    let plan = plan_two_pt_with_budget(&one).unwrap();
    assert_eq!(plan.frames.load_frames, 1);
    assert_eq!(plan.frames.stack_frames, 1);
    assert_eq!(plan.frames.total_frames, 7);
    assert_eq!(plan.layout.stack_page, 0x600000);
}

#[test]
fn invalid_elf_never_produces_a_frame_budget_or_consumes_external_state() {
    let mut bad = fixture(0x401000, 1, 0x403000, 1);
    let initial = bad;
    bad[0] = 0; // no valid ELF => no allocation budget at all
    assert_eq!(plan_one_pt_with_budget(&bad),
        Err(LaunchError::Elf(ElfError::Magic)));
    assert_eq!(plan_two_pt_with_budget(&bad),
        Err(LaunchError::Elf(ElfError::Magic)));
    // Both helpers are pure; image bytes and caller state are untouched.
    assert_eq!(bad[1..], initial[1..]);
    let previous = plan_two_pt_with_budget(&initial).unwrap();
    assert_eq!(previous.frames.total_frames, 8);
}
