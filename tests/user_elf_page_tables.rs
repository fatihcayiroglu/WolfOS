//! Exact no_std mapper, checked with independent page walks and corruptions.
#[path = "../kernel/src/elf64_preflight.rs"]
mod elf64_preflight;
#[path = "../kernel/src/user_elf_launch_layout.rs"]
mod user_elf_launch_layout;
#[path = "../kernel/src/elf64_page_image.rs"]
mod elf64_page_image;
#[path = "../kernel/src/pmm_frame_batch.rs"]
mod pmm_frame_batch;
#[path = "../kernel/src/user_elf_page_tables.rs"]
mod user_elf_page_tables;

use user_elf_launch_layout::{LaunchError, plan_bounded_with_budget};
use user_elf_page_tables::{ElfPageTables, MappingError, OwnedLeafPage, StageError, TableBuffers};
use elf64_page_image::PAGE_SIZE;

fn image(text: u64, text_pages: u64, data: Option<u64>) -> Vec<u8> {
    let mut b = vec![0; 1024];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&62u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&(text + 0x200).to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&(if data.is_some() { 2u16 } else { 1 }).to_le_bytes());
    for (i, (va, pages, flags, offset)) in [
        (text, text_pages, 5u32, 0x200u64),
        (data.unwrap_or(0), 1, 6, 0x300),
    ]
    .into_iter()
    .take(if data.is_some() { 2 } else { 1 })
    .enumerate()
    {
        let at = 64 + 56 * i;
        b[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
        b[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
        b[at + 16..at + 24].copy_from_slice(&(va + offset).to_le_bytes());
        b[at + 32..at + 40].copy_from_slice(&8u64.to_le_bytes());
        b[at + 40..at + 48].copy_from_slice(&(pages * 4096 - offset).to_le_bytes());
        b[at + 48..at + 56].copy_from_slice(&4096u64.to_le_bytes());
    }
    b[0x200] = 0xc3;
    b
}

fn frames(count: usize) -> Vec<u64> {
    (0..count).map(|i| 0x10000 + i as u64 * 4096).collect()
}
type Bank = [[u64; 512]; 5];
fn buffers(bank: &mut Bank, two: bool) -> TableBuffers<'_> {
    let [pml4, pdpt, pd, pt0, pt1] = bank;
    TableBuffers {
        pml4,
        pdpt,
        pd,
        pt0,
        pt1: if two { Some(pt1) } else { None },
    }
}

/// Walk by physical pointer entries, independently of the mapper's recipe.
fn walk(bank: &Bank, owned: &[u64], va: u64) -> Option<u64> {
    let mut table = 0;
    for shift in [39, 30, 21] {
        let entry = bank[table][((va >> shift) & 511) as usize];
        if entry & 1 == 0 {
            return None;
        }
        table = owned
            .iter()
            .position(|frame| *frame == entry & 0x000f_ffff_ffff_f000)?;
        if table >= 5 {
            return None;
        }
    }
    let entry = bank[table][((va >> 12) & 511) as usize];
    (entry & 1 != 0).then_some(entry)
}

#[test]
fn one_recipe_drives_exact_six_seven_eight_and_nine_frame_images() {
    for (elf, tables, loads, total) in [
        (image(0x401000, 1, None), 4, 1, 6),
        (image(0x401000, 1, Some(0x403000)), 4, 2, 7),
        (image(0x401000, 1, Some(0x600000)), 5, 2, 8),
        (image(0x401000, 2, Some(0x600000)), 5, 3, 9),
    ] {
        let owned = frames(total);
        let mapper = ElfPageTables::bind(&elf, 7, &owned).unwrap();
        assert_eq!(mapper.launch().frames.table_frames, tables);
        assert_eq!(mapper.launch().frames.load_frames, loads);
        assert_eq!(mapper.launch().frames.total_frames, total);
        assert_eq!(mapper.entry(), (7 << 39) + 0x401200);
        let mut bank = [[0; 512]; 5];
        mapper
            .populate(&mut buffers(&mut bank, tables == 5))
            .unwrap();
        mapper.audit(&buffers(&mut bank, tables == 5)).unwrap();
        for (i, leaf) in mapper.launch().layout.leaves[..loads + 1]
            .iter()
            .flatten()
            .enumerate()
        {
            let actual = walk(&bank, &owned, (7 << 39) + leaf.virtual_address).unwrap();
            let flags = 1
                | 4
                | if leaf.writable { 2 } else { 0 }
                | if leaf.executable { 0 } else { 1 << 63 };
            assert_eq!(actual, owned[tables + i] | flags);
        }
        assert!(walk(&bank, &owned, (7 << 39) + 0x400000).is_none());
        assert!(walk(&bank, &owned, mapper.stack_page() + 4096).is_none());
        assert!(bank[0][256..].iter().all(|entry| *entry == 0));
        assert_eq!(bank[2].iter().filter(|e| **e != 0).count(), tables - 3);
        if tables == 4 {
            assert_eq!(bank[4], [0; 512]);
        }
    }
}

#[test]
fn stack_alone_can_require_the_second_pt() {
    let elf = image(0x5ff000, 1, None);
    let plan = plan_bounded_with_budget(&elf).unwrap();
    assert_eq!(plan.frames.total_frames, 7);
    assert_eq!(plan.frames.table_frames, 5);
    let mapper = ElfPageTables::bind(&elf, 1, &frames(7)).unwrap();
    let mut bank = [[0; 512]; 5];
    mapper.populate(&mut buffers(&mut bank, true)).unwrap();
    assert_eq!(bank[3][511] & (2 | (1 << 63)), 0); // RX
    assert_eq!(bank[4][0] & (2 | (1 << 63)), 2 | (1 << 63)); // RW/NX stack
}

#[test]
fn header_order_and_nonfixture_table_indices_remain_byte_derived() {
    let mut elf = image(0x12301000, 1, Some(0x12603000));
    let first: [u8; 56] = elf[64..120].try_into().unwrap();
    elf.copy_within(120..176, 64);
    elf[120..176].copy_from_slice(&first);
    let owned = frames(8);
    let mapper = ElfPageTables::bind(&elf, 255, &owned).unwrap();
    let mut bank = [[0; 512]; 5];
    mapper.populate(&mut buffers(&mut bank, true)).unwrap();
    assert_eq!(
        walk(&bank, &owned, (255 << 39) + 0x12603000),
        Some(owned[5] | 7 | (1 << 63))
    );
    assert_eq!(
        walk(&bank, &owned, (255 << 39) + 0x12301000),
        Some(owned[6] | 5)
    );
    assert_eq!(mapper.stack_page(), (255 << 39) + 0x12604000);
}

#[test]
fn insufficient_or_padded_leases_are_never_bound() {
    let elf = image(0x401000, 1, None);
    for count in [0, 1, 5, 7, 9, 10] {
        assert!(matches!(
            ElfPageTables::bind(&elf, 1, &frames(count)),
            Err(MappingError::FrameCount)
        ));
    }
}

#[test]
fn every_table_leaf_and_cross_leaf_physical_alias_is_rejected() {
    let elf = image(0x401000, 2, Some(0x600000));
    for a in 0..9 {
        for b in a + 1..9 {
            let mut owned = frames(9);
            owned[b] = owned[a];
            assert!(matches!(
                ElfPageTables::bind(&elf, 1, &owned),
                Err(MappingError::AliasedFrame)
            ));
        }
    }
    for i in 0..9 {
        for invalid in [0, 1, 4097, 1 << 52, u64::MAX] {
            let mut owned = frames(9);
            owned[i] = invalid;
            assert!(matches!(
                ElfPageTables::bind(&elf, 1, &owned),
                Err(MappingError::InvalidFrame)
            ));
        }
    }
}

#[test]
fn wrong_table_bank_shape_never_writes_any_entry() {
    for two in [false, true] {
        let elf = image(0x401000, 1, Some(if two { 0x600000 } else { 0x403000 }));
        let mapper = ElfPageTables::bind(&elf, 1, &frames(if two { 8 } else { 7 })).unwrap();
        let mut bank = [[0; 512]; 5];
        assert_eq!(
            mapper.populate(&mut buffers(&mut bank, !two)),
            Err(MappingError::TableCount)
        );
        assert_eq!(bank, [[0; 512]; 5]);
    }
}

#[test]
fn dirty_last_entry_of_any_destination_is_transactionally_rejected() {
    let elf = image(0x401000, 2, Some(0x600000));
    let mapper = ElfPageTables::bind(&elf, 1, &frames(9)).unwrap();
    for table in 0..5 {
        let mut bank = [[0; 512]; 5];
        bank[table][511] = 0x1234005;
        let before = bank;
        assert_eq!(
            mapper.populate(&mut buffers(&mut bank, true)),
            Err(MappingError::DirtyTable)
        );
        assert_eq!(bank, before);
    }
}

#[test]
fn audit_rejects_permission_escalation_missing_mappings_and_extra_aliases() {
    let elf = image(0x401000, 2, Some(0x600000));
    let mapper = ElfPageTables::bind(&elf, 1, &frames(9)).unwrap();
    let mut good = [[0; 512]; 5];
    mapper.populate(&mut buffers(&mut good, true)).unwrap();
    // RX made writable; stack made executable; parent U removed; extra
    // supervisor mapping; swapped PT pointer; absent second RX leaf.
    for (table, index, xor) in [
        (3, 1, 2),
        (4, 1, 1 << 63),
        (1, 0, 4),
        (0, 256, 0x10005),
        (2, 2, 4096),
        (3, 2, 1),
    ] {
        let mut bank = good;
        bank[table][index] ^= xor;
        assert_eq!(
            mapper.audit(&buffers(&mut bank, true)),
            Err(MappingError::MismatchedTable)
        );
    }
}

#[test]
fn malformed_and_unsupported_images_do_not_produce_a_recipe() {
    let mut wx = image(0x401000, 1, None);
    wx[68..72].copy_from_slice(&7u32.to_le_bytes());
    assert!(matches!(
        ElfPageTables::bind(&wx, 1, &frames(6)),
        Err(MappingError::Image(_))
    ));
    let cross = image(0x3ffff000, 1, Some(0x40000000));
    assert_eq!(
        plan_bounded_with_budget(&cross),
        Err(LaunchError::CrossesPageDirectory)
    );
    let mut bad = image(0x401000, 1, None);
    bad[0] = 0;
    assert!(matches!(
        ElfPageTables::bind(&bad, 1, &frames(6)),
        Err(MappingError::Image(_))
    ));
}

#[test]
fn relocation_never_crosses_into_another_or_noncanonical_slot() {
    let elf = image(0x401000, 1, None);
    for slot in [0, 256, 511, usize::MAX] {
        assert!(matches!(
            ElfPageTables::bind(&elf, slot, &frames(6)),
            Err(MappingError::InvalidUserSlot)
        ));
    }
    let high_source = image((1 << 39) + 0x401000, 1, None);
    assert!(matches!(
        ElfPageTables::bind(&high_source, 1, &frames(6)),
        Err(MappingError::AddressRange)
    ));
    let last_stack = image((1 << 39) - 8192, 1, None);
    assert!(ElfPageTables::bind(&last_stack, 254, &frames(6)).is_ok());
    assert!(matches!(
        ElfPageTables::bind(&last_stack, 255, &frames(6)),
        Err(MappingError::AddressRange)
    ));
}

#[test]
fn high_physical_addresses_are_never_truncated_to_32_bits() {
    let elf = image(0x401000, 1, None);
    let owned: Vec<_> = frames(6).iter().map(|p| p + (1 << 36)).collect();
    let mapper = ElfPageTables::bind(&elf, 1, &owned).unwrap();
    let mut bank = [[0; 512]; 5];
    mapper.populate(&mut buffers(&mut bank, false)).unwrap();
    assert_eq!(
        walk(&bank, &owned, (1 << 39) + 0x401000),
        Some(owned[4] | 5)
    );
}

#[test]
fn the_exact_six_seven_eight_and_nine_frame_recipes_stage_real_elf_bytes() {
    for (mut elf, table_frames, loads, total) in [
        (image(0x401000, 1, None), 4, 1, 6),
        (image(0x401000, 1, Some(0x403000)), 4, 2, 7),
        (image(0x401000, 1, Some(0x600000)), 5, 2, 8),
        (image(0x401000, 2, Some(0x600000)), 5, 3, 9),
    ] {
        elf[0x300] = 0x5a;
        let owned = frames(total);
        let mapper = ElfPageTables::bind(&elf, 11, &owned).unwrap();
        let mut pages = vec![[0u8; PAGE_SIZE]; loads];
        let mut stack_page = [0u8; PAGE_SIZE];
        {
            let mut buffers: Vec<OwnedLeafPage<'_>> = pages.iter_mut().enumerate()
                .map(|(i, bytes)| OwnedLeafPage {
                    physical_frame: owned[table_frames + i],
                    bytes,
                }).collect();
            let mut stack = OwnedLeafPage {
                physical_frame: owned[total - 1],
                bytes: &mut stack_page,
            };
            let result = mapper.stage_load_and_stack(&elf, &mut buffers, &mut stack)
                .expect("the shared page-table budget also drives safe payload staging");
            assert_eq!(result[0].unwrap().copied, 8);
            assert!(result[0].unwrap().executable);
            assert!(!result[0].unwrap().writable);
            for inactive in &result[loads..] {
                assert_eq!(*inactive, None);
            }
            if loads == 3 {
                assert_eq!(result[1].unwrap().copied, 0); // second RX BSS page
            }
        }
        assert_eq!(pages[0][0x200], 0xc3);
        assert!(pages[0][0x201..].iter().all(|b| *b == 0));
        if loads > 1 {
            assert_eq!(pages[loads - 1][0x300], 0x5a);
        }
        assert!(stack_page.iter().all(|b| *b == 0));
        assert!(pages.iter().all(|p| p[PAGE_SIZE - 1] == 0));
    }
}

#[test]
fn stage_rejects_late_wrong_frame_and_dirty_stack_before_any_payload_write() {
    let elf = image(0x401000, 2, Some(0x600000));
    let owned = frames(9);
    let mapper = ElfPageTables::bind(&elf, 7, &owned).unwrap();
    let mut pages = vec![[0u8; PAGE_SIZE]; 3];
    let mut stack_page = [0u8; PAGE_SIZE];
    {
        let mut buffers: Vec<OwnedLeafPage<'_>> = pages.iter_mut().enumerate()
            .map(|(i, bytes)| OwnedLeafPage {
                physical_frame: owned[5 + i], bytes,
            }).collect();
        let mut stack = OwnedLeafPage {
            physical_frame: owned[8], bytes: &mut stack_page,
        };

        buffers[2].physical_frame = owned[1];
        assert_eq!(
            mapper.stage_load_and_stack(&elf, &mut buffers, &mut stack),
            Err(StageError::BackingFrameMismatch { index: 2 }),
        );
        buffers[2].physical_frame = owned[7];

        stack.bytes[PAGE_SIZE - 1] = 0xa5;
        assert_eq!(
            mapper.stage_load_and_stack(&elf, &mut buffers, &mut stack),
            Err(StageError::DirtyOwnedPage { index: 3 }),
        );
        assert!(buffers.iter().all(|p| p.bytes.iter().all(|b| *b == 0)));
        assert_eq!(stack.bytes[PAGE_SIZE - 1], 0xa5);
        stack.bytes[PAGE_SIZE - 1] = 0;

        let changed = image(0x401000, 1, Some(0x600000));
        assert_eq!(
            mapper.stage_load_and_stack(&changed, &mut buffers, &mut stack),
            Err(StageError::ChangedImageLayout),
        );
        assert_eq!(
            mapper.stage_load_and_stack(&[0u8; 8], &mut buffers, &mut stack),
            Err(StageError::Image(LaunchError::Elf(
                elf64_preflight::ElfError::Truncated
            ))),
        );
    }
    assert!(pages.iter().all(|p| p.iter().all(|b| *b == 0)));
    assert!(stack_page.iter().all(|b| *b == 0));
}

#[derive(Default)]
struct FakePmm {
    next: usize,
    fail_after: usize,
    allocated: Vec<u64>,
    released: Vec<u64>,
}
impl pmm_frame_batch::FrameSource for FakePmm {
    fn allocate(&mut self) -> Option<u64> {
        if self.next == self.fail_after { return None }
        let frame = 0x10000 + 4096 * self.next as u64;
        self.next += 1;
        self.allocated.push(frame);
        Some(frame)
    }
    fn release(&mut self, frame: u64) -> bool {
        self.released.push(frame);
        true
    }
}

#[test]
fn elf_counted_pmm_staging_rolls_back_after_rejected_payload() {
    for (elf, expected_frames) in [
        (image(0x401000, 1, None), 6),
        (image(0x401000, 1, Some(0x403000)), 7),
        (image(0x401000, 1, Some(0x600000)), 8),
        (image(0x401000, 2, Some(0x600000)), 9),
    ] {
        let plan = plan_bounded_with_budget(&elf).unwrap();
        assert_eq!(plan.frames.total_frames, expected_frames);
        let mut pmm = FakePmm { fail_after: expected_frames, ..Default::default() };
        {
            let batch = pmm_frame_batch::FrameBatch::<_, 9>::acquire_count(
                &mut pmm, plan.frames.total_frames,
            ).unwrap();
            let mapper = ElfPageTables::bind(&elf, 3, batch.leased_frames()).unwrap();
            let count = plan.frames.load_frames;
            let mut pages = vec![[0u8; PAGE_SIZE]; count];
            let mut stack_page = [0u8; PAGE_SIZE];
            stack_page[PAGE_SIZE - 1] = 1; // late admission failure, no payload copied
            let mut buffers: Vec<OwnedLeafPage<'_>> = pages.iter_mut().enumerate()
                .map(|(i, bytes)| OwnedLeafPage {
                    physical_frame: batch.leased_frames()[plan.frames.table_frames + i],
                    bytes,
                }).collect();
            let mut stack = OwnedLeafPage {
                physical_frame: batch.leased_frames()[expected_frames - 1],
                bytes: &mut stack_page,
            };
            assert_eq!(
                mapper.stage_load_and_stack(&elf, &mut buffers, &mut stack),
                Err(StageError::DirtyOwnedPage { index: count }),
            );
            assert!(buffers.iter().all(|page| page.bytes.iter().all(|b| *b == 0)));
            // Neither the sealed recipe nor a staged batch may be published.
            // Drop returns the exact ELF-derived live prefix in reverse.
        }
        assert_eq!(pmm.allocated.len(), expected_frames);
        assert_eq!(pmm.released.len(), expected_frames);
        assert_eq!(pmm.released, pmm.allocated.iter().rev().copied().collect::<Vec<_>>());
    }
}

#[test]
fn elf_counted_pmm_short_allocation_releases_exact_partial_prefix() {
    let elf = image(0x401000, 2, Some(0x600000));
    let needed = plan_bounded_with_budget(&elf).unwrap().frames.total_frames;
    assert_eq!(needed, 9);
    let mut pmm = FakePmm { fail_after: 4, ..Default::default() };
    assert_eq!(
        pmm_frame_batch::FrameBatch::<_, 9>::acquire_count(&mut pmm, needed)
            .err().expect("the fifth allocation fails"),
        pmm_frame_batch::AcquireError::Exhausted {
            acquired: 4,
            rollback: pmm_frame_batch::ReleaseReport { released: 4, failed: 0 },
        }
    );
    assert_eq!(pmm.released, pmm.allocated.iter().rev().copied().collect::<Vec<_>>());
}
