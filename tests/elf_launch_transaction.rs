//! Observe the actual preparation owner and backend calls, not hardware CPUs.
#[path = "../kernel/src/active_address_space.rs"]
mod active_address_space;
#[path = "../kernel/src/address_space_retirement.rs"]
mod address_space_retirement;
#[path = "../kernel/src/elf64_page_image.rs"]
mod elf64_page_image;
#[path = "../kernel/src/elf64_preflight.rs"]
mod elf64_preflight;
#[path = "../kernel/src/elf_launch_transaction.rs"]
mod elf_launch_transaction;
#[path = "../kernel/src/pmm_frame_batch.rs"]
mod pmm_frame_batch;
#[path = "../kernel/src/saved_context_retirement.rs"]
mod saved_context_retirement;
#[path = "../kernel/src/user_elf_launch_layout.rs"]
mod user_elf_launch_layout;
#[path = "../kernel/src/user_elf_page_tables.rs"]
mod user_elf_page_tables;

use elf_launch_transaction::{ElfLaunch, PayloadReady, ReserveError, Reserved, TablesReady};
use pmm_frame_batch::{AcquireError, FrameSource, ReleaseReport};
use std::{cell::RefCell, collections::BTreeSet, rc::Rc};
use user_elf_page_tables::{MappingError, OwnedLeafPage, StageError, TableBuffers};

#[derive(Default)]
struct Trace {
    attempts: usize,
    allocated: Vec<u64>,
    live: BTreeSet<u64>,
    released: Vec<u64>,
    fail_release: Option<u64>,
}
struct Source {
    next: u64,
    remaining: usize,
    trace: Rc<RefCell<Trace>>,
}
impl Source {
    fn new(limit: usize) -> Self {
        Self {
            next: 0x10000,
            remaining: limit,
            trace: Rc::default(),
        }
    }
}
impl FrameSource for Source {
    fn allocate(&mut self) -> Option<u64> {
        let mut t = self.trace.borrow_mut();
        t.attempts += 1;
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let frame = self.next;
        self.next += 4096;
        t.allocated.push(frame);
        assert!(t.live.insert(frame));
        Some(frame)
    }
    fn release(&mut self, frame: u64) -> bool {
        let mut t = self.trace.borrow_mut();
        t.released.push(frame);
        if t.fail_release == Some(frame) {
            return false;
        }
        assert!(t.live.remove(&frame), "no double release");
        true
    }
}

fn image(loads: usize, two: bool) -> Vec<u8> {
    let mut b = vec![0; 1024];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    b[18..20].copy_from_slice(&62u16.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&0x401200u64.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&(if loads == 1 { 1u16 } else { 2 }).to_le_bytes());
    let data = if two { 0x600000u64 } else { 0x403000 };
    for (i, (va, pages, flags, offset)) in [
        (
            0x401000u64,
            if loads == 3 { 2u64 } else { 1 },
            5u32,
            0x200u64,
        ),
        (data, 1, 6, 0x300),
    ]
    .into_iter()
    .take(if loads == 1 { 1 } else { 2 })
    .enumerate()
    {
        let at = 64 + 56 * i;
        b[at..at + 4].copy_from_slice(&1u32.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&flags.to_le_bytes());
        b[at + 8..at + 16].copy_from_slice(&offset.to_le_bytes());
        b[at + 16..at + 24].copy_from_slice(&(va + offset).to_le_bytes());
        b[at + 32..at + 40].copy_from_slice(&8u64.to_le_bytes());
        b[at + 40..at + 48].copy_from_slice(&(4096 * pages - offset).to_le_bytes());
        b[at + 48..at + 56].copy_from_slice(&4096u64.to_le_bytes());
    }
    b[0x200] = 0xc3;
    b[0x300] = 0x5a;
    b
}
type Tx<'s, 'i, Step> = ElfLaunch<'s, 'i, Source, 12, Step>;
type Bank = [[u64; 512]; 5];
fn tables(bank: &mut Bank, two: bool) -> TableBuffers<'_> {
    let [pml4, pdpt, pd, pt0, pt1] = bank;
    TableBuffers {
        pml4,
        pdpt,
        pd,
        pt0,
        pt1: if two { Some(pt1) } else { None },
    }
}
fn staged<'s, 'i>(tx: Tx<'s, 'i, Reserved>) -> Tx<'s, 'i, PayloadReady> {
    let owned = tx.leased_frames().to_vec();
    let plan = *tx.recipe().launch();
    let mut pages = vec![[0u8; 4096]; plan.frames.load_frames];
    let mut stack = [0u8; 4096];
    let mut loads: Vec<_> = pages
        .iter_mut()
        .enumerate()
        .map(|(i, bytes)| OwnedLeafPage {
            physical_frame: owned[plan.frames.table_frames + i],
            bytes,
        })
        .collect();
    let mut stack = OwnedLeafPage {
        physical_frame: *owned.last().unwrap(),
        bytes: &mut stack,
    };
    let (tx, report) = tx
        .stage_payload(&mut loads, &mut stack)
        .unwrap_or_else(|(_, error)| panic!("stage: {error:?}"));
    assert_eq!(loads[0].bytes[0x200], 0xc3);
    assert_eq!(report[0].unwrap().copied, 8);
    assert!(stack.bytes.iter().all(|byte| *byte == 0));
    tx
}
fn prepared<'s, 'i>(tx: Tx<'s, 'i, Reserved>) -> Tx<'s, 'i, TablesReady> {
    let two = tx.recipe().launch().frames.table_frames == 5;
    let tx = staged(tx);
    let mut bank = [[0; 512]; 5];
    tx.build_tables(&mut tables(&mut bank, two))
        .unwrap_or_else(|(_, error)| panic!("map: {error:?}"))
}
fn assert_released(trace: &Rc<RefCell<Trace>>, count: usize) {
    let t = trace.borrow();
    assert_eq!(t.allocated.len(), count);
    assert_eq!(
        t.released,
        t.allocated.iter().rev().copied().collect::<Vec<_>>()
    );
    assert!(t.live.is_empty());
}

#[test]
fn every_real_budget_owns_only_the_prefix_and_transfers_once_to_active_retirement() {
    for (loads, two, count) in [(1, false, 6), (2, false, 7), (2, true, 8), (3, true, 9)] {
        let elf = image(loads, two);
        let mut source = Source::new(count);
        let trace = source.trace.clone();
        let tx = Tx::reserve(&mut source, &elf, 7).unwrap_or_else(|e| panic!("{e:?}"));
        let lease = tx.leased_frames().to_vec();
        assert_eq!(lease.len(), count); // storage capacity is twelve, never allocated
        let tx = prepared(tx);
        assert!(trace.borrow().released.is_empty());
        // No host CPU loads these synthetic roots. These are real allocator
        // callback effects and ledger composition, not hardware quiescence.
        let mut active =
            unsafe { tx.publish::<1>(11, 0x9000) }.unwrap_or_else(|(_, e)| panic!("{e:?}"));
        assert_eq!(active.leased_frames(), lease);
        assert!(active.frames()[count..].iter().all(|frame| *frame == 0));
        assert!(active.matches_process_lease_counted(11, lease[0], &lease));
        let ticket = active.reserve_cpu(0).unwrap();
        active.confirm_active(ticket, lease[0]).unwrap();
        active.begin_retirement().unwrap();
        assert_eq!(
            active.finish_retirement(),
            Err(address_space_retirement::Error::OutstandingCpus)
        );
        assert!(trace.borrow().released.is_empty());
        active.acknowledge_quiescent(ticket, 0x9000).unwrap();
        active.finish_retirement().unwrap();
        assert_eq!(
            unsafe { active.reclaim() }.ok(),
            Some(ReleaseReport {
                released: count,
                failed: 0
            })
        );
        assert_released(&trace, count);
    }
}

#[test]
fn abort_and_drop_in_every_prepublication_stage_roll_back_once() {
    for stage in 0..3 {
        let elf = image(3, true);
        let mut source = Source::new(9);
        let trace = source.trace.clone();
        let tx = Tx::reserve(&mut source, &elf, 7).unwrap_or_else(|e| panic!("{e:?}"));
        let report = match stage {
            0 => tx.abort(),
            1 => staged(tx).abort(),
            _ => prepared(tx).abort(),
        };
        assert_eq!(
            report,
            ReleaseReport {
                released: 9,
                failed: 0
            }
        );
        assert_released(&trace, 9);
    }
    for stage in 0..3 {
        let elf = image(2, true);
        let mut source = Source::new(8);
        let trace = source.trace.clone();
        let tx = Tx::reserve(&mut source, &elf, 1).unwrap_or_else(|e| panic!("{e:?}"));
        match stage {
            0 => drop(tx),
            1 => drop(staged(tx)),
            _ => drop(prepared(tx)),
        }
        assert_released(&trace, 8);
    }
}

#[test]
fn every_partial_allocation_boundary_has_an_exact_report_and_no_leak() {
    for (loads, two, count) in [(1, false, 6), (2, false, 7), (2, true, 8), (3, true, 9)] {
        let elf = image(loads, two);
        for acquired in 0..count {
            let mut source = Source::new(acquired);
            let trace = source.trace.clone();
            assert_eq!(
                Tx::reserve(&mut source, &elf, 1).err(),
                Some(ReserveError::Allocation(AcquireError::Exhausted {
                    acquired,
                    rollback: ReleaseReport {
                        released: acquired,
                        failed: 0
                    }
                }))
            );
            assert_eq!(trace.borrow().attempts, acquired + 1);
            assert_released(&trace, acquired);
        }
    }
}

#[test]
fn malformed_image_invalid_slot_and_small_capacity_never_call_allocator() {
    let elf = image(3, true);
    let mut source = Source::new(9);
    let trace = source.trace.clone();
    assert!(matches!(
        Tx::reserve(&mut source, &[0; 8], 1),
        Err(ReserveError::Image(_))
    ));
    assert!(matches!(
        Tx::reserve(&mut source, &elf, 0),
        Err(ReserveError::InvalidSlot)
    ));
    assert!(matches!(
        ElfLaunch::<_, 8, Reserved>::reserve(&mut source, &elf, 1),
        Err(ReserveError::Allocation(AcquireError::InvalidCount {
            requested: 9,
            capacity: 8
        }))
    ));
    assert_eq!(trace.borrow().attempts, 0);
    assert!(trace.borrow().released.is_empty());
}

#[test]
fn rejected_frame_binding_rolls_back_even_physical_zero_and_reports_backend_failures() {
    let elf = image(1, false);
    for fail in [None, Some(0x2000)] {
        let mut source = Source::new(6);
        source.next = 0; // aligned, owned PMM frame; deliberately not a valid root identity
        let trace = source.trace.clone();
        trace.borrow_mut().fail_release = fail;
        assert_eq!(
            Tx::reserve(&mut source, &elf, 1).err(),
            Some(ReserveError::Binding {
                error: MappingError::InvalidFrame,
                rollback: ReleaseReport {
                    released: if fail.is_some() { 5 } else { 6 },
                    failed: usize::from(fail.is_some())
                },
            })
        );
        assert_eq!(trace.borrow().released.len(), 6); // no destructor retry
        assert_eq!(trace.borrow().live.len(), usize::from(fail.is_some()));
    }
    let mut source = Source::new(3);
    let trace = source.trace.clone();
    trace.borrow_mut().fail_release = Some(0x11000);
    assert_eq!(
        Tx::reserve(&mut source, &elf, 1).err(),
        Some(ReserveError::Allocation(AcquireError::Exhausted {
            acquired: 3,
            rollback: ReleaseReport {
                released: 2,
                failed: 1
            }
        }))
    );
    assert_eq!(trace.borrow().released.len(), 3);
    assert_eq!(trace.borrow().live.len(), 1);
}

#[test]
fn unsupported_source_slot_binding_returns_the_complete_already_reserved_lease() {
    let mut elf = image(1, false);
    let text = (1u64 << 39) + 0x401200;
    elf[24..32].copy_from_slice(&text.to_le_bytes());
    elf[80..88].copy_from_slice(&text.to_le_bytes());
    let mut source = Source::new(6);
    let trace = source.trace.clone();
    assert_eq!(
        Tx::reserve(&mut source, &elf, 1).err(),
        Some(ReserveError::Binding {
            error: MappingError::AddressRange,
            rollback: ReleaseReport {
                released: 6,
                failed: 0
            },
        })
    );
    assert_released(&trace, 6);
}

#[test]
fn stage_and_table_errors_return_the_owner_for_retry_without_early_release() {
    let elf = image(3, true);
    let mut source = Source::new(9);
    let trace = source.trace.clone();
    let tx = Tx::reserve(&mut source, &elf, 1).unwrap_or_else(|e| panic!("{e:?}"));
    let lease = tx.leased_frames().to_vec();
    let mut pages = [[0u8; 4096]; 3];
    let mut stack_page = [0u8; 4096];
    let mut loads: Vec<_> = pages
        .iter_mut()
        .enumerate()
        .map(|(i, bytes)| OwnedLeafPage {
            physical_frame: lease[5 + i],
            bytes,
        })
        .collect();
    let mut stack = OwnedLeafPage {
        physical_frame: lease[8],
        bytes: &mut stack_page,
    };
    loads[2].physical_frame = lease[0];
    let (tx, error) = tx.stage_payload(&mut loads, &mut stack).err().unwrap();
    assert_eq!(error, StageError::BackingFrameMismatch { index: 2 });
    assert!(loads.iter().all(|p| p.bytes.iter().all(|b| *b == 0)));
    assert!(trace.borrow().released.is_empty());
    loads[2].physical_frame = lease[7];
    let (tx, _) = tx
        .stage_payload(&mut loads, &mut stack)
        .unwrap_or_else(|(_, e)| panic!("{e:?}"));
    let mut bank = [[0u64; 512]; 5];
    bank[4][511] = 1;
    let before = bank;
    let (tx, error) = tx.build_tables(&mut tables(&mut bank, true)).err().unwrap();
    assert_eq!(error, MappingError::DirtyTable);
    assert_eq!(bank, before);
    assert!(trace.borrow().released.is_empty());
    bank[4][511] = 0;
    let tx = tx
        .build_tables(&mut tables(&mut bank, true))
        .unwrap_or_else(|(_, e)| panic!("{e:?}"));
    assert_eq!(
        tx.abort(),
        ReleaseReport {
            released: 9,
            failed: 0
        }
    );
    assert_released(&trace, 9);
}

#[test]
fn publication_failure_returns_staging_owner_and_active_drop_never_rolls_it_back() {
    let elf = image(2, true);
    let mut source = Source::new(8);
    let trace = source.trace.clone();
    let tx = prepared(Tx::reserve(&mut source, &elf, 1).unwrap_or_else(|e| panic!("{e:?}")));
    let (tx, error) = unsafe { tx.publish::<1>(0, 0x9000) }.err().unwrap();
    assert_eq!(
        error,
        active_address_space::PublishError::Gate(address_space_retirement::Error::InvalidIdentity)
    );
    assert!(trace.borrow().released.is_empty());
    let wrong_supervisor = tx.leased_frames()[1];
    let (tx, error) = unsafe { tx.publish::<1>(1, wrong_supervisor) }
        .err()
        .unwrap();
    assert_eq!(error, active_address_space::PublishError::SupervisorOwned);
    assert!(trace.borrow().released.is_empty());
    let active = unsafe { tx.publish::<1>(1, 0x9000) }.unwrap_or_else(|(_, e)| panic!("{e:?}"));
    drop(active);
    assert!(trace.borrow().released.is_empty());
    assert_eq!(trace.borrow().live.len(), 8);
}

#[test]
fn compiler_refuses_publication_of_reserved_and_payload_only_owners() {
    let library = std::env::current_dir()
        .unwrap()
        .join("out/libwolfos_launch_contract.rlib");
    assert!(
        library.is_file(),
        "run the no_std contract build before these tests"
    );
    for stage in ["Reserved", "PayloadReady"] {
        let dir = std::env::temp_dir().join(format!(
            "wolfos-launch-contract-{}-{stage}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("premature.rs");
        std::fs::write(&file, format!(r#"#![no_std]
use wolfos_launch_contract::{{elf_launch_transaction::{{ElfLaunch, {stage}}}, pmm_frame_batch::FrameSource}};
pub fn premature<'f, 'i, S: FrameSource>(tx: ElfLaunch<'f, 'i, S, 12, {stage}>) {{
    let _ = unsafe {{ tx.publish::<1>(1, 0x9000) }};
}}
"#)).unwrap();
        let result = std::process::Command::new("rustc")
            .args([
                "--edition=2024",
                "--target",
                "x86_64-unknown-none",
                "--crate-type",
                "lib",
                "--extern",
            ])
            .arg(format!("wolfos_launch_contract={}", library.display()))
            .arg(&file)
            .arg("-o")
            .arg(dir.join("premature.rlib"))
            .output()
            .unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(
            !result.status.success(),
            "{stage} unexpectedly exposed publish"
        );
        assert!(
            error.contains("E0599") && error.contains("publish"),
            "{error}"
        );
    }
}
