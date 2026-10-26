//! Host tests run the exact no_std frame-ownership contract with a
//! deterministic fake provider (no physical memory or disk touched).
#[path = "../kernel/src/pmm_frame_batch.rs"]
mod pmm_frame_batch;
use pmm_frame_batch::{AcquireError, AdoptError, FrameBatch, FrameSource, ReleaseReport};

struct MockFrames {
    issued: usize,
    ceiling: usize,
    freed: [u64; 16],
    frees: usize,
    fail_releases: bool,
}

impl MockFrames {
    fn with_ceiling(ceiling: usize) -> Self {
        Self { issued: 0, ceiling, freed: [0; 16],
            frees: 0, fail_releases: false }
    }
}

impl FrameSource for MockFrames {
    fn allocate(&mut self) -> Option<u64> {
        if self.issued >= self.ceiling { return None; }
        self.issued += 1;
        Some(self.issued as u64 * 4096)
    }

    fn release(&mut self, frame: u64) -> bool {
        self.freed[self.frees] = frame;
        self.frees += 1;
        !self.fail_releases
    }
}

#[test]
fn closes_full_batch_once_in_reverse_allocation_order() {
    let mut source = MockFrames::with_ceiling(8);
    let batch = FrameBatch::<_, 8>::acquire(&mut source).unwrap_or_else(|_| panic!("allocate"));
    assert_eq!(batch.frames(), &[4096, 8192, 12288, 16384, 20480, 24576, 28672, 32768]);
    assert_eq!(batch.close(), ReleaseReport { released: 8, failed: 0 });
    assert_eq!(source.frees, 8);
    assert_eq!(&source.freed[..source.frees], &[32768, 28672, 24576, 20480, 16384, 12288, 8192, 4096]);
}

#[test]
fn injected_fourth_allocation_failure_rolls_back_three_frames() {
    let mut source = MockFrames::with_ceiling(3);
    assert!(matches!(
        FrameBatch::<_, 8>::acquire(&mut source),
        Err(AcquireError::Exhausted {
            acquired: 3,
            rollback: ReleaseReport { released: 3, failed: 0 }
        })
    ));
    assert_eq!(&source.freed[..source.frees], &[12288, 8192, 4096]);
    assert_eq!(source.frees, source.issued);
}

#[test]
fn early_scope_exit_and_empty_batch_do_not_double_free() {
    let mut source = MockFrames::with_ceiling(8);
    {
        let batch = FrameBatch::<_, 4>::acquire(&mut source).unwrap_or_else(|_| panic!("allocate"));
        assert_eq!(batch.frames().len(), 4);
        // Deliberately no close(): Drop must roll the staged frames back.
    }
    assert_eq!(&source.freed[..source.frees], &[16384, 12288, 8192, 4096]);
    let empty = FrameBatch::<_, 0>::acquire(&mut source).unwrap_or_else(|_| panic!("zero"));
    assert_eq!(empty.frames(), &[]);
    assert_eq!(empty.close(), ReleaseReport { released: 0, failed: 0 });
    assert_eq!(source.frees, 4);
}

#[test]
fn failed_backend_releases_are_visible_not_reported_as_success() {
    let mut source = MockFrames::with_ceiling(2);
    source.fail_releases = true;
    assert!(matches!(
        FrameBatch::<_, 4>::acquire(&mut source),
        Err(AcquireError::Exhausted {
            acquired: 2,
            rollback: ReleaseReport { released: 0, failed: 2 }
        })
    ));
    assert_eq!(source.frees, 2);
    let mut source = MockFrames::with_ceiling(3);
    source.fail_releases = true;
    let batch = FrameBatch::<_, 3>::acquire(&mut source).unwrap_or_else(|_| panic!("allocate"));
    assert_eq!(batch.close(), ReleaseReport { released: 0, failed: 3 });
    assert_eq!(source.frees, 3);
}

#[test]
fn image_budget_counts_six_through_nine_lease_exactly_requested_frames() {
    for count in [6usize, 7, 8, 9] {
        let mut source = MockFrames::with_ceiling(9);
        let batch = FrameBatch::<_, 9>::acquire_count(&mut source, count)
            .unwrap_or_else(|_| panic!("counted allocation"));
        assert_eq!(batch.leased_frames().len(), count);
        assert_eq!(batch.leased_frames()[0], 4096);
        assert_eq!(batch.leased_frames()[count - 1], count as u64 * 4096);
        assert!(batch.frames()[count..].iter().all(|frame| *frame == 0));
        assert_eq!(batch.close(), ReleaseReport { released: count, failed: 0 });
        assert_eq!(source.issued, count);
        assert_eq!(source.frees, count);
        for index in 0..count {
            assert_eq!(source.freed[index], (count - index) as u64 * 4096);
        }
    }
}

#[test]
fn bad_counts_reject_before_source_is_touched() {
    let mut source = MockFrames::with_ceiling(9);
    for requested in [0usize, 10, usize::MAX] {
        assert_eq!(
            FrameBatch::<_, 9>::acquire_count(&mut source, requested).err(),
            Some(AcquireError::InvalidCount { requested, capacity: 9 }),
        );
    }
    assert_eq!(source.issued, 0);
    assert_eq!(source.frees, 0);
}

#[test]
fn counted_mid_allocation_failure_releases_only_acquired_prefix() {
    for requested in [6usize, 7, 8, 9] {
        let mut source = MockFrames::with_ceiling(3);
        assert_eq!(
            FrameBatch::<_, 9>::acquire_count(&mut source, requested).err(),
            Some(AcquireError::Exhausted {
                acquired: 3,
                rollback: ReleaseReport { released: 3, failed: 0 },
            }),
        );
        assert_eq!(source.issued, 3);
        assert_eq!(&source.freed[..source.frees], &[12288, 8192, 4096]);
    }
}

#[test]
fn counted_early_drop_releases_only_live_frames_and_reports_failure() {
    let mut source = MockFrames::with_ceiling(9);
    {
        let batch = FrameBatch::<_, 9>::acquire_count(&mut source, 6)
            .unwrap_or_else(|_| panic!("counted allocation"));
        assert_eq!(batch.leased_frames().len(), 6);
    }
    assert_eq!(source.issued, 6);
    assert_eq!(source.frees, 6);
    assert_eq!(&source.freed[..6], &[24576, 20480, 16384, 12288, 8192, 4096]);

    let mut failing = MockFrames::with_ceiling(9);
    failing.fail_releases = true;
    let batch = FrameBatch::<_, 9>::acquire_count(&mut failing, 7)
        .unwrap_or_else(|_| panic!("counted allocation"));
    assert_eq!(batch.close(), ReleaseReport { released: 0, failed: 7 });
    assert_eq!(failing.frees, 7);
}

#[test]
fn adopted_external_pmm_frames_have_one_staged_owner_and_release_once() {
    for count in [6usize, 7, 8, 9] {
        let mut source = MockFrames::with_ceiling(9);
        let mut frames = [0u64; 9];
        for frame in &mut frames[..count] {
            *frame = source.allocate().unwrap();
        }
        // SAFETY: each address was freshly allocated from this exact source,
        // and the test gives up manual release on successful adoption.
        let batch = unsafe { FrameBatch::<_, 9>::adopt_allocated(&mut source, frames, count) }
            .unwrap_or_else(|_| panic!("valid PMM handoff"));
        assert_eq!(batch.leased_frames(), &frames[..count]);
        assert!(batch.frames()[count..].iter().all(|frame| *frame == 0));
        assert_eq!(batch.close(), ReleaseReport { released: count, failed: 0 });
        assert_eq!(source.issued, count); // adoption did not reallocate
        assert_eq!(source.frees, count);
        for index in 0..count {
            assert_eq!(source.freed[index], (count - index) as u64 * 4096);
        }
    }
}

#[test]
fn adopted_staged_scope_exit_rolls_back_exactly_once() {
    let mut source = MockFrames::with_ceiling(3);
    let frames = [source.allocate().unwrap(), source.allocate().unwrap(), 0];
    {
        // SAFETY: both issued allocations have exactly one owner after this
        // transfer; Drop must release them if publication never happens.
        let batch = unsafe { FrameBatch::<_, 3>::adopt_allocated(&mut source, frames, 2) }
            .unwrap_or_else(|_| panic!("adopt"));
        assert_eq!(batch.leased_frames(), &frames[..2]);
    }
    assert_eq!(source.issued, 2);
    assert_eq!(source.frees, 2);
    assert_eq!(&source.freed[..2], &[0x2000, 0x1000]);
}

#[test]
fn rejected_external_handoff_returns_descriptor_without_touching_provider() {
    let invalid: [(usize, [u64; 3], AdoptError); 9] = [
        (0, [0x1000, 0, 0], AdoptError::InvalidCount { requested: 0, capacity: 3 }),
        (4, [0x1000, 0x2000, 0], AdoptError::InvalidCount { requested: 4, capacity: 3 }),
        (1, [0, 0, 0], AdoptError::InvalidFrame { index: 0, frame: 0 }),
        (1, [0x1001, 0, 0], AdoptError::InvalidFrame { index: 0, frame: 0x1001 }),
        (1, [1 << 52, 0, 0], AdoptError::InvalidFrame { index: 0, frame: 1 << 52 }),
        (1, [u64::MAX, 0, 0], AdoptError::InvalidFrame { index: 0, frame: u64::MAX }),
        (2, [0x1000, 0x1000, 0], AdoptError::DuplicateFrame { index: 1, first_index: 0 }),
        (1, [0x1000, 0x2000, 0], AdoptError::NonzeroTail { index: 1, frame: 0x2000 }),
        (2, [0x1000, 0x2000, 0x3000], AdoptError::NonzeroTail { index: 2, frame: 0x3000 }),
    ];
    for (requested, frames, expected) in invalid {
        let mut source = MockFrames::with_ceiling(3);
        // SAFETY: rejected metadata is checked before ownership is formed;
        // the source is untouched and no rejected frame is ever released.
        let failure = unsafe { FrameBatch::<_, 3>::adopt_allocated(&mut source, frames, requested) };
        assert_eq!(failure.err().map(|(reason, returned)| (reason, returned)), Some((expected, frames)));
        assert_eq!(source.issued, 0);
        assert_eq!(source.frees, 0);
    }
}

#[test]
fn rejected_handoff_keeps_existing_frame_ownership_with_caller() {
    let mut source = MockFrames::with_ceiling(3);
    let first = source.allocate().unwrap();
    let second = source.allocate().unwrap();
    // SAFETY: the two valid PMM allocations remain caller-owned because the
    // invalid nonzero tail forces rejection before the guard is constructed.
    let (reason, returned) = unsafe {
        FrameBatch::<_, 3>::adopt_allocated(&mut source, [first, second, 0], 1)
    }.err().expect("reject nonzero tail");
    assert_eq!(reason, AdoptError::NonzeroTail { index: 1, frame: second });
    assert_eq!(returned, [first, second, 0]);
    assert_eq!(source.frees, 0);
    assert!(source.release(second));
    assert!(source.release(first));
    assert_eq!(source.frees, 2);
}
