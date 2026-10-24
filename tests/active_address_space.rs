//! Exact production ownership/ledger code with observable allocator effects.
#[path = "../kernel/src/active_address_space.rs"]
mod active_address_space;
#[path = "../kernel/src/address_space_retirement.rs"]
mod address_space_retirement;
#[path = "../kernel/src/pmm_frame_batch.rs"]
mod pmm_frame_batch;

use active_address_space::{ActiveAddressSpace, PublishError};
use address_space_retirement::{Error, Phase};
use pmm_frame_batch::{FrameBatch, FrameSource, ReleaseReport};
use std::{cell::RefCell, collections::BTreeSet, rc::Rc};

#[derive(Default)]
struct Trace {
    owned: BTreeSet<u64>,
    releases: Vec<u64>,
    fail: Option<u64>,
}

struct Source {
    next: std::vec::IntoIter<u64>,
    trace: Rc<RefCell<Trace>>,
}

impl Source {
    fn new(frames: &[u64]) -> Self {
        Self {
            next: frames.to_vec().into_iter(),
            trace: Rc::default(),
        }
    }
}

impl FrameSource for Source {
    fn allocate(&mut self) -> Option<u64> {
        let frame = self.next.next()?;
        self.trace.borrow_mut().owned.insert(frame);
        Some(frame)
    }
    fn release(&mut self, frame: u64) -> bool {
        let mut trace = self.trace.borrow_mut();
        trace.releases.push(frame);
        if trace.fail == Some(frame) {
            return false;
        }
        trace.owned.remove(&frame)
    }
}

fn publish<const N: usize, const C: usize>(
    source: &mut Source,
    root: u64,
) -> ActiveAddressSpace<'_, Source, N, C> {
    let batch = FrameBatch::acquire(source).unwrap_or_else(|_| panic!("allocate"));
    ActiveAddressSpace::publish(batch, 7, root, 0x9000).unwrap_or_else(|_| panic!("publish"))
}

// No host CPU loads these synthetic roots or publishes saved contexts.
fn reclaim<const N: usize, const C: usize>(
    owner: ActiveAddressSpace<'_, Source, N, C>,
) -> Result<ReleaseReport, (ActiveAddressSpace<'_, Source, N, C>, Error)> {
    unsafe { owner.reclaim() }
}

#[test]
fn transfer_and_live_drop_never_call_allocator_release() {
    let mut source = Source::new(&[0x1000, 0x2000, 0x3000]);
    let trace = source.trace.clone();
    let mut owner = publish::<3, 4>(&mut source, 0x2000);
    assert_eq!(owner.frames(), &[0x1000, 0x2000, 0x3000]);
    let ticket = owner.reserve_cpu(3).unwrap();
    owner.confirm_active(ticket, 0x2000).unwrap();
    drop(owner);
    assert!(trace.borrow().releases.is_empty());
    assert_eq!(trace.borrow().owned.len(), 3);
}

#[test]
fn pending_retiring_and_retired_drop_all_retain_frames() {
    for phase in 0..3 {
        let mut source = Source::new(&[0x1000]);
        let trace = source.trace.clone();
        let mut owner = publish::<1, 1>(&mut source, 0x1000);
        let ticket = owner.reserve_cpu(0).unwrap();
        if phase >= 1 {
            owner.begin_retirement().unwrap();
        }
        if phase == 2 {
            owner.acknowledge_quiescent(ticket, 0x9000).unwrap();
            owner.finish_retirement().unwrap();
        }
        drop(owner);
        assert!(trace.borrow().releases.is_empty());
        assert_eq!(trace.borrow().owned.len(), 1);
    }
}

#[test]
fn failed_publication_returns_original_staging_owner() {
    for (generation, root, supervisor, expected) in [
        (
            0,
            0x1000,
            0x9000,
            PublishError::Gate(Error::InvalidIdentity),
        ),
        (7, 0x1001, 0x9000, PublishError::Gate(Error::InvalidRoot)),
        (7, 0x4000, 0x9000, PublishError::RootNotOwned),
        (7, 0x1000, 0x2000, PublishError::SupervisorOwned),
    ] {
        let mut source = Source::new(&[0x1000, 0x2000]);
        let trace = source.trace.clone();
        let batch = FrameBatch::<_, 2>::acquire(&mut source).unwrap_or_else(|_| panic!());
        let (batch, error) =
            match ActiveAddressSpace::<_, 2, 4>::publish(batch, generation, root, supervisor) {
                Err(failure) => failure,
                Ok(_) => panic!("accepted invalid publication"),
            };
        assert_eq!(error, expected);
        assert_eq!(batch.frames(), &[0x1000, 0x2000]);
        assert!(trace.borrow().releases.is_empty());
        drop(batch);
        assert_eq!(trace.borrow().releases, [0x2000, 0x1000]);
        assert!(trace.borrow().owned.is_empty());
    }
}

#[test]
fn discarded_publication_failure_keeps_automatic_staging_rollback() {
    let mut source = Source::new(&[0x1000]);
    let trace = source.trace.clone();
    let batch = FrameBatch::<_, 1>::acquire(&mut source).unwrap_or_else(|_| panic!());
    drop(ActiveAddressSpace::<_, 1, 0>::publish(
        batch, 7, 0x1000, 0x9000,
    ));
    assert_eq!(trace.borrow().releases, [0x1000]);
    assert!(trace.borrow().owned.is_empty());
}

#[test]
fn malformed_provider_addresses_never_become_active() {
    for bad in [0, 0x1001, 1 << 52, u64::MAX, 0x1000] {
        // Fault injection: deliberately violate the source address contract.
        let mut source = Source::new(&[0x1000, bad]);
        let batch = FrameBatch::<_, 2>::acquire(&mut source).unwrap_or_else(|_| panic!());
        match ActiveAddressSpace::<_, 2, 1>::publish(batch, 7, 0x1000, 0x9000) {
            Err((batch, error)) => {
                assert_eq!(error, PublishError::InvalidFrames);
                drop(batch);
            }
            Ok(_) => panic!("accepted malformed batch"),
        }
    }
}

#[test]
fn empty_batch_cannot_own_a_root() {
    let mut source = Source::new(&[]);
    let batch = FrameBatch::<_, 0>::acquire(&mut source).unwrap_or_else(|_| panic!());
    match ActiveAddressSpace::<_, 0, 1>::publish(batch, 7, 0x1000, 0x9000) {
        Err((_, error)) => assert_eq!(error, PublishError::RootNotOwned),
        Ok(_) => panic!("empty owner"),
    }
}

#[test]
fn every_four_cpu_ack_order_pins_the_entire_batch_until_explicit_reclaim() {
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let order = [a, b, c, d];
                    if order
                        .iter()
                        .enumerate()
                        .any(|(i, cpu)| order[..i].contains(cpu))
                    {
                        continue;
                    }
                    let mut source = Source::new(&[0x1000, 0x2000, 0x3000, 0x4000]);
                    let trace = source.trace.clone();
                    let mut owner = publish::<4, 4>(&mut source, 0x2000);
                    let tickets = core::array::from_fn::<_, 4, _>(|cpu| {
                        let ticket = owner.reserve_cpu(cpu).unwrap();
                        owner.confirm_active(ticket, 0x2000).unwrap();
                        ticket
                    });
                    owner.begin_retirement().unwrap();
                    for cpu in order {
                        assert_eq!(owner.finish_retirement(), Err(Error::OutstandingCpus));
                        let before = owner.snapshot();
                        owner = match reclaim(owner) {
                            Err((owner, error)) => {
                                assert_eq!(error, Error::WrongPhase);
                                owner
                            }
                            Ok(_) => panic!("premature release"),
                        };
                        assert_eq!(owner.snapshot(), before);
                        assert!(trace.borrow().releases.is_empty());
                        assert_eq!(trace.borrow().owned.len(), 4);
                        owner.acknowledge_quiescent(tickets[cpu], 0x9000).unwrap();
                    }
                    owner.finish_retirement().unwrap();
                    assert_eq!(owner.snapshot().phase, Phase::Retired);
                    assert!(trace.borrow().releases.is_empty());
                    assert_eq!(
                        reclaim(owner).ok(),
                        Some(ReleaseReport {
                            released: 4,
                            failed: 0
                        })
                    );
                    assert_eq!(trace.borrow().releases, [0x4000, 0x3000, 0x2000, 0x1000]);
                    assert!(trace.borrow().owned.is_empty());
                }
            }
        }
    }
}

#[test]
fn retirement_racing_a_load_and_stale_ack_cannot_unpin_frames() {
    let mut source = Source::new(&[0x1000, 0x2000]);
    let trace = source.trace.clone();
    let mut owner = publish::<2, 2>(&mut source, 0x1000);
    let old = owner.reserve_cpu(0).unwrap();
    owner.acknowledge_quiescent(old, 0x9000).unwrap();
    let late = owner.reserve_cpu(0).unwrap();
    let peer = owner.reserve_cpu(1).unwrap();
    owner.confirm_active(peer, 0x1000).unwrap();
    owner.begin_retirement().unwrap();
    let before = owner.snapshot();
    assert_eq!(owner.confirm_active(late, 0x1000), Err(Error::WrongPhase));
    assert_eq!(
        owner.acknowledge_quiescent(old, 0x9000),
        Err(Error::StaleTicket)
    );
    assert_eq!(
        owner.acknowledge_quiescent(late, 0x1000),
        Err(Error::WrongCr3)
    );
    assert_eq!(owner.snapshot(), before);
    owner.acknowledge_quiescent(peer, 0x9000).unwrap();
    assert_eq!(owner.finish_retirement(), Err(Error::OutstandingCpus));
    assert!(trace.borrow().releases.is_empty());
    owner.acknowledge_quiescent(late, 0x9000).unwrap();
    owner.finish_retirement().unwrap();
    assert_eq!(
        reclaim(owner).ok(),
        Some(ReleaseReport {
            released: 2,
            failed: 0
        })
    );
}

#[test]
fn release_failures_are_reported_once_without_destructor_retry() {
    let mut source = Source::new(&[0x1000, 0x2000, 0x3000]);
    let trace = source.trace.clone();
    trace.borrow_mut().fail = Some(0x2000);
    let mut owner = publish::<3, 1>(&mut source, 0x1000);
    owner.begin_retirement().unwrap();
    owner.finish_retirement().unwrap();
    assert_eq!(
        reclaim(owner).ok(),
        Some(ReleaseReport {
            released: 2,
            failed: 1
        })
    );
    assert_eq!(trace.borrow().releases, [0x3000, 0x2000, 0x1000]);
    assert_eq!(
        trace.borrow().owned.iter().copied().collect::<Vec<_>>(),
        [0x2000]
    );
}

#[test]
fn ownership_preserves_physical_addresses_above_64_gib() {
    let root = (1 << 36) + 4096;
    let mut source = Source::new(&[root, root + 4096]);
    let trace = source.trace.clone();
    let mut owner = publish::<2, 64>(&mut source, root);
    let ticket = owner.reserve_cpu(63).unwrap();
    owner.confirm_active(ticket, root).unwrap();
    owner.begin_retirement().unwrap();
    owner.acknowledge_quiescent(ticket, 0x9000).unwrap();
    owner.finish_retirement().unwrap();
    assert_eq!(
        reclaim(owner).ok(),
        Some(ReleaseReport {
            released: 2,
            failed: 0
        })
    );
    assert_eq!(trace.borrow().releases, [root + 4096, root]);
}
