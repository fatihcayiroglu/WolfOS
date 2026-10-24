//! Exact production ownership/ledger code with observable allocator effects.
#[path = "../kernel/src/active_address_space.rs"]
mod active_address_space;
#[path = "../kernel/src/ring3_context_retirement.rs"]
mod ring3_context_retirement;
#[path = "../kernel/src/ring3_runqueue.rs"]
mod ring3_runqueue;
#[path = "../kernel/src/saved_context_retirement.rs"]
mod saved_context_retirement;
#[path = "../kernel/src/address_space_retirement.rs"]
mod address_space_retirement;
#[path = "../kernel/src/pmm_frame_batch.rs"]
mod pmm_frame_batch;

use active_address_space::{ActiveAddressSpace, PublishError, ResumeError};
use saved_context_retirement::{Error as ContextError, Phase as ContextPhase};
use ring3_context_retirement::{Error as BindError, Ring3SavedBinding};
use ring3_runqueue::{Error as QueueError, Ring3RunQueue, State as QueueState};
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

#[test]
fn saved_context_blocks_retirement_and_frame_reclamation_until_verified_revocation() {
    let mut source = Source::new(&[0x1000, 0x2000]);
    let trace = source.trace.clone();
    let mut owner = publish::<2, 4>(&mut source, 0x1000);
    let context = owner.register_saved_context(4).unwrap();
    assert_eq!(owner.context_snapshot().pending, 1u64 << 4);
    owner.begin_retirement().unwrap();
    assert_eq!(owner.context_snapshot().phase, ContextPhase::Closing);
    assert_eq!(owner.finish_retirement(), Err(Error::OutstandingContexts));
    assert_eq!(
        owner.reserve_saved_resume(context, 2),
        Err(ResumeError::Context(ContextError::WrongPhase))
    );
    assert_eq!(owner.snapshot().reserved, 0);
    assert!(trace.borrow().releases.is_empty());
    owner = match reclaim(owner) {
        Err((owner, Error::WrongPhase)) => owner,
        _ => panic!("saved context allowed premature frame release"),
    };
    // SAFETY: synthetic host test never actually publishes a user frame,
    // dispatch queue, wakeup or CPU load; no external resumable users exist.
    unsafe { owner.revoke_saved_context(context) }.unwrap();
    assert_eq!(owner.context_snapshot().pending, 0);
    owner.finish_retirement().unwrap();
    assert_eq!(owner.context_snapshot().phase, ContextPhase::Closed);
    assert_eq!(
        reclaim(owner).ok(),
        Some(ReleaseReport { released: 2, failed: 0 })
    );
    assert_eq!(trace.borrow().releases, [0x2000, 0x1000]);
}

#[test]
fn stale_saved_slot_cannot_reserve_cpu_or_revoke_new_context() {
    let mut source = Source::new(&[0x1000]);
    let trace = source.trace.clone();
    let mut owner = publish::<1, 2>(&mut source, 0x1000);
    let stale = owner.register_saved_context(63).unwrap();
    assert_eq!(owner.register_saved_context(63), Err(ContextError::Busy));
    // SAFETY: host-only metadata, with no actual saved frame or queue users.
    unsafe { owner.revoke_saved_context(stale) }.unwrap();
    let fresh = owner.register_saved_context(63).unwrap();
    assert_ne!(stale, fresh);
    assert_eq!(
        owner.reserve_saved_resume(stale, 1),
        Err(ResumeError::Context(ContextError::StaleTicket))
    );
    assert_eq!(
        unsafe { owner.revoke_saved_context(stale) },
        Err(ContextError::StaleTicket)
    );
    assert_eq!(owner.snapshot().reserved, 0);
    assert_eq!(owner.context_snapshot().pending, 1u64 << 63);
    let cpu = owner.reserve_saved_resume(fresh, 1).unwrap();
    owner.confirm_active(cpu, 0x1000).unwrap();
    owner.begin_retirement().unwrap();
    assert_eq!(owner.finish_retirement(), Err(Error::OutstandingCpus));
    owner.acknowledge_quiescent(cpu, 0x9000).unwrap();
    assert_eq!(owner.finish_retirement(), Err(Error::OutstandingContexts));
    // SAFETY: host-only mock has no actual resumable scheduler context.
    unsafe { owner.revoke_saved_context(fresh) }.unwrap();
    owner.finish_retirement().unwrap();
    assert_eq!(
        reclaim(owner).ok(),
        Some(ReleaseReport { released: 1, failed: 0 })
    );
    assert_eq!(trace.borrow().releases, [0x1000]);
}

#[test]
fn retirement_closes_context_registration_and_cpu_resume_atomically() {
    let mut source = Source::new(&[0x1000]);
    let mut owner = publish::<1, 1>(&mut source, 0x1000);
    let context = owner.register_saved_context(0).unwrap();
    owner.begin_retirement().unwrap();
    let cpu_before = owner.snapshot();
    let context_before = owner.context_snapshot();
    assert_eq!(owner.register_saved_context(1), Err(ContextError::WrongPhase));
    assert_eq!(
        owner.reserve_saved_resume(context, 0),
        Err(ResumeError::Context(ContextError::WrongPhase))
    );
    assert_eq!(owner.snapshot(), cpu_before);
    assert_eq!(owner.context_snapshot(), context_before);
    assert_eq!(owner.begin_retirement(), Err(Error::WrongPhase));
    // SAFETY: host-only context ledger has no external saved CPU frame or queue.
    unsafe { owner.revoke_saved_context(context) }.unwrap();
    owner.finish_retirement().unwrap();
    assert_eq!(reclaim(owner).ok(), Some(ReleaseReport { released: 1, failed: 0 }));
}

#[test]
fn bound_event_wake_cannot_resurrect_a_retiring_saved_process() {
    let mut source = Source::new(&[0x1000, 0x2000]);
    let trace = source.trace.clone();
    let mut owner = publish::<2, 2>(&mut source, 0x1000);
    let mut queue = Ring3RunQueue::<2>::new();
    let blocked = queue.admit(41).unwrap();
    let peer = queue.admit(42).unwrap();
    assert_eq!(queue.start_next(), Ok(blocked));
    let (next, wait) = queue.block_current_for_event(blocked, 0xabc).unwrap();
    assert_eq!(next, Some(peer));
    let binding = Ring3SavedBinding::attach(&mut owner, &queue, blocked, 3).unwrap();
    assert_eq!(owner.context_snapshot().pending, 1 << 3);
    owner.begin_retirement().unwrap();
    let before = queue;
    assert_eq!(
        binding.wake_for_event(&mut queue, &owner, wait, 0xabc),
        Err(BindError::Context(ContextError::WrongPhase))
    );
    assert_eq!(queue, before);
    assert_eq!(owner.finish_retirement(), Err(Error::OutstandingContexts));
    assert!(trace.borrow().releases.is_empty());
    // SAFETY: host simulation has no real Ring3 frame, timer, pending IPI,
    // wakeup, or hardware load; only the queue metadata above exists.
    unsafe { binding.cancel(&mut queue, &mut owner) }.unwrap();
    assert!(queue.slots().iter().any(|s| s.handle == blocked && s.state == QueueState::Exited));
    assert_eq!(queue.wake_for_event(wait, 0xabc), Err(QueueError::WrongState));
    assert_eq!(owner.context_snapshot().pending, 0);
    owner.finish_retirement().unwrap();
    assert_eq!(reclaim(owner).ok(), Some(ReleaseReport { released: 2, failed: 0 }));
    assert_eq!(trace.borrow().releases, [0x2000, 0x1000]);
}

#[test]
fn bound_dispatch_stages_queue_until_exact_selected_handle_is_authorized() {
    let mut source = Source::new(&[0x1000]);
    let mut owner = publish::<1, 2>(&mut source, 0x1000);
    let mut queue = Ring3RunQueue::<2>::new();
    let earlier = queue.admit(77).unwrap();
    let selected = queue.admit(88).unwrap();
    let binding = Ring3SavedBinding::attach(&mut owner, &queue, selected, 0).unwrap();
    let before = queue;
    assert_eq!(
        binding.start_next(&mut queue, &mut owner, 1),
        Err(BindError::WrongHandle)
    );
    assert_eq!(queue, before);
    assert_eq!(owner.snapshot().reserved, 0);
    queue.cancel(earlier).unwrap();
    let cpu = binding.start_next(&mut queue, &mut owner, 1).unwrap();
    assert_eq!(queue.running(), Some(selected));
    assert_eq!(owner.snapshot().reserved, 0b10);
    owner.confirm_active(cpu, 0x1000).unwrap();
    owner.begin_retirement().unwrap();
    owner.acknowledge_quiescent(cpu, 0x9000).unwrap();
    assert_eq!(owner.finish_retirement(), Err(Error::OutstandingContexts));
    queue.exit_current(selected).unwrap();
    // SAFETY: host mock has no actual saved user frame, queue reader,
    // wakeup, in-flight CPU load, or DMA user. Owner CPU was acknowledged.
    unsafe { binding.retire_exited(&queue, &mut owner) }.unwrap();
    owner.finish_retirement().unwrap();
    assert_eq!(reclaim(owner).ok(), Some(ReleaseReport { released: 1, failed: 0 }));
}

#[test]
fn busy_cpu_cannot_partially_commit_a_bound_queue_dispatch() {
    let mut source = Source::new(&[0x1000]);
    let mut owner = publish::<1, 1>(&mut source, 0x1000);
    let mut queue = Ring3RunQueue::<1>::new();
    let handle = queue.admit(17).unwrap();
    let binding = Ring3SavedBinding::attach(&mut owner, &queue, handle, 1).unwrap();
    let preexisting = owner.reserve_cpu(0).unwrap();
    let original = queue;
    assert_eq!(
        binding.start_next(&mut queue, &mut owner, 0),
        Err(BindError::Reserve(active_address_space::ResumeError::Cpu(Error::CpuBusy)))
    );
    assert_eq!(queue, original);
    owner.acknowledge_quiescent(preexisting, 0x9000).unwrap();
    let cpu = binding.start_next(&mut queue, &mut owner, 0).unwrap();
    assert_eq!(queue.running(), Some(handle));
    owner.begin_retirement().unwrap();
    owner.acknowledge_quiescent(cpu, 0x9000).unwrap();
    queue.exit_current(handle).unwrap();
    // SAFETY: isolated mock has no real saved frame, wakeup or CPU load.
    unsafe { binding.retire_exited(&queue, &mut owner) }.unwrap();
    owner.finish_retirement().unwrap();
    assert_eq!(reclaim(owner).ok(), Some(ReleaseReport { released: 1, failed: 0 }));
}
