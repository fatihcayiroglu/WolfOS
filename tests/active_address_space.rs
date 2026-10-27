//! Exact production ownership/ledger code with observable allocator effects.
#[path = "../kernel/src/active_address_space.rs"]
mod active_address_space;
#[path = "../kernel/src/ring3_context_retirement.rs"]
mod ring3_context_retirement;
#[path = "../kernel/src/ring3_runqueue.rs"]
mod ring3_runqueue;
#[path = "../kernel/src/process_table.rs"]
mod process_table;
#[path = "../kernel/src/saved_context_retirement.rs"]
mod saved_context_retirement;
#[path = "../kernel/src/address_space_retirement.rs"]
mod address_space_retirement;
#[path = "../kernel/src/tlb_shootdown.rs"]
mod tlb_shootdown;
#[path = "../kernel/src/retirement_tlb_round.rs"]
mod retirement_tlb_round;
#[path = "../kernel/src/pmm_frame_batch.rs"]
mod pmm_frame_batch;

use active_address_space::{ActiveAddressSpace, PublishError, ResumeError};
use saved_context_retirement::{Error as ContextError, Phase as ContextPhase};
use ring3_context_retirement::{Error as BindError, Ring3SavedBinding};
use ring3_runqueue::{Error as QueueError, Ring3RunQueue, State as QueueState};
use address_space_retirement::{Error, Phase};
use pmm_frame_batch::{FrameBatch, FrameSource, ReleaseReport};
use process_table::ProcessTable;
use retirement_tlb_round::Error as RoundError;
use tlb_shootdown::{Error as BarrierError, Phase as BarrierPhase, ShootdownBarrier};
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
                    // This is a host-only metadata simulation: the CPUs
                    // above did not execute real CR3 writes or TLB flushes.
                    // Multi-CPU history cannot use the legacy close path.
                    assert_eq!(owner.finish_retirement(), Err(Error::OutstandingShootdown));
                    assert_eq!(owner.snapshot().phase, Phase::Retiring);
                    assert!(trace.borrow().releases.is_empty());
                    let mut barrier = ShootdownBarrier::<4>::new(7).unwrap();
                    let round = owner.begin_retirement_shootdown(&mut barrier, 0b1111).unwrap();
                    for cpu in order {
                        unsafe { barrier.acknowledge_after_local_flush(round, cpu).unwrap() };
                    }
                    assert_eq!(owner.finish_retirement_after_shootdown(&barrier, round), Ok(()));
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
    assert_eq!(owner.finish_retirement(), Err(Error::OutstandingShootdown));
    assert_eq!(owner.snapshot().phase, Phase::Retiring);
    assert!(trace.borrow().releases.is_empty());
    let mut barrier = ShootdownBarrier::<2>::new(7).unwrap();
    // Even the unconfirmed, racing load's CPU must be in the target set.
    assert_eq!(
        owner.begin_retirement_shootdown(&mut barrier, 0b10),
        Err(RoundError::Shootdown(BarrierError::MissingRequiredTargets)),
    );
    let round = owner.begin_retirement_shootdown(&mut barrier, 0b11).unwrap();
    // Simulated host acknowledgements; actual per-CPU TLB flushes are the
    // separate responsibility of the QEMU hardware path.
    unsafe { barrier.acknowledge_after_local_flush(round, 1).unwrap() };
    assert_eq!(
        owner.finish_retirement_after_shootdown(&barrier, round),
        Err(Error::OutstandingShootdown),
    );
    assert!(trace.borrow().releases.is_empty());
    unsafe { barrier.acknowledge_after_local_flush(round, 0).unwrap() };
    assert_eq!(owner.finish_retirement_after_shootdown(&barrier, round), Ok(()));
    assert_eq!(
        reclaim(owner).ok(),
        Some(ReleaseReport {
            released: 2,
            failed: 0
        })
    );
}

#[test]
fn a_reused_single_cpu_remains_one_historical_target() {
    // Host-only ledger validation. Reuse by the same CPU is not multicore
    // history; it still requires separate hardware proof for unsafe reclaim.
    let mut source = Source::new(&[0x1000]);
    let trace = source.trace.clone();
    let mut owner = publish::<1, 4>(&mut source, 0x1000);
    for _ in 0..3 {
        let ticket = owner.reserve_cpu(3).unwrap();
        owner.confirm_active(ticket, 0x1000).unwrap();
        owner.acknowledge_quiescent(ticket, 0x9000).unwrap();
    }
    owner.begin_retirement().unwrap();
    assert_eq!(owner.finish_retirement(), Ok(()));
    assert_eq!(reclaim(owner).ok(), Some(ReleaseReport { released: 1, failed: 0 }));
    assert_eq!(trace.borrow().releases, [0x1000]);
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

#[test]
fn bound_running_event_park_publishes_only_after_exact_cpu_quiescence() {
    let mut source = Source::new(&[0x1000]);
    let trace = source.trace.clone();
    let mut owner = publish::<1, 1>(&mut source, 0x1000);
    let mut queue = Ring3RunQueue::<1>::new();
    let handle = queue.admit(901).unwrap();
    let binding = Ring3SavedBinding::attach(&mut owner, &queue, handle, 5).unwrap();
    let cpu = binding.start_next(&mut queue, &mut owner, 0).unwrap();
    owner.confirm_active(cpu, 0x1000).unwrap();

    let original = queue;
    assert_eq!(
        unsafe { binding.park_for_event(&mut queue, &mut owner, cpu, 0x1000, 0xbad) },
        Err(BindError::Quiesce(Error::WrongCr3))
    );
    assert_eq!(queue, original);
    assert_eq!(owner.snapshot().active, 1);
    assert_eq!(
        unsafe { binding.park_for_event(&mut queue, &mut owner, cpu, 0x9000, 0) },
        Err(BindError::Queue(QueueError::InvalidEvent))
    );
    assert_eq!(queue, original);
    assert_eq!(owner.snapshot().active, 1);

    // SAFETY: host-only simulation, without a real CPL3 frame, event
    // registration or CR3 load. The synthetic token models completed
    // authenticated trap save and supervisor-root restoration.
    let (selected, wait) = unsafe {
        binding.park_for_event(&mut queue, &mut owner, cpu, 0x9000, 0xbad)
    }.unwrap();
    assert_eq!(selected, None);
    assert_eq!(owner.snapshot().active, 0);
    assert_eq!(owner.context_snapshot().pending, 1u64 << 5);
    assert_eq!(queue.running(), None);
    assert!(queue.slots().iter().any(|s| s.handle == handle && s.state == QueueState::Blocked));
    assert_eq!(queue.wake_for_event(wait, 0xbee), Err(QueueError::WrongEvent));
    assert_eq!(binding.wake_for_event(&mut queue, &owner, wait, 0xbad), Ok(()));
    let resumed = binding.start_next(&mut queue, &mut owner, 0).unwrap();
    owner.confirm_active(resumed, 0x1000).unwrap();
    owner.begin_retirement().unwrap();
    owner.acknowledge_quiescent(resumed, 0x9000).unwrap();
    queue.exit_current(handle).unwrap();
    // SAFETY: isolated host metadata has no actual saved frame, IRQ,
    // queued wakeup, external hardware load or DMA reference.
    unsafe { binding.retire_exited(&queue, &mut owner) }.unwrap();
    owner.finish_retirement().unwrap();
    assert_eq!(reclaim(owner).ok(), Some(ReleaseReport { released: 1, failed: 0 }));
    assert_eq!(trace.borrow().releases, [0x1000]);
}

#[test]
fn foreign_cpu_ticket_or_retiring_owner_never_commits_bound_block() {
    let mut source = Source::new(&[0x1000]);
    let mut owner = publish::<1, 1>(&mut source, 0x1000);
    let mut foreign_source = Source::new(&[0x2000]);
    let mut foreign_owner = publish::<1, 1>(&mut foreign_source, 0x2000);
    let foreign_cpu = foreign_owner.reserve_cpu(0).unwrap();
    let mut queue = Ring3RunQueue::<1>::new();
    let handle = queue.admit(902).unwrap();
    let binding = Ring3SavedBinding::attach(&mut owner, &queue, handle, 6).unwrap();
    let cpu = binding.start_next(&mut queue, &mut owner, 0).unwrap();
    owner.confirm_active(cpu, 0x1000).unwrap();
    let before = queue;
    assert_eq!(
        unsafe { binding.park_for_event(&mut queue, &mut owner, foreign_cpu, 0x9000, 0xaaa) },
        Err(BindError::Quiesce(Error::StaleTicket))
    );
    assert_eq!(queue, before);
    assert_eq!(owner.snapshot().active, 1);
    // A separate owner cannot use its ticket to quiesce this task.
    assert_eq!(foreign_owner.snapshot().reserved, 1);

    owner.begin_retirement().unwrap();
    assert_eq!(
        unsafe { binding.park_for_event(&mut queue, &mut owner, cpu, 0x9000, 0xaaa) },
        Err(BindError::Context(ContextError::WrongPhase))
    );
    assert_eq!(queue, before);
    assert_eq!(owner.snapshot().active, 1);
    assert_eq!(owner.context_snapshot().pending, 1u64 << 6);
    owner.acknowledge_quiescent(cpu, 0x9000).unwrap();
    queue.exit_current(handle).unwrap();
    // SAFETY: no Ring3 frame, event source, timer wake, in-flight CPU
    // handoff, private CR3 load, or external frame users exist in this test.
    unsafe { binding.retire_exited(&queue, &mut owner) }.unwrap();
    owner.finish_retirement().unwrap();
    assert_eq!(reclaim(owner).ok(), Some(ReleaseReport { released: 1, failed: 0 }));
    foreign_owner.acknowledge_quiescent(foreign_cpu, 0x9000).unwrap();
    foreign_owner.begin_retirement().unwrap();
    foreign_owner.finish_retirement().unwrap();
    assert_eq!(reclaim(foreign_owner).ok(), Some(ReleaseReport { released: 1, failed: 0 }));
}

#[test]
fn registry_bound_admission_matches_exact_pid_root_and_pmm_lease() {
    let mut source = Source::new(&[0x1000, 0x2000]);
    let trace = source.trace.clone();
    let staged = FrameBatch::<_, 2>::acquire(&mut source).unwrap();
    let mut owner = ActiveAddressSpace::<_, 2, 1>::publish(staged, 1, 0x1000, 0x9000).unwrap_or_else(|_| panic!("publish"));
    let mut registry = ProcessTable::<1, 2>::new();
    let pid = registry.reserve(0x1000, [0x1000, 0x2000]).unwrap();
    assert_eq!(pid, 1);
    let mut queue = Ring3RunQueue::<1>::new();
    let handle = queue.admit(pid).unwrap();
    let bound = Ring3SavedBinding::attach_from_process_table(
        &mut owner, &registry, &queue, handle, 9
    ).unwrap();
    assert_eq!(owner.context_snapshot().pending, 1 << 9);
    assert_eq!(queue.running(), None);
    // SAFETY: this host-only metadata fixture has no real user frame,
    // registered event source, pending handoff, AP or CR3 hardware load.
    unsafe { bound.cancel(&mut queue, &mut owner) }.unwrap();
    assert_eq!(registry.cancel_ready(pid, 0x9000).unwrap(), [0x1000, 0x2000]);
    owner.begin_retirement().unwrap();
    owner.finish_retirement().unwrap();
    assert_eq!(reclaim(owner).ok(), Some(ReleaseReport { released: 2, failed: 0 }));
    assert_eq!(trace.borrow().releases, [0x2000, 0x1000]);
}

#[test]
fn registry_bound_admission_rejects_wrong_state_stale_handle_and_wrong_owner() {
    let mut source = Source::new(&[0x1000, 0x2000]);
    let staged = FrameBatch::<_, 2>::acquire(&mut source).unwrap();
    let mut owner = ActiveAddressSpace::<_, 2, 1>::publish(staged, 1, 0x1000, 0x9000).unwrap_or_else(|_| panic!("publish"));
    let mut registry = ProcessTable::<1, 2>::new();
    let pid = registry.reserve(0x1000, [0x1000, 0x2000]).unwrap();
    let mut queue = Ring3RunQueue::<1>::new();
    let handle = queue.admit(pid).unwrap();

    let forged = ring3_runqueue::Handle { pid, generation: handle.generation + 1 };
    assert!(matches!(
        Ring3SavedBinding::attach_from_process_table(&mut owner, &registry, &queue, forged, 0),
        Err(BindError::StaleHandle)
    ));
    assert_eq!(owner.context_snapshot().pending, 0);
    assert_eq!(queue.start_next(), Ok(handle));
    assert_eq!(queue.block_current(handle), Ok(None));
    assert_eq!(
        Ring3SavedBinding::attach_from_process_table(&mut owner, &registry, &queue, handle, 0),
        Err(BindError::RegistryMismatch)
    );
    assert_eq!(owner.context_snapshot().pending, 0);
    registry.mark_running(pid, 0x1000).unwrap();
    registry.block_running(pid, 0x1000).unwrap();
    let valid = Ring3SavedBinding::attach_from_process_table(
        &mut owner, &registry, &queue, handle, 0
    ).unwrap();
    assert_eq!(owner.context_snapshot().pending, 1);
    // SAFETY: no real saved frames, IRQ wakeups or hardware users exist.
    unsafe { valid.cancel(&mut queue, &mut owner) }.unwrap();
    assert_eq!(registry.cancel_blocked(pid, 0x9000).unwrap(), [0x1000, 0x2000]);
    owner.begin_retirement().unwrap();
    owner.finish_retirement().unwrap();
    assert_eq!(reclaim(owner).ok(), Some(ReleaseReport { released: 2, failed: 0 }));

    // An exact process table cannot be paired with either a copied owner
    // from a different PID generation or a different set of physical pages.
    for (generation, frames) in [
        (2, [0x1000, 0x2000]),
        (1, [0x1000, 0x3000]),
    ] {
        let mut other_source = Source::new(&frames);
        let batch = FrameBatch::<_, 2>::acquire(&mut other_source).unwrap();
        let mut other_owner = ActiveAddressSpace::<_, 2, 1>::publish(
            batch, generation, 0x1000, 0x9000
        ).unwrap_or_else(|_| panic!("publish"));
        let mut other_registry = ProcessTable::<1, 2>::new();
        let other_pid = other_registry.reserve(0x1000, [0x1000, 0x2000]).unwrap();
        let mut other_queue = Ring3RunQueue::<1>::new();
        let other_handle = other_queue.admit(other_pid).unwrap();
        let snapshot = other_queue;
        assert_eq!(
            Ring3SavedBinding::attach_from_process_table(
                &mut other_owner, &other_registry, &other_queue, other_handle, 63
            ),
            Err(BindError::OwnerMismatch)
        );
        assert_eq!(other_queue, snapshot);
        assert_eq!(other_owner.context_snapshot().pending, 0);
        other_owner.begin_retirement().unwrap();
        other_owner.finish_retirement().unwrap();
        assert_eq!(reclaim(other_owner).ok(), Some(ReleaseReport { released: 2, failed: 0 }));
    }
}

#[test]
fn counted_registry_binding_accepts_exact_pmm_prefixes_without_padding() {
    for count in [6usize, 7, 8, 9] {
        let addresses: [u64; 9] = core::array::from_fn(|i| (i as u64 + 1) * 4096);
        let mut source = Source::new(&addresses);
        let trace = source.trace.clone();
        let batch = FrameBatch::<_, 9>::acquire_count(&mut source, count).unwrap();
        let mut owner = ActiveAddressSpace::<_, 9, 1>::publish(
            batch, 1, addresses[0], 0xf000,
        ).unwrap_or_else(|_| panic!("counted publish"));
        let padded = *owner.frames();
        assert!(owner.matches_process_lease_counted(1, addresses[0], &addresses[..count]));
        assert!(!owner.matches_process_lease_counted(2, addresses[0], &addresses[..count]));
        assert!(!owner.matches_process_lease_counted(1, addresses[0], &addresses[..count - 1]));
        assert_eq!(
            owner.matches_process_lease_counted(1, addresses[0], &padded),
            count == 9,
        );
        if count == 9 {
            assert!(owner.matches_process_lease(1, addresses[0], &padded));
        } else {
            assert!(!owner.matches_process_lease(1, addresses[0], &padded));
        }

        let mut registry = ProcessTable::<1, 9>::new();
        let pid = registry.reserve_counted(addresses[0], padded, count).unwrap();
        assert_eq!(pid, 1);
        let mut queue = Ring3RunQueue::<1>::new();
        let handle = queue.admit(pid).unwrap();
        let binding = Ring3SavedBinding::attach_from_process_table(
            &mut owner, &registry, &queue, handle, 9,
        ).unwrap();
        assert_eq!(owner.context_snapshot().pending, 1 << 9);
        // SAFETY: isolated host metadata does not publish a real user frame,
        // CPU load, interrupt, event source, or external queued handoff.
        unsafe { binding.cancel(&mut queue, &mut owner) }.unwrap();
        assert_eq!(owner.context_snapshot().pending, 0);
        let lease = registry.cancel_ready_counted(pid, 0xf000).unwrap();
        assert_eq!(lease.count, count);
        assert_eq!(lease.as_slice(), &addresses[..count]);
        owner.begin_retirement().unwrap();
        owner.finish_retirement().unwrap();
        assert_eq!(reclaim(owner).ok(),
                   Some(ReleaseReport { released: count, failed: 0 }));
        let observed = trace.borrow();
        assert!(observed.owned.is_empty());
        assert_eq!(observed.releases.len(), count);
    }
}

#[test]
fn counted_binding_rejects_wrong_count_root_and_generation_without_context_pin() {
    let addresses: [u64; 9] = core::array::from_fn(|i| (i as u64 + 1) * 4096);
    let mut source = Source::new(&addresses);
    let batch = FrameBatch::<_, 9>::acquire_count(&mut source, 8).unwrap();
    let mut owner = ActiveAddressSpace::<_, 9, 1>::publish(
        batch, 1, addresses[0], 0xf000,
    ).unwrap_or_else(|_| panic!("counted publish"));
    let mut queue = Ring3RunQueue::<1>::new();
    let handle = queue.admit(1).unwrap();
    for count in [6usize, 7, 9] {
        let padded: [u64; 9] =
            core::array::from_fn(|i| if i < count { addresses[i] } else { 0 });
        let mut registry = ProcessTable::<1, 9>::new();
        assert_eq!(registry.reserve_counted(addresses[0], padded, count), Ok(1));
        let before = (owner.context_snapshot(), queue);
        assert_eq!(
            Ring3SavedBinding::attach_from_process_table(
                &mut owner, &registry, &queue, handle, 1,
            ),
            Err(BindError::OwnerMismatch),
        );
        assert_eq!((owner.context_snapshot(), queue), before);
    }
    // Correct count but wrong root/order or generation must also fail closed.
    for (root, frames, count) in [
        (addresses[1], {
            let mut frames = *owner.frames();
            frames[0] = addresses[1];
            frames[1] = addresses[0];
            frames
        }, 8usize),
    ] {
        let mut registry = ProcessTable::<1, 9>::new();
        assert_eq!(registry.reserve_counted(root, frames, count), Ok(1));
        assert_eq!(
            Ring3SavedBinding::attach_from_process_table(
                &mut owner, &registry, &queue, handle, 1,
            ),
            Err(BindError::OwnerMismatch),
        );
    }
    assert!(!owner.matches_process_lease_counted(2, addresses[0], owner.leased_frames()));
    let mut stale_registry = ProcessTable::<1, 9>::new();
    let padded = *owner.frames();
    let old_pid = stale_registry.reserve_counted(addresses[0], padded, 8).unwrap();
    assert_eq!(stale_registry.cancel_ready_counted(old_pid, 0xf000).unwrap().count, 8);
    assert_eq!(stale_registry.reserve_counted(addresses[0], padded, 8), Ok(2));
    assert_eq!(
        Ring3SavedBinding::attach_from_process_table(
            &mut owner, &stale_registry, &queue, handle, 1,
        ),
        Err(BindError::RegistryMismatch),
    );
    assert_eq!(owner.context_snapshot().pending, 0);
    owner.begin_retirement().unwrap();
    owner.finish_retirement().unwrap();
    assert_eq!(reclaim(owner).ok(),
               Some(ReleaseReport { released: 8, failed: 0 }));
}

#[test]
fn counted_blocked_binding_tracks_exact_lease_until_safe_cancel() {
    let addresses: [u64; 9] = core::array::from_fn(|i| (i as u64 + 1) * 4096);
    let mut source = Source::new(&addresses);
    let batch = FrameBatch::<_, 9>::acquire_count(&mut source, 7).unwrap();
    let mut owner = ActiveAddressSpace::<_, 9, 1>::publish(
        batch, 1, addresses[0], 0xf000,
    ).unwrap_or_else(|_| panic!("counted publish"));
    let mut registry = ProcessTable::<1, 9>::new();
    let pid = registry.reserve_counted(addresses[0], *owner.frames(), 7).unwrap();
    let mut queue = Ring3RunQueue::<1>::new();
    let handle = queue.admit(pid).unwrap();
    assert_eq!(queue.start_next(), Ok(handle));
    registry.mark_running(pid, addresses[0]).unwrap();
    registry.block_running(pid, addresses[0]).unwrap();
    assert_eq!(queue.block_current(handle), Ok(None));
    let binding = Ring3SavedBinding::attach_from_process_table(
        &mut owner, &registry, &queue, handle, 3,
    ).unwrap();
    assert_eq!(owner.context_snapshot().pending, 1 << 3);
    owner.begin_retirement().unwrap();
    assert_eq!(owner.finish_retirement(), Err(Error::OutstandingContexts));
    // SAFETY: host fixture holds no real saved user CPU/FX frame or IRQ wait.
    unsafe { binding.cancel(&mut queue, &mut owner) }.unwrap();
    let lease = registry.cancel_blocked_counted(pid, 0xf000).unwrap();
    assert_eq!(lease.as_slice(), &addresses[..7]);
    assert_eq!(owner.context_snapshot().pending, 0);
    owner.finish_retirement().unwrap();
    assert_eq!(reclaim(owner).ok(),
               Some(ReleaseReport { released: 7, failed: 0 }));
}

#[test]
fn counted_owner_publishes_only_budgeted_frames_and_reclaims_exact_count() {
    for count in [6usize, 7, 8, 9] {
        let addresses: [u64; 9] = core::array::from_fn(|i| (i as u64 + 1) * 4096);
        let mut source = Source::new(&addresses);
        let trace = source.trace.clone();
        let batch = FrameBatch::<_, 9>::acquire_count(&mut source, count)
            .unwrap_or_else(|_| panic!("counted batch"));
        assert_eq!(batch.leased_frames(), &addresses[..count]);
        let mut owner = ActiveAddressSpace::<_, 9, 1>::publish(
            batch, 7, addresses[0], 0xf000,
        ).unwrap_or_else(|_| panic!("counted publish"));
        assert_eq!(owner.leased_frames(), &addresses[..count]);
        assert!(owner.frames()[count..].iter().all(|frame| *frame == 0));
        // A legacy fixed-size process lease must never match a padded owner.
        assert_eq!(
            owner.matches_process_lease(7, addresses[0], owner.frames()),
            count == addresses.len(),
        );
        let cpu = owner.reserve_cpu(0).unwrap();
        owner.confirm_active(cpu, addresses[0]).unwrap();
        owner.begin_retirement().unwrap();
        assert_eq!(owner.finish_retirement(), Err(Error::OutstandingCpus));
        assert_eq!(trace.borrow().owned.len(), count);
        owner.acknowledge_quiescent(cpu, 0xf000).unwrap();
        owner.finish_retirement().unwrap();
        assert_eq!(reclaim(owner).ok(),
            Some(ReleaseReport { released: count, failed: 0 }));
        let observed = trace.borrow();
        assert!(observed.owned.is_empty());
        assert_eq!(observed.releases.len(), count);
        for i in 0..count {
            assert_eq!(observed.releases[i], addresses[count - 1 - i]);
        }
    }
}

#[test]
fn counted_publish_failure_preserves_exact_partial_lease_for_rollback() {
    let addresses: [u64; 9] = core::array::from_fn(|i| (i as u64 + 1) * 4096);
    let mut source = Source::new(&addresses);
    let trace = source.trace.clone();
    let batch = FrameBatch::<_, 9>::acquire_count(&mut source, 6)
        .unwrap_or_else(|_| panic!("counted batch"));
    // Frame 7 is outside the leased prefix, although the backing capacity is 9.
    let (batch, error) = match ActiveAddressSpace::<_, 9, 1>::publish(
        batch, 7, addresses[6], 0xf000,
    ) {
        Err(value) => value,
        Ok(_) => panic!("accepted unleased CR3 root"),
    };
    assert_eq!(error, PublishError::RootNotOwned);
    assert_eq!(batch.leased_frames(), &addresses[..6]);
    assert!(trace.borrow().releases.is_empty());
    assert_eq!(batch.close(), ReleaseReport { released: 6, failed: 0 });
    assert_eq!(trace.borrow().releases,
        [addresses[5], addresses[4], addresses[3],
         addresses[2], addresses[1], addresses[0]]);
    assert!(trace.borrow().owned.is_empty());
}

#[test]
fn owned_retirement_round_refuses_saved_contexts_and_missing_historical_cpus() {
    let mut source = Source::new(&[0x1000, 0x2000]);
    let trace = source.trace.clone();
    let mut owner = publish::<2, 4>(&mut source, 0x1000);
    for cpu in [1, 3] {
        let ticket = owner.reserve_cpu(cpu).unwrap();
        owner.confirm_active(ticket, 0x1000).unwrap();
        owner.acknowledge_quiescent(ticket, 0x9000).unwrap();
    }
    let saved = owner.register_saved_context(7).unwrap();
    owner.begin_retirement().unwrap();
    let mut barrier = ShootdownBarrier::<4>::new(7).unwrap();

    assert_eq!(
        owner.begin_retirement_shootdown(&mut barrier, 0b1010),
        Err(RoundError::OutstandingContexts),
    );
    assert_eq!(barrier.snapshot().phase, BarrierPhase::Ready);
    assert_eq!(barrier.snapshot().epoch, 0);
    // SAFETY: no actual CPU/FX/IRET frame or wakeup exists in this host fixture.
    unsafe { owner.revoke_saved_context(saved).unwrap() };
    assert_eq!(
        owner.begin_retirement_shootdown(&mut barrier, 0b1000),
        Err(RoundError::Shootdown(BarrierError::MissingRequiredTargets)),
    );
    assert_eq!(barrier.snapshot().epoch, 0);
    let round = owner.begin_retirement_shootdown(&mut barrier, 0b1011).unwrap();
    assert_eq!(barrier.snapshot().pending, 0b1011);
    // Simulated acknowledgements only; they do NOT prove hardware invalidation.
    unsafe { barrier.acknowledge_after_local_flush(round, 0).unwrap() };
    unsafe { barrier.acknowledge_after_local_flush(round, 3).unwrap() };
    assert!(!barrier.completed(round));
    assert_eq!(barrier.snapshot().pending, 0b0010);
    assert_eq!(trace.borrow().releases.len(), 0);
    unsafe { barrier.acknowledge_after_local_flush(round, 1).unwrap() };
    assert!(barrier.completed(round));
    // Never turn simulated acknowledgements into permission to reclaim PMM.
    drop(owner);
    assert!(trace.borrow().releases.is_empty());
    assert_eq!(trace.borrow().owned.len(), 2);
}

#[test]
fn owned_round_refuses_outstanding_cpu_and_wrong_generation_without_mutation() {
    let mut source = Source::new(&[0x1000]);
    let trace = source.trace.clone();
    let mut owner = publish::<1, 2>(&mut source, 0x1000);
    let ticket = owner.reserve_cpu(1).unwrap();
    let mut barrier = ShootdownBarrier::<2>::new(7).unwrap();
    assert_eq!(
        owner.begin_retirement_shootdown(&mut barrier, 0b10),
        Err(RoundError::NotRetiring),
    );
    owner.begin_retirement().unwrap();
    assert_eq!(
        owner.begin_retirement_shootdown(&mut barrier, 0b10),
        Err(RoundError::OutstandingCpus),
    );
    owner.acknowledge_quiescent(ticket, 0x9000).unwrap();
    let mut foreign = ShootdownBarrier::<2>::new(8).unwrap();
    assert_eq!(
        owner.begin_retirement_shootdown(&mut foreign, 0b10),
        Err(RoundError::WrongGeneration),
    );
    assert_eq!(foreign.snapshot().epoch, 0);
    assert_eq!(barrier.snapshot().epoch, 0);
    let round = owner.begin_retirement_shootdown(&mut barrier, 0b10).unwrap();
    assert!(!barrier.completed(round));
    drop(owner);
    assert!(trace.borrow().releases.is_empty());
    assert_eq!(trace.borrow().owned.len(), 1);
}

#[test]
fn owned_round_cannot_start_for_never_used_or_already_retired_owner() {
    let mut source = Source::new(&[0x1000]);
    let trace = source.trace.clone();
    let mut owner = publish::<1, 2>(&mut source, 0x1000);
    let mut barrier = ShootdownBarrier::<2>::new(7).unwrap();
    owner.begin_retirement().unwrap();
    assert_eq!(
        owner.begin_retirement_shootdown(&mut barrier, 0b11),
        Err(RoundError::NoReservedCpuHistory),
    );
    owner.finish_retirement().unwrap();
    assert_eq!(
        owner.begin_retirement_shootdown(&mut barrier, 0b11),
        Err(RoundError::NotRetiring),
    );
    assert_eq!(barrier.snapshot().epoch, 0);
    drop(owner);
    assert!(trace.borrow().releases.is_empty());
    assert_eq!(trace.borrow().owned.len(), 1);
}

#[test]
fn armed_owner_cannot_retire_before_its_exact_round_completes() {
    // Host-only synthetic acknowledgements exercise the production metadata
    // guards. They are NOT evidence of real hardware TLB invalidation.
    let mut source = Source::new(&[0x1000, 0x2000]);
    let trace = source.trace.clone();
    let mut owner = publish::<2, 4>(&mut source, 0x1000);
    for cpu in [0, 2, 3] {
        let ticket = owner.reserve_cpu(cpu).unwrap();
        owner.confirm_active(ticket, 0x1000).unwrap();
        owner.acknowledge_quiescent(ticket, 0x9000).unwrap();
    }
    owner.begin_retirement().unwrap();
    let mut barrier = ShootdownBarrier::<4>::new(7).unwrap();
    let round = owner.begin_retirement_shootdown(&mut barrier, 0b1101).unwrap();
    let first = barrier.snapshot();

    assert_eq!(
        owner.begin_retirement_shootdown(&mut barrier, 0b1111),
        Err(RoundError::AlreadyArmed),
    );
    assert_eq!(barrier.snapshot(), first);
    assert_eq!(owner.finish_retirement(), Err(Error::OutstandingShootdown));
    assert_eq!(owner.snapshot().phase, Phase::Retiring);
    assert_eq!(trace.borrow().releases.len(), 0);

    let foreign = ShootdownBarrier::<4>::new(8).unwrap();
    assert_eq!(
        owner.finish_retirement_after_shootdown(&foreign, round),
        Err(Error::OutstandingShootdown),
    );
    // Even an independent same-generation barrier at the exact same epoch
    // has a distinct instance identity and cannot impersonate the owner round.
    let mut lookalike = ShootdownBarrier::<4>::new(7).unwrap();
    let lookalike_round = lookalike.begin(0b1101).unwrap();
    for cpu in [0, 2, 3] {
        unsafe { lookalike.acknowledge_after_local_flush(lookalike_round, cpu).unwrap() };
    }
    assert!(lookalike.completed(lookalike_round));
    assert_ne!(round, lookalike_round);
    assert_eq!(
        owner.finish_retirement_after_shootdown(&lookalike, round),
        Err(Error::OutstandingShootdown),
    );
    assert_eq!(
        owner.finish_retirement_after_shootdown(&lookalike, lookalike_round),
        Err(Error::OutstandingShootdown),
    );
    // An unrelated same-generation barrier with a *different epoch* cannot
    // replace the round previously minted through this physical owner.
    let mut other = ShootdownBarrier::<4>::new(7).unwrap();
    let old = other.begin(0b1101).unwrap();
    for cpu in [0, 2, 3] {
        unsafe { other.acknowledge_after_local_flush(old, cpu).unwrap() };
    }
    let other_round = other.begin(0b1101).unwrap();
    for cpu in [0, 2, 3] {
        unsafe { other.acknowledge_after_local_flush(other_round, cpu).unwrap() };
    }
    assert!(other.completed(other_round));
    assert_ne!(other_round, round);
    assert_eq!(
        owner.finish_retirement_after_shootdown(&other, other_round),
        Err(Error::OutstandingShootdown),
    );

    // Even the owner's *correct* round refuses retirement until the final
    // independent participant has completed.
    for cpu in [0, 2] {
        unsafe { barrier.acknowledge_after_local_flush(round, cpu).unwrap() };
    }
    assert_eq!(barrier.snapshot().pending, 0b1000);
    assert_eq!(
        owner.finish_retirement_after_shootdown(&barrier, round),
        Err(Error::OutstandingShootdown),
    );
    assert_eq!(owner.finish_retirement(), Err(Error::OutstandingShootdown));
    assert_eq!(owner.snapshot().phase, Phase::Retiring);
    assert!(trace.borrow().releases.is_empty());

    unsafe { barrier.acknowledge_after_local_flush(round, 3).unwrap() };
    assert!(barrier.completed(round));
    assert_eq!(
        owner.finish_retirement_after_shootdown(&barrier, round),
        Ok(()),
    );
    assert_eq!(owner.snapshot().phase, Phase::Retired);
    assert!(trace.borrow().releases.is_empty());
    // SAFETY: host fixture never loaded a private CR3 or created real users.
    assert_eq!(
        unsafe { owner.reclaim() }.ok(),
        Some(ReleaseReport { released: 2, failed: 0 }),
    );
    assert_eq!(trace.borrow().releases, [0x2000, 0x1000]);
}
