//! Host-only contract tests of the exact kernel retirement/barrier modules.
//! No synthetic ack is evidence that any physical CPU executed INVLPG.
#[path = "../kernel/src/address_space_retirement.rs"]
mod address_space_retirement;
#[path = "../kernel/src/tlb_shootdown.rs"]
mod tlb_shootdown;
#[path = "../kernel/src/retirement_tlb_round.rs"]
mod retirement_tlb_round;

use address_space_retirement::{RetirementGate, Phase as RetirementPhase};
use retirement_tlb_round::{begin_retirement_shootdown, Error};
use tlb_shootdown::{Error as BarrierError, Phase as BarrierPhase, ShootdownBarrier};

fn live<const CPUS: usize>() -> RetirementGate<CPUS> {
    let mut gate = RetirementGate::new(7, 0x1000, 0x9000).unwrap();
    gate.publish().unwrap();
    gate
}

// Host simulation only. Production must call from the *target* CPU following
// authenticated local invalidation and a correctly published IPI round.
fn simulated_ack<const CPUS: usize>(
    barrier: &mut ShootdownBarrier<CPUS>,
    round: tlb_shootdown::Round,
    cpu: usize,
) {
    unsafe { barrier.acknowledge_after_local_flush(round, cpu) }.unwrap();
}

#[test]
fn old_idle_cpu_cannot_be_dropped_from_retirement_targets() {
    let mut gate = live::<4>();
    for cpu in [1, 3] {
        let ticket = gate.reserve_cpu(cpu).unwrap();
        gate.confirm_active(ticket, 0x1000).unwrap();
        gate.acknowledge_quiescent(ticket, 0x9000).unwrap();
    }
    assert_eq!(gate.snapshot().active, 0);
    assert_eq!(gate.potential_tlb_users(), 0b1010);
    gate.begin_retirement().unwrap();
    let mut barrier = ShootdownBarrier::<4>::new(7).unwrap();
    assert_eq!(
        begin_retirement_shootdown(&gate, &mut barrier, 0b1000),
        Err(Error::Shootdown(BarrierError::MissingRequiredTargets)),
    );
    assert_eq!(barrier.snapshot().phase, BarrierPhase::Ready);
    assert_eq!(barrier.snapshot().epoch, 0);
    let round = begin_retirement_shootdown(&gate, &mut barrier, 0b1011).unwrap();
    simulated_ack(&mut barrier, round, 3);
    simulated_ack(&mut barrier, round, 0);
    assert!(!barrier.completed(round));
    assert_eq!(barrier.snapshot().pending, 0b0010);
    simulated_ack(&mut barrier, round, 1);
    assert!(barrier.completed(round));
    assert_eq!(gate.snapshot().phase, RetirementPhase::Retiring);
    assert_eq!(gate.reserve_cpu(0), Err(address_space_retirement::Error::WrongPhase));
}

#[test]
fn wrong_generation_cannot_reuse_another_address_spaces_round() {
    let mut gate = live::<2>();
    let ticket = gate.reserve_cpu(0).unwrap();
    gate.acknowledge_quiescent(ticket, 0x9000).unwrap();
    gate.begin_retirement().unwrap();
    let mut foreign = ShootdownBarrier::<2>::new(8).unwrap();
    assert_eq!(
        begin_retirement_shootdown(&gate, &mut foreign, 0b11),
        Err(Error::WrongGeneration),
    );
    assert_eq!(foreign.snapshot().phase, BarrierPhase::Ready);
    assert_eq!(foreign.snapshot().epoch, 0);
}

#[test]
fn pending_private_cr3_reservation_blocks_round_creation() {
    let mut gate = live::<4>();
    let ticket = gate.reserve_cpu(2).unwrap();
    gate.begin_retirement().unwrap();
    let mut barrier = ShootdownBarrier::<4>::new(7).unwrap();
    assert_eq!(
        begin_retirement_shootdown(&gate, &mut barrier, 0b0100),
        Err(Error::OutstandingCpus),
    );
    assert_eq!(barrier.snapshot().phase, BarrierPhase::Ready);
    gate.acknowledge_quiescent(ticket, 0x9000).unwrap();
    let round = begin_retirement_shootdown(&gate, &mut barrier, 0b0100).unwrap();
    assert!(!barrier.completed(round));
    simulated_ack(&mut barrier, round, 2);
    assert!(barrier.completed(round));
}

#[test]
fn staged_live_retired_and_never_used_spaces_fail_closed() {
    let mut gate = RetirementGate::<2>::new(7, 0x1000, 0x9000).unwrap();
    let mut barrier = ShootdownBarrier::<2>::new(7).unwrap();
    assert_eq!(
        begin_retirement_shootdown(&gate, &mut barrier, 0b11),
        Err(Error::NotRetiring),
    );
    gate.publish().unwrap();
    assert_eq!(
        begin_retirement_shootdown(&gate, &mut barrier, 0b11),
        Err(Error::NotRetiring),
    );
    gate.begin_retirement().unwrap();
    assert_eq!(
        begin_retirement_shootdown(&gate, &mut barrier, 0b11),
        Err(Error::NoReservedCpuHistory),
    );
    gate.finish_retirement().unwrap();
    assert_eq!(
        begin_retirement_shootdown(&gate, &mut barrier, 0b11),
        Err(Error::NotRetiring),
    );
    assert_eq!(barrier.snapshot().epoch, 0);
}

#[test]
fn cpu63_bit_and_out_of_range_additional_target_are_checked() {
    let mut gate = live::<64>();
    let ticket = gate.reserve_cpu(63).unwrap();
    gate.confirm_active(ticket, 0x1000).unwrap();
    gate.acknowledge_quiescent(ticket, 0x9000).unwrap();
    gate.begin_retirement().unwrap();
    let mut barrier = ShootdownBarrier::<64>::new(7).unwrap();
    let round = begin_retirement_shootdown(&gate, &mut barrier, 1u64 << 63).unwrap();
    simulated_ack(&mut barrier, round, 63);
    assert!(barrier.completed(round));

    let mut gate = live::<2>();
    let ticket = gate.reserve_cpu(1).unwrap();
    gate.acknowledge_quiescent(ticket, 0x9000).unwrap();
    gate.begin_retirement().unwrap();
    let mut small_barrier = ShootdownBarrier::<2>::new(7).unwrap();
    assert_eq!(
        begin_retirement_shootdown(&gate, &mut small_barrier, 0b0110),
        Err(Error::Shootdown(BarrierError::InvalidTargets)),
    );
    assert_eq!(small_barrier.snapshot().epoch, 0);
}
