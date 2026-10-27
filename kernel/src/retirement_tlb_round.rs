//! Bind a retiring address-space generation to a conservative TLB target set.
//!
//! Coordinator METADATA ONLY: no IPI, no CR3 observation, no hardware flush,
//! no permission to release frames. The caller must hold the one exclusive
//! process/retirement/shootdown lock during both retirement transitions and
//! round publication, and must not treat a completed round as PMM ownership
//! release without separate context/device/PCID/global-translation proofs.

use crate::{
    address_space_retirement::{Phase as RetirementPhase, RetirementGate},
    tlb_shootdown::{Error as ShootdownError, Round, ShootdownBarrier},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NotRetiring,
    OutstandingCpus,
    NoReservedCpuHistory,
    WrongGeneration,
    Shootdown(ShootdownError),
}

/// Start a retirement-only round covering every CPU that was *ever* granted
/// a private CR3 reservation for this generation, not merely active CPUs.
/// The additional requested targets may include more CPUs, never fewer.
///
/// Retiring permanently closes new CPU reservations. This function refuses
/// an outstanding reservation, including a CR3 load still racing retirement.
/// Each targeted CPU must independently acknowledge a real local flush.
/// Offline/hung CPUs must stay pending; timeouts must retain the PMM frames.
pub fn begin_retirement_shootdown<const CPUS: usize>(
    gate: &RetirementGate<CPUS>,
    barrier: &mut ShootdownBarrier<CPUS>,
    targets: u64,
) -> Result<Round, Error> {
    let snapshot = gate.snapshot();
    if snapshot.phase != RetirementPhase::Retiring {
        return Err(Error::NotRetiring);
    }
    if snapshot.reserved != 0 || snapshot.active != 0 {
        return Err(Error::OutstandingCpus);
    }
    let required = gate.potential_tlb_users();
    if required == 0 {
        return Err(Error::NoReservedCpuHistory);
    }
    if !barrier.matches_generation(gate.generation()) {
        return Err(Error::WrongGeneration);
    }
    barrier.begin_covering(targets, required).map_err(Error::Shootdown)
}
