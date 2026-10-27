//! No-heap, generation-tagged acknowledgement barrier for future TLB shootdowns.
//!
//! This is serialized coordinator METADATA, not an IPI sender, TLB flush,
//! hardware observation, or permission to reclaim physical frames. A caller
//! must arrange real per-CPU invalidation and authenticate local acknowledgements.
//! A timeout, lost CPU, or lost barrier must fail closed: keep frames pinned.
//!
//! All mutations require one exclusive coordinator lock. Never wait for remote
//! acknowledgements while holding a lock needed by their handlers.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Ready,
    Pending,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidCpuCount,
    InvalidGeneration,
    InvalidTargets,
    MissingRequiredTargets,
    Busy,
    InvalidCpu,
    UnexpectedCpu,
    DuplicateAck,
    StaleRound,
    WrongPhase,
    EpochExhausted,
}

/// Opaque generation-tagged round. An old acknowledgement must never drain
/// a newer shootdown, even when exactly the same CPU mask is targeted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Round {
    generation: u64,
    epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub phase: Phase,
    pub epoch: u64,
    pub targets: u64,
    pub pending: u64,
}

/// One barrier for one globally unique address-space generation.
/// Does not own frames or synchronize memory without the external lock.
#[must_use = "discarding a pending barrier is not evidence of quiescence"]
pub struct ShootdownBarrier<const CPUS: usize> {
    generation: u64,
    epoch: u64,
    phase: Phase,
    targets: u64,
    pending: u64,
}

impl<const CPUS: usize> ShootdownBarrier<CPUS> {
    pub fn new(generation: u64) -> Result<Self, Error> {
        if CPUS == 0 || CPUS > 64 {
            return Err(Error::InvalidCpuCount);
        }
        if generation == 0 {
            return Err(Error::InvalidGeneration);
        }
        Ok(Self {
            generation,
            epoch: 0,
            phase: Phase::Ready,
            targets: 0,
            pending: 0,
        })
    }

    /// Compare an independently minted address-space generation before
    /// using this barrier to certify that address space's shootdown round.
    pub fn matches_generation(&self, generation: u64) -> bool {
        self.generation == generation
    }

    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            phase: self.phase,
            epoch: self.epoch,
            targets: self.targets,
            pending: self.pending,
        }
    }

    /// Legacy round start: every requested CPU is mandatory, but callers
    /// are responsible for deriving a complete, authenticated target set.
    /// See begin_covering() when a separate required target mask is known.
    pub fn begin(&mut self, targets: u64) -> Result<Round, Error> {
        self.begin_covering(targets, targets)
    }

    /// Fail closed if an independently established required CPU mask would
    /// be omitted from the new round. The required set must be a nonempty,
    /// authenticated *conservative* superset of possible stale TLB users;
    /// derive it under the same coordinator lock as publication/retirement.
    ///
    /// This only validates metadata, not CPU participation, IPI delivery or
    /// hardware invalidation. A missing/offline required CPU must remain
    /// pending until an independent quiescence protocol proves it safe.
    /// Rejection never advances the epoch or mutates a completed round.
    pub fn begin_covering(&mut self, targets: u64, required: u64) -> Result<Round, Error> {
        if self.phase == Phase::Pending {
            return Err(Error::Busy);
        }
        let allowed = if CPUS == 64 {
            u64::MAX
        } else {
            (1u64 << CPUS) - 1
        };
        if targets == 0 || targets & !allowed != 0
            || required == 0 || required & !allowed != 0
        {
            return Err(Error::InvalidTargets);
        }
        if targets & required != required {
            return Err(Error::MissingRequiredTargets);
        }
        let next = self.epoch.checked_add(1).ok_or(Error::EpochExhausted)?;
        self.epoch = next;
        self.targets = targets;
        self.pending = targets;
        self.phase = Phase::Pending;
        Ok(Round {
            generation: self.generation,
            epoch: next,
        })
    }

    /// Record one actual participant's completion, not an inferred receipt.
    ///
    /// # Safety
    /// The caller must be executing on the authenticated `cpu` represented
    /// by the targeted bit, after observing this exact published round and
    /// completing all required local TLB invalidation and ordering.
    /// With PCID/global translations, the appropriate architectural flush
    /// must cover them; ordinary CR3 inequality does NOT prove invalidation.
    /// Re-entry and saved-context reuse must also be separately controlled.
    /// Neither sending an IPI nor EOI alone satisfies this contract.
    pub unsafe fn acknowledge_after_local_flush(
        &mut self,
        round: Round,
        cpu: usize,
    ) -> Result<(), Error> {
        if self.phase != Phase::Pending {
            return Err(Error::WrongPhase);
        }
        if round.generation != self.generation || round.epoch != self.epoch {
            return Err(Error::StaleRound);
        }
        if cpu >= CPUS {
            return Err(Error::InvalidCpu);
        }
        let bit = 1u64 << cpu;
        if self.targets & bit == 0 {
            return Err(Error::UnexpectedCpu);
        }
        if self.pending & bit == 0 {
            return Err(Error::DuplicateAck);
        }
        self.pending &= !bit;
        if self.pending == 0 {
            self.phase = Phase::Complete;
        }
        Ok(())
    }

    /// Bookkeeping only. The caller must still independently prove saved
    /// contexts, mappings, borrowed tables, and device users are quiescent.
    pub fn completed(&self, round: Round) -> bool {
        self.phase == Phase::Complete
            && round.generation == self.generation
            && round.epoch == self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only a simulation: no host CPU loads these CR3 roots or issues IPIs.
    fn ack<const N: usize>(
        barrier: &mut ShootdownBarrier<N>,
        round: Round,
        cpu: usize,
    ) -> Result<(), Error> {
        unsafe { barrier.acknowledge_after_local_flush(round, cpu) }
    }

    #[test]
    fn rejects_zero_oversized_and_unidentified_barriers() {
        assert!(matches!(
            ShootdownBarrier::<0>::new(1),
            Err(Error::InvalidCpuCount)
        ));
        assert!(matches!(
            ShootdownBarrier::<65>::new(1),
            Err(Error::InvalidCpuCount)
        ));
        assert!(matches!(
            ShootdownBarrier::<1>::new(0),
            Err(Error::InvalidGeneration)
        ));
        let mut barrier = ShootdownBarrier::<4>::new(7).unwrap();
        assert_eq!(barrier.begin(0), Err(Error::InvalidTargets));
        assert_eq!(barrier.begin(1 << 4), Err(Error::InvalidTargets));
        assert_eq!(barrier.snapshot().phase, Phase::Ready);
    }

    #[test]
    fn every_four_cpu_completion_order_waits_for_last_ack() {
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        let order = [a, b, c, d];
                        if order.iter().enumerate()
                            .any(|(i, cpu)| order[..i].contains(cpu)) {
                            continue;
                        }
                        let mut barrier = ShootdownBarrier::<4>::new(7).unwrap();
                        let round = barrier.begin(0b1111).unwrap();
                        assert_eq!(barrier.begin(1), Err(Error::Busy));
                        for (index, cpu) in order.into_iter().enumerate() {
                            assert!(!barrier.completed(round));
                            ack(&mut barrier, round, cpu).unwrap();
                            assert_eq!(
                                barrier.snapshot().pending.count_ones(),
                                3 - index as u32,
                            );
                        }
                        assert!(barrier.completed(round));
                        assert_eq!(barrier.snapshot().phase, Phase::Complete);
                        assert_eq!(barrier.snapshot().targets, 0b1111);
                    }
                }
            }
        }
    }

    #[test]
    fn unrequested_duplicate_and_invalid_cpu_cannot_advance() {
        let mut barrier = ShootdownBarrier::<4>::new(7).unwrap();
        let round = barrier.begin(0b0101).unwrap();
        let original = barrier.snapshot();
        assert_eq!(ack(&mut barrier, round, 4), Err(Error::InvalidCpu));
        assert_eq!(ack(&mut barrier, round, 1), Err(Error::UnexpectedCpu));
        assert_eq!(barrier.snapshot(), original);
        ack(&mut barrier, round, 0).unwrap();
        let after_first = barrier.snapshot();
        assert_eq!(ack(&mut barrier, round, 0), Err(Error::DuplicateAck));
        assert_eq!(barrier.snapshot(), after_first);
        assert!(!barrier.completed(round));
        ack(&mut barrier, round, 2).unwrap();
        assert!(barrier.completed(round));
        assert_eq!(ack(&mut barrier, round, 2), Err(Error::WrongPhase));
    }

    #[test]
    fn stale_epoch_or_generation_cannot_drain_new_round() {
        let mut barrier = ShootdownBarrier::<2>::new(7).unwrap();
        let first = barrier.begin(1).unwrap();
        ack(&mut barrier, first, 0).unwrap();
        assert!(barrier.completed(first));
        let second = barrier.begin(3).unwrap();
        let before = barrier.snapshot();
        assert_eq!(ack(&mut barrier, first, 0), Err(Error::StaleRound));
        assert_eq!(
            ack(&mut barrier, Round { generation: 8, ..second }, 1),
            Err(Error::StaleRound),
        );
        assert_eq!(barrier.snapshot(), before);
        ack(&mut barrier, second, 1).unwrap();
        assert!(!barrier.completed(first));
        assert!(!barrier.completed(second));
        ack(&mut barrier, second, 0).unwrap();
        assert!(barrier.completed(second));
    }

    #[test]
    fn omitted_required_tlb_users_fail_closed_without_consuming_an_epoch() {
        let mut barrier = ShootdownBarrier::<4>::new(7).unwrap();
        let before = barrier.snapshot();
        for (targets, required, expected) in [
            (0b0011, 0b0101, Error::MissingRequiredTargets),
            (0b0001, 0b0101, Error::MissingRequiredTargets),
            (0b1111, 0, Error::InvalidTargets),
            (0b1111, 1u64 << 4, Error::InvalidTargets),
            (0, 0b0011, Error::InvalidTargets),
            (1u64 << 4, 0b0011, Error::InvalidTargets),
        ] {
            assert_eq!(barrier.begin_covering(targets, required), Err(expected));
            assert_eq!(barrier.snapshot(), before);
        }
        let round = barrier.begin_covering(0b1111, 0b0101).unwrap();
        assert_eq!(barrier.snapshot().targets, 0b1111);
        for cpu in [0, 1, 2] {
            ack(&mut barrier, round, cpu).unwrap();
            assert!(!barrier.completed(round));
        }
        assert_eq!(barrier.snapshot().pending, 0b1000);
        let pending = barrier.snapshot();
        assert_eq!(barrier.begin_covering(0b1111, 0b1111), Err(Error::Busy));
        assert_eq!(barrier.snapshot(), pending);
        ack(&mut barrier, round, 3).unwrap();
        assert!(barrier.completed(round));

        let completed = barrier.snapshot();
        assert_eq!(
            barrier.begin_covering(0b0011, 0b0111),
            Err(Error::MissingRequiredTargets)
        );
        assert_eq!(barrier.snapshot(), completed);
        let next = barrier.begin_covering(0b0111, 0b0111).unwrap();
        assert!(!barrier.completed(round));
        assert_eq!(barrier.snapshot().epoch, completed.epoch + 1);
        for cpu in [0, 1, 2] {
            ack(&mut barrier, next, cpu).unwrap();
        }
        assert!(barrier.completed(next));
    }

    #[test]
    fn mandatory_high_cpu_63_cannot_be_silently_omitted() {
        let mut barrier = ShootdownBarrier::<64>::new(11).unwrap();
        assert_eq!(
            barrier.begin_covering(0b0011, 1u64 << 63),
            Err(Error::MissingRequiredTargets)
        );
        assert_eq!(barrier.snapshot().epoch, 0);
        let round = barrier.begin_covering((1u64 << 63) | 0b0011, 1u64 << 63).unwrap();
        ack(&mut barrier, round, 0).unwrap();
        ack(&mut barrier, round, 1).unwrap();
        assert!(!barrier.completed(round));
        assert_eq!(barrier.snapshot().pending, 1u64 << 63);
        ack(&mut barrier, round, 63).unwrap();
        assert!(barrier.completed(round));
    }

    #[test]
    fn high_cpu_bit_and_epoch_overflow_fail_closed() {
        let mut barrier = ShootdownBarrier::<64>::new(9).unwrap();
        let round = barrier.begin(1u64 << 63).unwrap();
        assert!(!barrier.completed(round));
        ack(&mut barrier, round, 63).unwrap();
        assert!(barrier.completed(round));
        barrier.epoch = u64::MAX;
        let before = barrier.snapshot();
        assert_eq!(barrier.begin(1), Err(Error::EpochExhausted));
        assert_eq!(barrier.snapshot(), before);
    }

    #[test]
    fn a_missing_ack_never_completes_even_after_other_cpus_ack() {
        let mut barrier = ShootdownBarrier::<4>::new(9).unwrap();
        let round = barrier.begin(0b1111).unwrap();
        ack(&mut barrier, round, 0).unwrap();
        ack(&mut barrier, round, 1).unwrap();
        ack(&mut barrier, round, 2).unwrap();
        assert_eq!(barrier.snapshot().pending, 0b1000);
        assert_eq!(barrier.begin(0b1000), Err(Error::Busy));
        assert!(!barrier.completed(round));
        // A timeout is not an acknowledgement. Dropping pending metadata
        // cannot be treated as a frame-reclamation capability.
    }
}
