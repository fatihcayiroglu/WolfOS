//! Pure AP handoff evidence checker. No timeouts, sleeping, or test skips.
//! Separates the first failing piece of the existing BSP acceptance contract.
//! In particular, a completed mailbox is NOT proof that paused logical
//! state, IPI accounting or AP-owner identity was valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepFailure {
    SnapshotUnavailable,
    WrongEpoch, WrongOwner, WrongStep, WrongDigest,
    WrongCompletion, WrongIrqCount, WrongEoiCount,
    WrongClaimCount, WrongExecutedCount,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepEvidence {
    pub snapshot: Option<(u64, usize, u64, u64)>, // epoch, owner, steps, digest
    pub completion: Option<u64>,
    pub received: u64,
    pub eois: u64,
    pub claimed: u64,
    pub executed: u64,
}
pub fn validate(
    e: StepEvidence, epoch: u64, owner: usize, step: u64,
    digest: u64, cpu_generation: u64,
) -> Result<(), StepFailure> {
    let (seen_epoch, seen_owner, seen_step, seen_digest) =
        e.snapshot.ok_or(StepFailure::SnapshotUnavailable)?;
    if seen_epoch != epoch { return Err(StepFailure::WrongEpoch) }
    if seen_owner != owner { return Err(StepFailure::WrongOwner) }
    if seen_step != step { return Err(StepFailure::WrongStep) }
    if seen_digest != digest { return Err(StepFailure::WrongDigest) }
    if e.completion != Some(digest) { return Err(StepFailure::WrongCompletion) }
    if e.received != cpu_generation { return Err(StepFailure::WrongIrqCount) }
    if e.eois != cpu_generation { return Err(StepFailure::WrongEoiCount) }
    if e.claimed != cpu_generation { return Err(StepFailure::WrongClaimCount) }
    if e.executed != cpu_generation { return Err(StepFailure::WrongExecutedCount) }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> StepEvidence {
        StepEvidence {
            snapshot: Some((2, 3, 3, 0x55)),
            completion: Some(0x55),
            received: 1, eois: 1, claimed: 1, executed: 1,
        }
    }
    #[test]
    fn requires_all_independent_published_evidence() {
        assert_eq!(validate(valid(),2,3,3,0x55,1),Ok(()));
        let mut e=valid(); e.snapshot=None;
        assert_eq!(validate(e,2,3,3,0x55,1),Err(StepFailure::SnapshotUnavailable));
        let mut e=valid(); e.snapshot=Some((9,3,3,0x55));
        assert_eq!(validate(e,2,3,3,0x55,1),Err(StepFailure::WrongEpoch));
        let mut e=valid(); e.snapshot=Some((2,1,3,0x55));
        assert_eq!(validate(e,2,3,3,0x55,1),Err(StepFailure::WrongOwner));
        let mut e=valid(); e.snapshot=Some((2,3,7,0x55));
        assert_eq!(validate(e,2,3,3,0x55,1),Err(StepFailure::WrongStep));
        let mut e=valid(); e.snapshot=Some((2,3,3,0xaa));
        assert_eq!(validate(e,2,3,3,0x55,1),Err(StepFailure::WrongDigest));
        let mut e=valid(); e.completion=Some(0xaa);
        assert_eq!(validate(e,2,3,3,0x55,1),Err(StepFailure::WrongCompletion));
        let mut e=valid(); e.received=0;
        assert_eq!(validate(e,2,3,3,0x55,1),Err(StepFailure::WrongIrqCount));
        let mut e=valid(); e.eois=0;
        assert_eq!(validate(e,2,3,3,0x55,1),Err(StepFailure::WrongEoiCount));
        let mut e=valid(); e.claimed=0;
        assert_eq!(validate(e,2,3,3,0x55,1),Err(StepFailure::WrongClaimCount));
        let mut e=valid(); e.executed=0;
        assert_eq!(validate(e,2,3,3,0x55,1),Err(StepFailure::WrongExecutedCount));
    }
    #[test]
    fn cannot_accept_stale_cpu_generation_even_with_correct_digest() {
        assert_eq!(validate(valid(),2,3,3,0x55,2),Err(StepFailure::WrongIrqCount));
    }
}
