//! Explicit staged-to-live PMM ownership; active Drop deliberately leaks.
//!
//! The private ledger cannot be replaced or detached from its frame owner.
//! Retired is still only bookkeeping: reclamation is unsafe because saved
//! contexts, aliases and authenticated hardware observations are external.

use core::mem::ManuallyDrop;

use crate::{
    address_space_retirement::{Error, Phase, RetirementGate, Snapshot, Ticket},
    pmm_frame_batch::{FrameBatch, FrameSource, ReleaseReport},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishError {
    Gate(Error),
    RootNotOwned,
    SupervisorOwned,
    InvalidFrames,
}

/// Move-only owner. No safe method returns its staging guard or releases its
/// frames. Dropping it in ANY phase retains the PMM allocations permanently;
/// losing bookkeeping must never become a use-after-free on another CPU.
#[must_use = "dropping an active address space retains its physical frames"]
pub struct ActiveAddressSpace<'a, S: FrameSource, const N: usize, const CPUS: usize> {
    batch: ManuallyDrop<FrameBatch<'a, S, N>>,
    gate: RetirementGate<CPUS>,
}

impl<'a, S: FrameSource, const N: usize, const CPUS: usize> ActiveAddressSpace<'a, S, N, CPUS> {
    /// Consume staged ownership BEFORE any CPU reserves or loads this CR3.
    /// Failure returns the unchanged staging guard, preserving rollback.
    /// The source must honor FrameSource's unique/exclusive ownership contract;
    /// address checks cannot authenticate PMM ownership or image contents.
    pub fn publish(
        batch: FrameBatch<'a, S, N>,
        generation: u64,
        root: u64,
        supervisor: u64,
    ) -> Result<Self, (FrameBatch<'a, S, N>, PublishError)> {
        let mut gate = match RetirementGate::new(generation, root, supervisor) {
            Ok(gate) => gate,
            Err(error) => return Err((batch, PublishError::Gate(error))),
        };
        let frames = batch.frames();
        let error = if !frames.contains(&root) {
            Some(PublishError::RootNotOwned)
        } else if frames.contains(&supervisor) {
            Some(PublishError::SupervisorOwned)
        } else if frames.iter().enumerate().any(|(i, frame)| {
            *frame == 0 || *frame >= 1 << 52 || *frame & 4095 != 0 || frames[..i].contains(frame)
        }) {
            Some(PublishError::InvalidFrames)
        } else {
            None
        };
        if let Some(error) = error {
            return Err((batch, error));
        }
        if let Err(error) = gate.publish() {
            return Err((batch, PublishError::Gate(error)));
        }
        Ok(Self {
            batch: ManuallyDrop::new(batch),
            gate,
        })
    }

    pub fn frames(&self) -> &[u64; N] {
        self.batch.frames()
    }

    pub fn snapshot(&self) -> Snapshot {
        self.gate.snapshot()
    }

    pub fn reserve_cpu(&mut self, cpu: usize) -> Result<Ticket, Error> {
        self.gate.reserve_cpu(cpu)
    }

    pub fn confirm_active(&mut self, ticket: Ticket, actual_cr3: u64) -> Result<(), Error> {
        self.gate.confirm_active(ticket, actual_cr3)
    }

    pub fn begin_retirement(&mut self) -> Result<(), Error> {
        self.gate.begin_retirement()
    }

    pub fn acknowledge_quiescent(&mut self, ticket: Ticket, actual_cr3: u64) -> Result<(), Error> {
        self.gate.acknowledge_quiescent(ticket, actual_cr3)
    }

    /// Metadata only; does not reclaim or certify external references.
    pub fn finish_retirement(&mut self) -> Result<(), Error> {
        self.gate.finish_retirement()
    }

    /// Consume a retired owner and attempt each release exactly once, in
    /// reverse allocation order. Refusal returns the complete active owner.
    /// Backend release failures are reported, never retried by a destructor.
    ///
    /// # Safety
    /// Before a successful call, the caller must independently establish:
    /// - Every CR3 load used this ledger under one exclusive lock. Each
    ///   acknowledgement came from its authenticated CPU after restoration
    ///   of the trusted supervisor root and cancellation of pending loads.
    /// - PCID is disabled on every participant; no private global translation
    ///   survives. Required local invalidation has completed on every CPU.
    /// - All saved contexts, queues, walkers, mappings and device references
    ///   that could access these frames are revoked or permanently quiescent.
    /// - Borrowed/shared child tables stay resident and are not in this batch.
    /// A retired snapshot or a coordinator CR3 observation alone is insufficient.
    pub unsafe fn reclaim(mut self) -> Result<ReleaseReport, (Self, Error)> {
        if self.gate.snapshot().phase != Phase::Retired {
            return Err((self, Error::WrongPhase));
        }
        // SAFETY: successful retirement plus the caller's external proof
        // permits release. Self is consumed, no Drop reads batch, and this
        // ManuallyDrop is never exposed or read again after take().
        let batch = unsafe { ManuallyDrop::take(&mut self.batch) };
        Ok(batch.close())
    }
}
