//! Explicit staged-to-live PMM ownership; active Drop deliberately leaks.
//!
//! The private ledger cannot be replaced or detached from its frame owner.
//! Retired is still only bookkeeping: reclamation is unsafe because saved
//! contexts, aliases and authenticated hardware observations are external.

use core::mem::ManuallyDrop;

use crate::{
    address_space_retirement::{Error, Phase, RetirementGate, Snapshot, Ticket},
    pmm_frame_batch::{FrameBatch, FrameSource, ReleaseReport},
    saved_context_retirement::{
        ContextTicket, Error as ContextError, SavedContextGate, Snapshot as ContextSnapshot,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeError {
    Context(ContextError),
    Cpu(Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublishError {
    Gate(Error),
    Context(ContextError),
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
    contexts: SavedContextGate<64>,
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
        let contexts = match SavedContextGate::<64>::new(generation) {
            Ok(contexts) => contexts,
            Err(error) => return Err((batch, PublishError::Context(error))),
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
            contexts,
        })
    }

    pub fn frames(&self) -> &[u64; N] {
        self.batch.frames()
    }

    pub fn snapshot(&self) -> Snapshot {
        self.gate.snapshot()
    }

    /// Only for a fresh entry that has no saved resumable context. A scheduler
    /// must use reserve_saved_resume for every suspended/preempted user return.
    pub fn reserve_cpu(&mut self, cpu: usize) -> Result<Ticket, Error> {
        self.gate.reserve_cpu(cpu)
    }

    pub fn context_snapshot(&self) -> ContextSnapshot {
        self.contexts.snapshot()
    }

    /// Metadata admission; register the actual resumable frame and queue entry
    /// before publishing them to any dispatcher. One exclusive owner lock is
    /// needed across scheduler admission, dispatch, and retirement.
    pub fn register_saved_context(&mut self, slot: usize) -> Result<ContextTicket, ContextError> {
        if self.gate.snapshot().phase != Phase::Live {
            return Err(ContextError::WrongPhase);
        }
        self.contexts.admit(slot)
    }

    /// Validate the exact saved-context incarnation and reserve its CPU under
    /// the same exclusive borrow. This does not load CR3 or dequeue a task.
    pub fn reserve_saved_resume(
        &mut self,
        context: ContextTicket,
        cpu: usize,
    ) -> Result<Ticket, ResumeError> {
        self.contexts
            .validate_resume(context)
            .map_err(ResumeError::Context)?;
        self.gate.reserve_cpu(cpu).map_err(ResumeError::Cpu)
    }

    /// # Safety
    /// The caller must first cancel the actual saved execution frame,
    /// dispatch queue, wakeups and pending handoffs for this exact token.
    /// Metadata revocation alone is not proof of cancellation.
    pub unsafe fn revoke_saved_context(
        &mut self,
        context: ContextTicket,
    ) -> Result<(), ContextError> {
        unsafe { self.contexts.revoke(context) }
    }

    pub fn confirm_active(&mut self, ticket: Ticket, actual_cr3: u64) -> Result<(), Error> {
        self.gate.confirm_active(ticket, actual_cr3)
    }

    pub fn begin_retirement(&mut self) -> Result<(), Error> {
        self.gate.begin_retirement()?;
        // Both ledgers share this exclusive &mut owner. Closing after the CPU
        // gate is monotone; context admission is now permanently disallowed.
        self.contexts.close_admission().map_err(|_| Error::WrongPhase)
    }

    pub fn acknowledge_quiescent(&mut self, ticket: Ticket, actual_cr3: u64) -> Result<(), Error> {
        self.gate.acknowledge_quiescent(ticket, actual_cr3)
    }

    /// Metadata only; does not reclaim or certify external references.
    pub fn finish_retirement(&mut self) -> Result<(), Error> {
        let cpus = self.gate.snapshot();
        if cpus.phase != Phase::Retiring {
            return Err(Error::WrongPhase);
        }
        if cpus.reserved != 0 || cpus.active != 0 {
            return Err(Error::OutstandingCpus);
        }
        if self.contexts.snapshot().pending != 0 {
            return Err(Error::OutstandingContexts);
        }
        // All checks occur under the exclusive owner borrow. Neither gate
        // can reopen. This still does not prove external hardware quiescence.
        self.contexts.finish().map_err(|_| Error::WrongPhase)?;
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
        if self.contexts.snapshot().pending != 0 {
            return Err((self, Error::OutstandingContexts));
        }
        if self.contexts.snapshot().phase != crate::saved_context_retirement::Phase::Closed {
            return Err((self, Error::WrongPhase));
        }
        // SAFETY: successful retirement plus the caller's external proof
        // permits release. Self is consumed, no Drop reads batch, and this
        // ManuallyDrop is never exposed or read again after take().
        let batch = unsafe { ManuallyDrop::take(&mut self.batch) };
        Ok(batch.close())
    }
}
