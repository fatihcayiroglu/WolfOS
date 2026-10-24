//! Serialized policy bridge between one Ring3 runqueue handle and one
//! PMM-owned address-space saved-context ticket.
//!
//! This integrates the real Ring3RunQueue *metadata* with ActiveAddressSpace's
//! retirement ledger. It does NOT perform a CPL3 trap, save an IRET/FX frame,
//! disable interrupts, take the production scheduler lock, or load CR3.
//! Callers must hold one external exclusive coordinator lock across BOTH
//! the runqueue and address-space owner on every admission/dispatch/wake/
//! cancellation. A separate per-process owner must be used for each PID.

use crate::{
    active_address_space::{ActiveAddressSpace, ResumeError},
    address_space_retirement::Ticket as CpuTicket,
    pmm_frame_batch::FrameSource,
    process_table::ProcessTable,
    ring3_runqueue::{Error as QueueError, Handle, Ring3RunQueue, State, WaitTicket},
    saved_context_retirement::{ContextTicket, Error as ContextError},
};

#[cfg(not(test))]
use crate::user_context_bank::{ContextError as FrameEvidenceError, UserContextBank};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    StaleHandle,
    WrongState,
    WrongHandle,
    Queue(QueueError),
    Context(ContextError),
    Reserve(ResumeError),
    Quiesce(crate::address_space_retirement::Error),
    RegistryMismatch,
    OwnerMismatch,
    #[cfg(not(test))]
    FrameEvidence(FrameEvidenceError),
}

/// A process-generation-safe association. The queue may outlive the
/// address-space owner, but this binding NEVER owns frames or authorizes
/// hardware reentry without a separately obtained CPU reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ring3SavedBinding {
    handle: Handle,
    context: ContextTicket,
}

impl Ring3SavedBinding {
    fn state<const QUEUE: usize>(
        &self,
        queue: &Ring3RunQueue<QUEUE>,
    ) -> Result<State, Error> {
        queue
            .slots()
            .iter()
            .find(|slot| slot.state != State::Empty && slot.handle == self.handle)
            .map(|slot| slot.state)
            .ok_or(Error::StaleHandle)
    }

    /// Bind a *previously admitted* queue entry to an already authenticated,
    /// saved user frame. Callers must first save the real interrupt/user
    /// context, validate the PID/CR3 owner, and hold the shared scheduler lock.
    /// The wrapper checks only queue identity and saved-context metadata.
    pub fn attach<'a, S: FrameSource, const FRAMES: usize, const CPUS: usize,
        const QUEUE: usize>(
        owner: &mut ActiveAddressSpace<'a, S, FRAMES, CPUS>,
        queue: &Ring3RunQueue<QUEUE>,
        handle: Handle,
        saved_slot: usize,
    ) -> Result<Self, Error> {
        let slots = queue.slots();
        let found = slots.iter()
            .find(|slot| slot.state != State::Empty && slot.handle == handle)
            .ok_or(Error::StaleHandle)?;
        if !matches!(found.state, State::Ready | State::Blocked) {
            return Err(Error::WrongState);
        }
        let context = owner.register_saved_context(saved_slot).map_err(Error::Context)?;
        Ok(Self { handle, context })
    }

    /// Admission against an actual generation-safe process registry and
    /// move-only PMM owner, not merely a caller-selected queue PID/slot.
    /// Requires registry state READY for a READY queue entry, or BLOCKED
    /// for a BLOCKED one; root, ordered leased frames, and PID generation
    /// must all match the SAME live address-space owner before a saved token
    /// is registered. A mismatch has no owner/queue effects.
    ///
    /// This is stronger metadata identity validation, but cannot establish
    /// that UserContextBank contains the authentic GPR/IRET/FX trap frame.
    /// The trusted coordinator still must authenticate that frame and hold
    /// the same scheduler/registry/PMM-owner lock across this admission and
    /// every future dispatch/wake/cancel. Legacy attach exists only for
    /// isolated synthetic composition until the hardware path is migrated.
    pub fn attach_from_process_table<'a, S: FrameSource, const FRAMES: usize,
        const CPUS: usize, const QUEUE: usize>(
        owner: &mut ActiveAddressSpace<'a, S, FRAMES, CPUS>,
        registry: &ProcessTable<QUEUE, FRAMES>,
        queue: &Ring3RunQueue<QUEUE>,
        handle: Handle,
        saved_slot: usize,
    ) -> Result<Self, Error> {
        let state = queue.slots().iter()
            .find(|slot| slot.state != State::Empty && slot.handle == handle)
            .map(|slot| slot.state).ok_or(Error::StaleHandle)?;
        if !matches!(state, State::Ready | State::Blocked) {
            return Err(Error::WrongState);
        }
        let (root, frames) = registry.saved_binding_lease(handle.pid, state == State::Blocked)
            .ok_or(Error::RegistryMismatch)?;
        if !owner.matches_process_lease(handle.pid, root, &frames) {
            return Err(Error::OwnerMismatch);
        }
        Self::attach(owner, queue, handle, saved_slot)
    }

    /// Production-path pre-admission check: the stored exact PID frame must
    /// be a verified IF-enabled hardware trap record, not a bootstrap frame,
    /// before cross-checking its queue/registry/PMM owner. Both read-only
    /// validation stages complete BEFORE admitting the saved context token.
    /// The caller still authenticates actual CPU/FX/trap provenance and holds
    /// the single external scheduler lock across all these ledgers.
    #[cfg(not(test))]
    pub fn attach_from_context_bank<'a, S: FrameSource, const FRAMES: usize,
        const CPUS: usize, const QUEUE: usize>(
        owner: &mut ActiveAddressSpace<'a, S, FRAMES, CPUS>,
        registry: &ProcessTable<QUEUE, FRAMES>,
        bank: &UserContextBank<QUEUE>,
        queue: &Ring3RunQueue<QUEUE>,
        handle: Handle,
        saved_slot: usize,
    ) -> Result<Self, Error> {
        bank.verify_saved_binding(registry, queue, handle).map_err(Error::FrameEvidence)?;
        Self::attach_from_process_table(owner, registry, queue, handle, saved_slot)
    }

    /// Stage an authenticated RUNNING -> BLOCKED event wait and publish it
    /// only after the CPU's exact address-space reservation has been drained.
    /// The queue remains unchanged for any validation, wait-sequence, or
    /// quiescence failure; a successful transition leaves the saved context
    /// pinned until a subsequent authenticated wake/cancel/exit.
    ///
    /// The caller must hold the SAME external scheduler/owner lock through
    /// this entire operation. It must not expose the staged peer as runnable
    /// on hardware until that peer independently reserves its own address
    /// space and completes all CR3/TSS/FX/IRET handoff checks.
    ///
    /// # Safety
    /// The trusted CPU trap path must already have copied and authenticated
    /// this exact PID's GPR/IRET/FX frame, registered the real event source,
    /// canceled pending private-CR3 loads, switched to the authenticated
    /// supervisor CR3, and completed required local invalidation. `cpu_ticket`
    /// MUST belong to the suspended CPU and this owner; a caller-supplied
    /// CR3 value is not hardware proof. This function performs no trap,
    /// lock, TLB, event-source, or scheduler hardware operation.
    pub unsafe fn park_for_event<'a, S: FrameSource, const FRAMES: usize,
        const CPUS: usize, const QUEUE: usize>(
        &self,
        queue: &mut Ring3RunQueue<QUEUE>,
        owner: &mut ActiveAddressSpace<'a, S, FRAMES, CPUS>,
        cpu_ticket: CpuTicket,
        actual_supervisor_cr3: u64,
        event: u64,
    ) -> Result<(Option<Handle>, WaitTicket), Error> {
        if self.state(queue)? != State::Running || queue.running() != Some(self.handle) {
            return Err(Error::WrongState);
        }
        owner.validate_saved_context(self.context).map_err(Error::Context)?;
        let mut staged = *queue;
        let result = staged.block_current_for_event(self.handle, event).map_err(Error::Queue)?;
        // SAFETY: the hardware and event-source obligations are required of
        // the unsafe caller above. The exact CPU ticket must be acknowledged
        // before the blocked policy record becomes visible.
        owner.acknowledge_quiescent(cpu_ticket, actual_supervisor_cr3)
            .map_err(Error::Quiesce)?;
        *queue = staged;
        Ok(result)
    }

    /// A delayed wait notification cannot make an address space runnable
    /// after retirement admission has closed. Queue state stays unchanged
    /// whenever the owner or exact wait ticket rejects the event.
    pub fn wake_for_event<'a, S: FrameSource, const FRAMES: usize,
        const CPUS: usize, const QUEUE: usize>(
        &self,
        queue: &mut Ring3RunQueue<QUEUE>,
        owner: &ActiveAddressSpace<'a, S, FRAMES, CPUS>,
        wait: WaitTicket,
        event: u64,
    ) -> Result<(), Error> {
        if wait.handle() != self.handle {
            return Err(Error::WrongHandle);
        }
        if self.state(queue)? != State::Blocked {
            return Err(Error::WrongState);
        }
        owner.validate_saved_context(self.context).map_err(Error::Context)?;
        queue.wake_for_event(wait, event).map_err(Error::Queue)
    }

    /// Transactional policy dispatch: stage the queue on the stack, verify
    /// the exact selected handle, then obtain the actual CPU reservation.
    /// Any pre-commit failure leaves the queue unchanged. A successful
    /// reservation still pins its CPU until acknowledged by its real owner;
    /// this function does not perform a hardware switch.
    pub fn start_next<'a, S: FrameSource, const FRAMES: usize,
        const CPUS: usize, const QUEUE: usize>(
        &self,
        queue: &mut Ring3RunQueue<QUEUE>,
        owner: &mut ActiveAddressSpace<'a, S, FRAMES, CPUS>,
        cpu: usize,
    ) -> Result<CpuTicket, Error> {
        if self.state(queue)? != State::Ready {
            return Err(Error::WrongState);
        }
        owner.validate_saved_context(self.context).map_err(Error::Context)?;
        let mut staged = *queue;
        let selected = staged.start_next().map_err(Error::Queue)?;
        if selected != self.handle {
            return Err(Error::WrongHandle);
        }
        let ticket = owner.reserve_saved_resume(self.context, cpu).map_err(Error::Reserve)?;
        *queue = staged;
        Ok(ticket)
    }

    /// Revoke a running process's saved context after a trusted exit trap
    /// has already transitioned its queue record to EXITED.
    ///
    /// # Safety
    /// The caller must have actually canceled every saved user frame,
    /// event/timer wakeup, in-flight CPU handoff, and future dispatch path.
    /// An EXITED policy snapshot is not itself proof of hardware quiescence.
    pub unsafe fn retire_exited<'a, S: FrameSource, const FRAMES: usize,
        const CPUS: usize, const QUEUE: usize>(
        &self,
        queue: &Ring3RunQueue<QUEUE>,
        owner: &mut ActiveAddressSpace<'a, S, FRAMES, CPUS>,
    ) -> Result<(), Error> {
        if self.state(queue)? != State::Exited {
            return Err(Error::WrongState);
        }
        unsafe { owner.revoke_saved_context(self.context) }.map_err(Error::Context)
    }

    /// Cancel a READY or BLOCKED queue entry and its saved-context pin in
    /// the same exclusive critical section. The old wait ticket cannot wake
    /// this entry after successful cancellation, even if the event arrives.
    ///
    /// # Safety
    /// Before calling, the trusted scheduler must have canceled actual
    /// saved GPR/IRET/FX frames, event/timer wakeups and in-flight CPU
    /// handoffs for this exact process generation. Neither this method nor
    /// Ring3RunQueue can establish that hardware/queue cancellation proof.
    pub unsafe fn cancel<'a, S: FrameSource, const FRAMES: usize,
        const CPUS: usize, const QUEUE: usize>(
        &self,
        queue: &mut Ring3RunQueue<QUEUE>,
        owner: &mut ActiveAddressSpace<'a, S, FRAMES, CPUS>,
    ) -> Result<(), Error> {
        if !matches!(self.state(queue)?, State::Ready | State::Blocked) {
            return Err(Error::WrongState);
        }
        let mut staged = *queue;
        staged.cancel(self.handle).map_err(Error::Queue)?;
        // SAFETY: cancellation of real saved frames/wakeups/handoffs is the
        // explicit external caller obligation stated above.
        unsafe { owner.revoke_saved_context(self.context) }.map_err(Error::Context)?;
        *queue = staged;
        Ok(())
    }
}
