//! Bounded process-associated surface retirement and GPU fence ledger.
//!
//! No allocation, unsafe, MMIO, DMA or actual GPU completion verification.
//! Only the trusted kernel may call ack_* AFTER checking a genuine used-ring
//! reply (index/head/length/type/nonce/fence), or authorize a PID generation.
//! A process exit revokes new renders immediately, but never frees DMA-pinned
//! storage while either transfer or flush acknowledgement remains outstanding.
//!
//! This contract is NOT a thread-safe lock or userspace capability table.
//! Callers must serialize all entrypoints with process teardown and rendering.

use super::damage::Rect;
use super::surface_pixels::{
    compose, CompositionReport, Error as PixelError, Identity, SurfacePixels,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidOwner,
    Full,
    GenerationExhausted,
    InvalidHandle,
    StaleHandle,
    StaleOwner,
    NotLive,
    Pending,
    InvalidFence,
    WrongFence,
    FlushBeforeTransfer,
    UnexpectedAck,
    StillLive,
    StillPinned,
    Pixel(PixelError),
}

/// Submitted means both commands remain unacknowledged. Transferred means
/// only the second, RESOURCE_FLUSH completion is still outstanding.
/// Closing variants deny rendering/new submissions and prevent reclamation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Live,
    Submitted,
    Transferred,
    Closing,
    ClosingSubmitted,
    ClosingTransferred,
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    identity: Option<Identity>,
    state: Option<State>,
    generation: u64,
    last_fence: u64,
    transfer_fence: u64,
    flush_fence: u64,
}

impl Entry {
    const fn empty() -> Self {
        Self {
            identity: None, state: None, generation: 0, last_fence: 0,
            transfer_fence: 0, flush_fence: 0,
        }
    }
}

/// Fixed-size trusted metadata; owns NO pixel storage or physical frames.
/// A released slot remembers its generations and last issued fence to refuse
/// ABA / replayed GPU acknowledgements after it is reused.
pub struct SurfaceLedger<const N: usize> {
    entries: [Entry; N],
}

impl<const N: usize> Default for SurfaceLedger<N> {
    fn default() -> Self { Self::new() }
}

impl<const N: usize> SurfaceLedger<N> {
    pub const fn new() -> Self {
        Self { entries: [Entry::empty(); N] }
    }

    /// The PID and its generation must come from the authenticated process
    /// registry, never directly from an application's untrusted arguments.
    pub fn open(&mut self, pid: u64, process_generation: u64)
        -> Result<Identity, Error>
    {
        if pid == 0 || process_generation == 0 {
            return Err(Error::InvalidOwner);
        }
        let mut exhausted = false;
        for (index, entry) in self.entries.iter_mut().enumerate() {
            if entry.identity.is_some() { continue; }
            if index >= u32::MAX as usize { return Err(Error::Full); }
            let Some(generation) = entry.generation.checked_add(1) else {
                exhausted = true;
                continue;
            };
            let identity = Identity {
                slot: index as u32 + 1,
                surface_generation: generation,
                pid,
                process_generation,
            };
            entry.identity = Some(identity);
            entry.state = Some(State::Live);
            entry.generation = generation;
            entry.transfer_fence = 0;
            entry.flush_fence = 0;
            return Ok(identity);
        }
        if exhausted { Err(Error::GenerationExhausted) } else { Err(Error::Full) }
    }

    fn entry(&self, identity: Identity) -> Result<&Entry, Error> {
        if identity.slot == 0 { return Err(Error::InvalidHandle); }
        let Some(entry) = self.entries.get(identity.slot as usize - 1) else {
            return Err(Error::InvalidHandle);
        };
        if entry.identity != Some(identity) { return Err(Error::StaleHandle); }
        Ok(entry)
    }

    fn entry_mut(&mut self, identity: Identity) -> Result<&mut Entry, Error> {
        if identity.slot == 0 { return Err(Error::InvalidHandle); }
        let Some(entry) = self.entries.get_mut(identity.slot as usize - 1) else {
            return Err(Error::InvalidHandle);
        };
        if entry.identity != Some(identity) { return Err(Error::StaleHandle); }
        Ok(entry)
    }

    pub fn state(&self, identity: Identity) -> Result<State, Error> {
        self.entry(identity)?.state.ok_or(Error::StaleHandle)
    }

    /// A pure authorization gate, NOT proof that a userspace address remains
    /// mapped or that an underlying GPU command has completed.
    pub fn require_live(&self, identity: Identity) -> Result<(), Error> {
        if self.state(identity)? != State::Live {
            return Err(Error::NotLive);
        }
        Ok(())
    }

    /// Enqueue contract: caller must still submit two genuinely fenced GPU
    /// commands, preserve backing pages and validate both hardware replies.
    /// Fence numbers strictly increase for the lifetime of a *slot*, even
    /// after that slot is recycled for a different owner.
    pub fn begin_submit(&mut self, identity: Identity,
                        transfer_fence: u64, flush_fence: u64)
        -> Result<(), Error>
    {
        let entry = self.entry_mut(identity)?;
        if entry.state != Some(State::Live) {
            return Err(Error::NotLive);
        }
        if transfer_fence == 0 || transfer_fence <= entry.last_fence
            || flush_fence <= transfer_fence
        {
            return Err(Error::InvalidFence);
        }
        entry.transfer_fence = transfer_fence;
        entry.flush_fence = flush_fence;
        entry.last_fence = flush_fence;
        entry.state = Some(State::Submitted);
        Ok(())
    }

    /// Must be invoked only by a trusted driver after the genuine transfer
    /// used-ring entry, response code and echoed fence were verified.
    pub fn ack_transfer(&mut self, identity: Identity, fence: u64)
        -> Result<(), Error>
    {
        let entry = self.entry_mut(identity)?;
        let next = match entry.state {
            Some(State::Submitted) => State::Transferred,
            Some(State::ClosingSubmitted) => State::ClosingTransferred,
            _ => return Err(Error::UnexpectedAck),
        };
        if fence == 0 || fence != entry.transfer_fence {
            return Err(Error::WrongFence);
        }
        entry.state = Some(next);
        Ok(())
    }

    /// Must follow a separately verified RESOURCE_FLUSH used-ring reply.
    /// Completion alone does not authorize freeing a *live* surface.
    pub fn ack_flush(&mut self, identity: Identity, fence: u64)
        -> Result<(), Error>
    {
        let entry = self.entry_mut(identity)?;
        let next = match entry.state {
            Some(State::Transferred) => State::Live,
            Some(State::ClosingTransferred) => State::Closing,
            Some(State::Submitted) | Some(State::ClosingSubmitted) =>
                return Err(Error::FlushBeforeTransfer),
            _ => return Err(Error::UnexpectedAck),
        };
        if fence == 0 || fence != entry.flush_fence {
            return Err(Error::WrongFence);
        }
        entry.state = Some(next);
        entry.transfer_fence = 0;
        entry.flush_fence = 0;
        Ok(())
    }

    /// Revoke ALL surfaces of one process generation in a single serialized
    /// operation. Future renders/submissions are refused; in-flight GPU DMA
    /// still keeps the underlying frames pinned until both real completions.
    /// A mismatching PID generation does not mutate any entries.
    pub fn close_owner(&mut self, pid: u64, process_generation: u64)
        -> Result<usize, Error>
    {
        if pid == 0 || process_generation == 0 {
            return Err(Error::InvalidOwner);
        }
        let found = self.entries.iter().any(|entry| {
            matches!(entry.identity, Some(identity)
                if identity.pid == pid
                    && identity.process_generation == process_generation)
        });
        if !found { return Err(Error::StaleOwner); }

        let mut count = 0;
        for entry in &mut self.entries {
            let matches_owner = matches!(entry.identity, Some(identity)
                if identity.pid == pid
                    && identity.process_generation == process_generation);
            if !matches_owner { continue; }
            entry.state = Some(match entry.state.expect("live identity has state") {
                State::Live | State::Closing => State::Closing,
                State::Submitted | State::ClosingSubmitted =>
                    State::ClosingSubmitted,
                State::Transferred | State::ClosingTransferred =>
                    State::ClosingTransferred,
            });
            count += 1;
        }
        Ok(count)
    }

    /// Produces a *logical* release permission only after explicit closure
    /// and all fenced replies. The caller is responsible for confirming no
    /// CPU references or outstanding DMA remain before actual PMM retirement.
    pub fn release(&mut self, identity: Identity) -> Result<Identity, Error> {
        let entry = self.entry_mut(identity)?;
        match entry.state {
            Some(State::Closing) => {}
            Some(State::ClosingSubmitted) | Some(State::ClosingTransferred)
                | Some(State::Submitted) | Some(State::Transferred) =>
                    return Err(Error::StillPinned),
            Some(State::Live) => return Err(Error::StillLive),
            None => return Err(Error::StaleHandle),
        };
        entry.identity = None;
        entry.state = None;
        entry.transfer_fence = 0;
        entry.flush_fence = 0;
        Ok(identity)
    }

    /// Reference-only software drawing. The ledger must be serialized by the
    /// kernel lock throughout validation AND composition, so a concurrent
    /// process teardown cannot invalidate backing while these slices are read.
    /// No GPU submission or hardware visibility is implied.
    #[allow(clippy::too_many_arguments)]
    pub fn compose_live(
        &self,
        destination: &mut [u32],
        background: &[u32],
        viewport: Rect,
        stride: usize,
        damage: Rect,
        first: SurfacePixels<'_>,
        second: SurfacePixels<'_>,
        top: Identity,
    ) -> Result<CompositionReport, Error> {
        self.require_live(first.identity())?;
        self.require_live(second.identity())?;
        compose(
            destination, background, viewport, stride, damage,
            first, second, [first.identity(), second.identity()], top,
        ).map_err(Error::Pixel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x:u32,y:u32,w:u32,h:u32) -> Rect {
        Rect::checked(x,y,w,h).unwrap()
    }

    #[test]
    fn close_revokes_all_buffers_and_preserves_every_rejected_pixel() {
        let mut ledger = SurfaceLedger::<3>::new();
        let a = ledger.open(77, 5).unwrap();
        let b = ledger.open(77, 5).unwrap();
        let other = ledger.open(88, 1).unwrap();
        let a_data = [0x00ff_0000; 4];
        let b_data = [0x0000_00ff; 4];
        let first = SurfacePixels::new(a, rect(1,1,2,2),2,&a_data).unwrap();
        let second = SurfacePixels::new(b,rect(2,1,2,2),2,&b_data).unwrap();
        let view = rect(0,0,5,4);
        let baseline = [7; 20];
        let mut destination = [0xdead; 20];
        let report = ledger.compose_live(
            &mut destination,&baseline,view,5,view,first,second,b
        ).unwrap();
        assert_eq!(report, CompositionReport {
            background: 14, first: 2, second: 4,
        });
        assert_eq!(destination[1*5 + 2],0x0000_00ff);
        assert_eq!(ledger.close_owner(77,5),Ok(2));
        assert_eq!(ledger.state(a),Ok(State::Closing));
        assert_eq!(ledger.state(b),Ok(State::Closing));
        assert_eq!(ledger.state(other),Ok(State::Live));
        destination.fill(0xdead);
        assert_eq!(
            ledger.compose_live(&mut destination,&baseline,view,5,view,
                                first,second,b),
            Err(Error::NotLive)
        );
        assert_eq!(destination,[0xdead;20]);
        assert_eq!(ledger.begin_submit(a,1,2),Err(Error::NotLive));
        assert_eq!(ledger.close_owner(77,999),Err(Error::StaleOwner));
        assert_eq!(ledger.release(a),Ok(a));
        assert_eq!(ledger.release(b),Ok(b));
        assert_eq!(ledger.release(a),Err(Error::StaleHandle));
    }

    #[test]
    fn process_exit_does_not_free_outstanding_transfer_or_flush() {
        let mut ledger = SurfaceLedger::<1>::new();
        let a = ledger.open(10, 1).unwrap();
        assert_eq!(ledger.release(a),Err(Error::StillLive));
        assert_eq!(ledger.begin_submit(a,100,101),Ok(()));
        assert_eq!(ledger.begin_submit(a,102,103),Err(Error::NotLive));
        assert_eq!(ledger.ack_flush(a,101),Err(Error::FlushBeforeTransfer));
        assert_eq!(ledger.close_owner(10,1),Ok(1));
        assert_eq!(ledger.state(a),Ok(State::ClosingSubmitted));
        assert_eq!(ledger.release(a),Err(Error::StillPinned));
        assert_eq!(ledger.ack_transfer(a,102),Err(Error::WrongFence));
        assert_eq!(ledger.ack_transfer(a,100),Ok(()));
        assert_eq!(ledger.ack_transfer(a,100),Err(Error::UnexpectedAck));
        assert_eq!(ledger.state(a),Ok(State::ClosingTransferred));
        assert_eq!(ledger.release(a),Err(Error::StillPinned));
        assert_eq!(ledger.ack_flush(a,100),Err(Error::WrongFence));
        assert_eq!(ledger.ack_flush(a,101),Ok(()));
        assert_eq!(ledger.state(a),Ok(State::Closing));
        assert_eq!(ledger.ack_flush(a,101),Err(Error::UnexpectedAck));
        assert_eq!(ledger.release(a),Ok(a));
        assert_eq!(ledger.ack_transfer(a,100),Err(Error::StaleHandle));
    }

    #[test]
    fn monotonic_surface_and_gpu_fence_generations_survive_reuse() {
        let mut ledger = SurfaceLedger::<1>::new();
        let old = ledger.open(12,1).unwrap();
        ledger.begin_submit(old,5,6).unwrap();
        ledger.ack_transfer(old,5).unwrap();
        ledger.ack_flush(old,6).unwrap();
        ledger.close_owner(12,1).unwrap();
        ledger.release(old).unwrap();

        let fresh = ledger.open(12,2).unwrap();
        assert_eq!(fresh.slot,old.slot);
        assert!(fresh.surface_generation > old.surface_generation);
        assert_eq!(ledger.require_live(old),Err(Error::StaleHandle));
        assert_eq!(ledger.close_owner(12,1),Err(Error::StaleOwner));
        assert_eq!(ledger.begin_submit(fresh,5,6),Err(Error::InvalidFence));
        assert_eq!(ledger.begin_submit(fresh,7,8),Ok(()));
        assert_eq!(ledger.ack_transfer(fresh,5),Err(Error::WrongFence));
        assert_eq!(ledger.ack_flush(fresh,8),Err(Error::FlushBeforeTransfer));
        ledger.ack_transfer(fresh,7).unwrap();
        ledger.ack_flush(fresh,8).unwrap();
        assert_eq!(ledger.state(fresh),Ok(State::Live));
    }

    #[test]
    fn capacity_bad_owner_and_close_two_different_states() {
        let mut ledger = SurfaceLedger::<2>::new();
        assert_eq!(ledger.open(0,1),Err(Error::InvalidOwner));
        assert_eq!(ledger.open(1,0),Err(Error::InvalidOwner));
        let first = ledger.open(1,1).unwrap();
        let second = ledger.open(1,1).unwrap();
        assert_eq!(ledger.open(2,1),Err(Error::Full));
        assert_eq!(ledger.close_owner(2,1),Err(Error::StaleOwner));
        ledger.begin_submit(first,12,13).unwrap();
        ledger.ack_transfer(first,12).unwrap();
        assert_eq!(ledger.close_owner(1,1),Ok(2));
        assert_eq!(ledger.state(first),Ok(State::ClosingTransferred));
        assert_eq!(ledger.state(second),Ok(State::Closing));
        assert_eq!(ledger.release(first),Err(Error::StillPinned));
        assert_eq!(ledger.release(second),Ok(second));
        assert_eq!(ledger.open(2,2).unwrap().slot,second.slot);
        assert_eq!(ledger.ack_flush(first,13),Ok(()));
        assert_eq!(ledger.release(first),Ok(first));
    }

    #[test]
    fn pixel_contract_rejection_and_inflight_authorization_are_fail_closed() {
        let mut ledger = SurfaceLedger::<2>::new();
        let a = ledger.open(7,1).unwrap();
        let b = ledger.open(8,1).unwrap();
        let red = [0x00aabbcc; 4];
        let blue = [0x000000ee; 4];
        let first = SurfacePixels::new(a,rect(1,1,2,2),2,&red).unwrap();
        let second = SurfacePixels::new(b,rect(2,2,2,2),2,&blue).unwrap();
        let view=rect(0,0,5,5);
        let background=[0;25];
        let mut dest=[0xf00;25];
        assert_eq!(ledger.compose_live(&mut dest,&background,view,5,view,
                    first,second,Identity{slot:999,..a}),
                   Err(Error::Pixel(PixelError::InvalidTop)));
        assert_eq!(dest,[0xf00;25]);
        ledger.begin_submit(a,1,2).unwrap();
        assert_eq!(ledger.compose_live(&mut dest,&background,view,5,view,
                    first,second,a),Err(Error::NotLive));
        assert_eq!(dest,[0xf00;25]);
        ledger.ack_transfer(a,1).unwrap();
        ledger.ack_flush(a,2).unwrap();
        assert_eq!(ledger.compose_live(&mut dest,&background,view,5,view,
                    first,second,a).unwrap().first,4);
    }

    #[test]
    fn empty_ledger_refuses_unknown_handles_without_panicking() {
        let ledger=SurfaceLedger::<0>::new();
        assert_eq!(ledger.state(Identity{
            slot: 1,surface_generation:1,pid:1,process_generation:1,
        }),Err(Error::InvalidHandle));
        let mut ledger=SurfaceLedger::<0>::new();
        assert_eq!(ledger.open(1,1),Err(Error::Full));
    }
}
