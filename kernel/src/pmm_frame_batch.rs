//! Staging-only, no-heap ownership of a fixed batch of PMM frames.
//!
//! Every successfully allocated frame is returned exactly once on explicit
//! close, partial-allocation failure, or an early scope exit (Drop). A future
//! runnable process must first consume this guard through the separate
//! ActiveAddressSpace owner; never install frames while still staged.
//!
//! The provider guarantees unique, aligned, owned PMM frame addresses.
//! This is a lifetime/rollback primitive, not a physical allocator, page
//! mapper, frame pinning implementation, or active-user-process retirement.

/// The source owns its allocator internals. Each successful allocate adds
/// exactly one new frame to the caller's temporary ownership; release
/// returns it exactly once. Release failure is explicitly reported by close.
pub trait FrameSource {
    fn allocate(&mut self) -> Option<u64>;
    fn release(&mut self, frame: u64) -> bool;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseReport {
    pub released: usize,
    pub failed: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcquireError {
    Exhausted {
        acquired: usize,
        rollback: ReleaseReport,
    },
    InvalidCount { requested: usize, capacity: usize },
}

/// Retains exclusive staged-frame ownership. No copy/clone or implicit
/// disarm path exists: dropping it MUST return all remaining frames unless
/// it has been consumed by the explicit ActiveAddressSpace transfer.
#[must_use = "staged PMM frames are released when this owner is dropped"]
pub struct FrameBatch<'a, S: FrameSource, const N: usize> {
    source: &'a mut S,
    frames: [u64; N],
    live: usize,
}

impl<'a, S: FrameSource, const N: usize> FrameBatch<'a, S, N> {
    /// Fail atomically on the FIRST allocation miss. Unlike an open-coded
    /// loop, all preceding successful allocations are rolled back in reverse
    /// order before returning an error with explicit cleanup evidence.
    pub fn acquire(source: &'a mut S) -> Result<Self, AcquireError> {
        Self::acquire_bounded(source, N)
    }

    /// Allocate precisely `requested` frames, not the full array capacity.
    /// Reject empty or oversized leases WITHOUT asking the provider for any
    /// frames. Counts come from validated image metadata, never raw ELF fields.
    /// Unused array entries remain zero and are not transferred or released.
    pub fn acquire_count(source: &'a mut S, requested: usize) -> Result<Self, AcquireError> {
        if requested == 0 || requested > N {
            return Err(AcquireError::InvalidCount { requested, capacity: N });
        }
        Self::acquire_bounded(source, requested)
    }

    fn acquire_bounded(source: &'a mut S, requested: usize) -> Result<Self, AcquireError> {
        let mut batch = Self {
            source,
            frames: [0; N],
            live: 0,
        };
        while batch.live < requested {
            let Some(frame) = batch.source.allocate() else {
                let acquired = batch.live;
                let rollback = batch.release_all();
                return Err(AcquireError::Exhausted { acquired, rollback });
            };
            batch.frames[batch.live] = frame;
            batch.live += 1;
        }
        Ok(batch)
    }

    /// Frames remain owned by this guard; borrowed addresses never transfer
    /// the right to free or publish them as a running userspace image.
    pub fn frames(&self) -> &[u64; N] {
        &self.frames
    }

    /// Only the currently leased frames, excluding the unused zero tail.
    /// Ownership and publication checks MUST use this bounded slice.
    pub fn leased_frames(&self) -> &[u64] {
        &self.frames[..self.live]
    }

    fn release_all(&mut self) -> ReleaseReport {
        let mut report = ReleaseReport { released: 0, failed: 0 };
        while self.live != 0 {
            self.live -= 1;
            let frame = self.frames[self.live];
            self.frames[self.live] = 0;
            if self.source.release(frame) {
                report.released += 1;
            } else {
                report.failed += 1;
            }
        }
        report
    }

    /// Explicit success/error visibility at a supervisor checkpoint. The
    /// subsequent Drop is a no-op, even if a backend release reported error.
    pub fn close(mut self) -> ReleaseReport {
        self.release_all()
    }
}

impl<'a, S: FrameSource, const N: usize> Drop for FrameBatch<'a, S, N> {
    fn drop(&mut self) {
        // Best effort on early return. Explicit close must be used wherever
        // the caller needs evidence of successful PMM accounting.
        let _ = self.release_all();
    }
}
