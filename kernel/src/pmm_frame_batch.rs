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

/// Rejection of an external PMM ownership handoff. The complete input frame
/// array is returned to the caller on every error; the source is untouched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdoptError {
    InvalidCount { requested: usize, capacity: usize },
    InvalidFrame { index: usize, frame: u64 },
    DuplicateFrame { index: usize, first_index: usize },
    NonzeroTail { index: usize, frame: u64 },
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

    /// Transfer an already allocated PMM frame prefix into a move-only staged
    /// owner. This makes existing kernel PMM allocations eligible for the
    /// same rollback and later ActiveAddressSpace publication path as frames
    /// allocated by `acquire_count`.
    ///
    /// No allocate/release call occurs during adoption or its validation.
    /// Rejection returns the unchanged descriptor, and does not transfer
    /// ownership: the caller remains responsible for its original frames.
    /// Successful adoption disarms the caller's prior manual cleanup path;
    /// dropping the returned guard releases each frame once in reverse order.
    ///
    /// # Safety
    /// The caller must prove that every frame in `frames[..requested]` is a
    /// live, exclusive allocation from THIS `source`, with no other owner or
    /// pending cleanup path. The caller must not read/write freed frames or
    /// independently release them after success. Address validation cannot
    /// establish PMM provenance, DMA quiescence or absence of stale CR3/TLB
    /// references. Publish via ActiveAddressSpace before any CPU uses them.
    pub unsafe fn adopt_allocated(
        source: &'a mut S,
        frames: [u64; N],
        requested: usize,
    ) -> Result<Self, (AdoptError, [u64; N])> {
        if requested == 0 || requested > N {
            return Err((AdoptError::InvalidCount { requested, capacity: N }, frames));
        }
        for index in 0..requested {
            let frame = frames[index];
            if frame == 0 || frame >= (1 << 52) || frame & 4095 != 0 {
                return Err((AdoptError::InvalidFrame { index, frame }, frames));
            }
            if let Some(first_index) = frames[..index].iter().position(|candidate| *candidate == frame) {
                return Err((AdoptError::DuplicateFrame { index, first_index }, frames));
            }
        }
        for index in requested..N {
            if frames[index] != 0 {
                return Err((AdoptError::NonzeroTail { index, frame: frames[index] }, frames));
            }
        }
        Ok(Self { source, frames, live: requested })
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
