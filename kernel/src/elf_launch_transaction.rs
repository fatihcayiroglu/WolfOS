//! Counted prepublication ELF ownership with consuming preparation stages.
//!
//! This composes existing mechanisms; it does not own HHDM views, publish a
//! process record, load CR3 or certify final image admission. Only an explicit
//! unsafe consuming transfer may turn its staging lease into an active owner.
//! Drop retains FrameBatch's best-effort rollback policy. Use abort to inspect
//! release failures; a failed release remains allocated and is never retried.

use core::marker::PhantomData;

use crate::{
    active_address_space::{ActiveAddressSpace, PublishError},
    elf64_page_image::PageContents,
    pmm_frame_batch::{AcquireError, FrameBatch, FrameSource, ReleaseReport},
    user_elf_launch_layout::{LaunchError, MAX_LOAD_PAGES, plan_bounded_with_budget},
    user_elf_page_tables::{ElfPageTables, MappingError, OwnedLeafPage, StageError, TableBuffers},
};

pub struct Reserved;
pub struct PayloadReady;
pub struct TablesReady;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReserveError {
    InvalidSlot,
    Image(LaunchError),
    Allocation(AcquireError),
    Binding {
        error: MappingError,
        rollback: ReleaseReport,
    },
}

pub type StagingReport = [Option<PageContents>; MAX_LOAD_PAGES];

/// CAP is storage capacity, never an allocation request. The validated ELF
/// determines the leased prefix. Private fields and consuming stages prevent
/// this API from publishing before both payload and table preparation.
#[must_use = "dropping this unpublished owner rolls back its exact frame lease"]
pub struct ElfLaunch<'frames, 'image, S: FrameSource, const CAP: usize, Stage> {
    batch: FrameBatch<'frames, S, CAP>,
    recipe: ElfPageTables,
    image: &'image [u8],
    stage: PhantomData<Stage>,
}

impl<'frames, 'image, S: FrameSource, const CAP: usize>
    ElfLaunch<'frames, 'image, S, CAP, Reserved>
{
    /// Validate the image and count before allocating. Frame/placement
    /// binding happens before any destination writes; its rejection closes
    /// the complete lease and explicitly reports every rollback failure.
    pub fn reserve(
        source: &'frames mut S,
        image: &'image [u8],
        slot: usize,
    ) -> Result<Self, ReserveError> {
        if !(1..256).contains(&slot) {
            return Err(ReserveError::InvalidSlot);
        }
        let plan = plan_bounded_with_budget(image).map_err(ReserveError::Image)?;
        let batch = FrameBatch::acquire_count(source, plan.frames.total_frames)
            .map_err(ReserveError::Allocation)?;
        let recipe = match ElfPageTables::bind(image, slot, batch.leased_frames()) {
            Ok(recipe) => recipe,
            Err(error) => {
                let rollback = batch.close();
                return Err(ReserveError::Binding { error, rollback });
            }
        };
        Ok(Self {
            batch,
            recipe,
            image,
            stage: PhantomData,
        })
    }

    /// Failure returns the still-owned transaction without changing its
    /// state or any backing bytes. Correct buffers and retry, or abort.
    pub fn stage_payload(
        self,
        loads: &mut [OwnedLeafPage<'_>],
        stack: &mut OwnedLeafPage<'_>,
    ) -> Result<
        (
            ElfLaunch<'frames, 'image, S, CAP, PayloadReady>,
            StagingReport,
        ),
        (Self, StageError),
    > {
        let report = match self.recipe.stage_load_and_stack(self.image, loads, stack) {
            Ok(report) => report,
            Err(error) => return Err((self, error)),
        };
        Ok((self.into_stage(), report))
    }
}

impl<'frames, 'image, S: FrameSource, const CAP: usize>
    ElfLaunch<'frames, 'image, S, CAP, PayloadReady>
{
    /// The buffers must be disconnected from every CPU. A rejected bank
    /// retains ownership for retry/abort; no PID, CR3 or active owner exists.
    pub fn build_tables(
        self,
        tables: &mut TableBuffers<'_>,
    ) -> Result<ElfLaunch<'frames, 'image, S, CAP, TablesReady>, (Self, MappingError)> {
        if let Err(error) = self
            .recipe
            .populate(tables)
            .and_then(|_| self.recipe.audit(tables))
        {
            return Err((self, error));
        }
        Ok(self.into_stage())
    }
}

impl<'frames, 'image, S: FrameSource, const CAP: usize>
    ElfLaunch<'frames, 'image, S, CAP, TablesReady>
{
    /// Transfer the staging guard; no CR3 load or PMM release happens here.
    /// Publication failure returns the same fully prepared staging owner.
    ///
    /// # Safety
    /// These stage types record completed operations, not live hardware or
    /// pointer provenance. Before transfer, authenticate every HHDM buffer
    /// against this lease, perform final complete ELF-byte/PTE/stack/kernel
    /// graft admission, and keep the admitted bytes/mappings stable. No CPU,
    /// saved execution context, walker or device may reference the root yet.
    /// Every future CR3 load must use the returned active owner's reservation
    /// gate. The provider must honor FrameSource's exclusive ownership rules.
    pub unsafe fn publish<const CPUS: usize>(
        self,
        generation: u64,
        supervisor: u64,
    ) -> Result<ActiveAddressSpace<'frames, S, CAP, CPUS>, (Self, PublishError)> {
        let Self {
            batch,
            recipe,
            image,
            ..
        } = self;
        let root = batch.leased_frames()[0];
        match ActiveAddressSpace::publish(batch, generation, root, supervisor) {
            Ok(owner) => Ok(owner),
            Err((batch, error)) => Err((
                Self {
                    batch,
                    recipe,
                    image,
                    stage: PhantomData,
                },
                error,
            )),
        }
    }
}

impl<'frames, 'image, S: FrameSource, const CAP: usize, Stage>
    ElfLaunch<'frames, 'image, S, CAP, Stage>
{
    /// Borrowed addresses are metadata, never permission to publish/free.
    pub fn leased_frames(&self) -> &[u64] {
        self.batch.leased_frames()
    }

    pub fn recipe(&self) -> &ElfPageTables {
        &self.recipe
    }

    /// Explicit rollback evidence. The caller must end all physical-buffer
    /// borrows and keep the root unpublished before releasing this lease.
    pub fn abort(self) -> ReleaseReport {
        self.batch.close()
    }

    fn into_stage<Next>(self) -> ElfLaunch<'frames, 'image, S, CAP, Next> {
        ElfLaunch {
            batch: self.batch,
            recipe: self.recipe,
            image: self.image,
            stage: PhantomData,
        }
    }
}
