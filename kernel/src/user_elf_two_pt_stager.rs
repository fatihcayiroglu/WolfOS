//! Non-allocating, fail-closed ELF -> private owned two-PT leaf staging.
//!
//! The trusted caller leases exactly the necessary PMM frames and supplies
//! distinct zeroed 4-KiB mutable HHDM buffers. This helper validates ALL
//! ELF leaves and frame assignments before writing ANY LOAD buffer. It never
//! edits PTEs, takes PMM ownership, activates CR3, or accepts user pointers.
//! A separate full PTE/byte/HHDM admission remains mandatory before IRET.

use crate::elf64_page_image::{materialize_bounded, MaterializeError, PageContents, PAGE_SIZE};
use crate::elf64_preflight::LoadSegment;
use crate::user_elf_launch_layout::MAX_LOAD_PAGES;
use crate::user_vm_two_pt::{
    derive_relocated_elf_pages, RelocatedElfPages, TwoPtElfError, TABLE_FRAMES,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageError {
    Manifest(TwoPtElfError),
    BackingCount,
    DirtyOwnedFrame,
    MissingLeafSource,
    Materialize(MaterializeError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StagedTwoPtElf {
    pub manifest: RelocatedElfPages,
    pub copied: [Option<PageContents>; MAX_LOAD_PAGES],
}

/// Stage one, two or three PT_LOAD pages plus an independent zeroed stack.
/// Exactly one LOAD buffer must correspond to each ordered ELF-derived leaf.
/// All buffers are exclusively borrowed and pre-zeroed by the PMM owner.
/// Every source range is inspected BEFORE writing the first destination.
/// On validation failure, every supplied destination remains byte-identical.
pub fn stage_relocated_two_pt_elf(
    image: &[u8],
    slot: usize,
    tables: [u64; TABLE_FRAMES],
    frames: &[u64],
    buffers: &mut [&mut [u8; PAGE_SIZE]],
    stack: &mut [u8; PAGE_SIZE],
) -> Result<StagedTwoPtElf, StageError> {
    let manifest = derive_relocated_elf_pages(image, slot, tables, frames)
        .map_err(StageError::Manifest)?;
    let source = &manifest.layout.source;
    let count = source.load_pages();
    if count == 0 || count > MAX_LOAD_PAGES || buffers.len() != count {
        return Err(StageError::BackingCount);
    }
    if buffers.iter().any(|bytes| bytes.iter().any(|byte| *byte != 0))
        || stack.iter().any(|byte| *byte != 0)
    { return Err(StageError::DirtyOwnedFrame) }

    let first = source.image.segments[0].as_ref().ok_or(StageError::MissingLeafSource)?;
    let mut requests: [(&LoadSegment, u64); MAX_LOAD_PAGES] =
        [(first, 0); MAX_LOAD_PAGES];
    for (i, request) in requests[..count].iter_mut().enumerate() {
        let leaf = source.leaves[i].ok_or(StageError::MissingLeafSource)?;
        let index = leaf.source_segment.ok_or(StageError::MissingLeafSource)?;
        let segment = source.image.segments[index].as_ref()
            .ok_or(StageError::MissingLeafSource)?;
        *request = (segment, leaf.virtual_address);
    }
    let copied = materialize_bounded::<MAX_LOAD_PAGES>(
        image, &requests[..count], buffers,
    ).map_err(StageError::Materialize)?;
    Ok(StagedTwoPtElf { manifest, copied })
}
