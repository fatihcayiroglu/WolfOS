//! Allocation-free launch-page layout for bounded static x86-64 ET_EXEC images.
//!
//! This derives ALL user leaf virtual addresses, exact PT_LOAD permissions,
//! and a separate RW+NX stack from checked ELF bytes. No image bytes are
//! copied, PMM frames allocated, page tables written or CR3/IRET touched.
//!
//! Current real Ring3 smoke owns four table frames and three leaf frames:
//! at most TWO LOAD leaves plus stack execute there today. This reusable
//! contract permits up to THREE LOAD leaves, but a future runtime must first
//! obtain/pin the corresponding frame count and audit the actual PTEs.

use crate::elf64_preflight::{preflight, ElfError, ImagePlan, PAGE_BYTES, USER_END};

pub const MAX_LOAD_PAGES: usize = 3;
pub const MAX_LEAVES: usize = MAX_LOAD_PAGES + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchError {
    Elf(ElfError),
    TooManyLoadPages,
    StackOutOfRange,
    CrossesPageTable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchLeaf {
    pub virtual_address: u64,
    /// None is the fresh RW+NX stack; Some(n) indexes the ELF plan PT_LOAD.
    pub source_segment: Option<usize>,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticLaunchLayout {
    pub image: ImagePlan,
    pub leaves: [Option<LaunchLeaf>; MAX_LEAVES],
    pub len: usize,
    pub stack_page: u64,
}

impl StaticLaunchLayout {
    pub fn load_pages(&self) -> usize { self.len - 1 }
}

/// Strictly bounded staging contract for any supported static ELF image.
///
/// All LOAD leaves must fit one 2-MiB PT, and a clean stack is reserved at
/// the first page after the HIGHEST LOAD, not a user-supplied address.
/// Reject images whose stack overflows the canonical user range, crosses
/// that PT boundary, or needs more than three independently backed LOADs.
/// Return metadata only; no data or hardware state is changed on error.
pub fn plan_static_image(input: &[u8]) -> Result<StaticLaunchLayout, LaunchError> {
    let image = preflight(input).map_err(LaunchError::Elf)?;
    let mut leaves = [None; MAX_LEAVES];
    let mut count = 0usize;
    let mut highest_end = 0u64;

    for segment_index in 0..image.len {
        let segment = image.segments[segment_index]
            .ok_or(LaunchError::TooManyLoadPages)?;
        highest_end = highest_end.max(segment.page_end);
        let mut va = segment.page_start;
        while va < segment.page_end {
            if count == MAX_LOAD_PAGES {
                return Err(LaunchError::TooManyLoadPages);
            }
            leaves[count] = Some(LaunchLeaf {
                virtual_address: va,
                source_segment: Some(segment_index),
                writable: segment.writable,
                executable: segment.executable,
            });
            count += 1;
            va = va.checked_add(PAGE_BYTES).ok_or(LaunchError::TooManyLoadPages)?;
        }
    }
    if count == 0 { return Err(LaunchError::TooManyLoadPages); }
    let stack_page = highest_end;
    let stack_end = stack_page.checked_add(PAGE_BYTES)
        .ok_or(LaunchError::StackOutOfRange)?;
    if stack_end > USER_END {
        return Err(LaunchError::StackOutOfRange);
    }

    // A single four-level PML4/PDPT/PD/PT bank cannot represent pages
    // spanning different 2-MiB regions. Validate before a frame is owned.
    let first_region = leaves[0]
        .ok_or(LaunchError::TooManyLoadPages)?.virtual_address >> 21;
    if leaves[..count].iter().flatten().any(|leaf|
        leaf.virtual_address >> 21 != first_region
    ) || stack_page >> 21 != first_region {
        return Err(LaunchError::CrossesPageTable);
    }

    leaves[count] = Some(LaunchLeaf {
        virtual_address: stack_page,
        source_segment: None,
        writable: true,
        executable: false,
    });
    Ok(StaticLaunchLayout { image, leaves, len: count + 1, stack_page })
}
