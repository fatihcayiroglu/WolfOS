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
    CrossesPageDirectory,
    TooManyPageTables,
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
    plan_with_table_limit(input, 1)
}

/// The same byte-derived layout, with a second PMM-owned PT allowed.
/// LOAD leaves and the fresh RW+NX stack may straddle TWO 2-MiB regions
/// inside ONE 1-GiB PDPT region; a separate audited two-PT VMM is required.
/// No page table, process or hardware state is changed here.
pub fn plan_two_pt_image(input: &[u8]) -> Result<StaticLaunchLayout, LaunchError> {
    plan_with_table_limit(input, 2)
}

fn plan_with_table_limit(input: &[u8], table_limit: usize)
    -> Result<StaticLaunchLayout, LaunchError>
{
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

    leaves[count] = Some(LaunchLeaf {
        virtual_address: stack_page,
        source_segment: None,
        writable: true,
        executable: false,
    });
    let len = count + 1;
    // Both paths must fit one PDPT entry (1 GiB); they differ only in the
    // permitted number of distinct 2-MiB PT regions. The legacy contract
    // preserves its original CrossesPageTable rejection.
    let first = leaves[0]
        .ok_or(LaunchError::TooManyLoadPages)?.virtual_address;
    let mut regions = [0u64; 2];
    let mut used = 0usize;
    for leaf in leaves[..len].iter().flatten() {
        if leaf.virtual_address >> 30 != first >> 30 {
            return Err(if table_limit == 1 {
                LaunchError::CrossesPageTable
            } else {
                LaunchError::CrossesPageDirectory
            });
        }
        let region = leaf.virtual_address >> 21;
        if !regions[..used].contains(&region) {
            if used == table_limit {
                return Err(if table_limit == 1 {
                    LaunchError::CrossesPageTable
                } else {
                    LaunchError::TooManyPageTables
                });
            }
            regions[used] = region;
            used += 1;
        }
    }
    Ok(StaticLaunchLayout { image, leaves, len, stack_page })
}
