//! Allocation-free launch-page layout for bounded static x86-64 ET_EXEC images.
//!
//! This derives ALL user leaf virtual addresses, exact PT_LOAD permissions,
//! and a separate RW+NX stack from checked ELF bytes. No image bytes are
//! copied, PMM frames allocated, page tables written or CR3/IRET touched.
//!
//! Genuine one-PT Ring3 gates now lease six or seven frames depending on
//! actual independently linked ELF LOAD pages; two-PT gates lease eight or
//! nine. The nonallocating frame budget is checked before PMM allocation.

use crate::elf64_preflight::{preflight, ElfError, ImagePlan, PAGE_BYTES, USER_END};

pub const MAX_LOAD_PAGES: usize = 3;
pub const MAX_LEAVES: usize = MAX_LOAD_PAGES + 1;
pub const ONE_PT_TABLE_FRAMES: usize = 4;
pub const TWO_PT_TABLE_FRAMES: usize = 5;

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

/// Exact nonallocating PMM requirement derived from validated ELF leaves.
/// The sole stack occupies one independent RW+NX page; the paging hierarchy
/// consumes either four (one PT) or five (two PTs) distinct table frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchFrameBudget {
    pub table_frames: usize,
    pub load_frames: usize,
    pub stack_frames: usize,
    pub leaf_frames: usize,
    pub total_frames: usize,
}

impl LaunchFrameBudget {
    /// Reject fixed smoke reservations that disagree with the checked ELF.
    /// Runtime callers must check this BEFORE asking PMM for any frames.
    pub fn matches_exact_lease(&self, tables: usize, total: usize) -> bool {
        self.table_frames == tables && self.total_frames == total
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetedLaunch {
    pub layout: StaticLaunchLayout,
    pub frames: LaunchFrameBudget,
}

fn budgeted(layout: StaticLaunchLayout, tables: usize) -> BudgetedLaunch {
    let load = layout.load_pages();
    let stack = 1;
    let leaf = load + stack;
    BudgetedLaunch {
        layout,
        frames: LaunchFrameBudget {
            table_frames: tables,
            load_frames: load,
            stack_frames: stack,
            leaf_frames: leaf,
            total_frames: tables + leaf,
        },
    }
}

/// One-PT ELF metadata and exact PMM lease count, with no allocation.
pub fn plan_one_pt_with_budget(input: &[u8]) -> Result<BudgetedLaunch, LaunchError> {
    Ok(budgeted(plan_static_image(input)?, ONE_PT_TABLE_FRAMES))
}

/// Two-PT ELF metadata and exact PMM lease count, with no allocation.
pub fn plan_two_pt_with_budget(input: &[u8]) -> Result<BudgetedLaunch, LaunchError> {
    Ok(budgeted(plan_two_pt_image(input)?, TWO_PT_TABLE_FRAMES))
}

/// Choose the exact hierarchy from ELF leaves, including the fresh stack.
/// Unlike the fixed one/two-PT contracts, no fixture flag chooses the budget.
/// At most two distinct 2-MiB regions inside one 1-GiB directory are supported.
pub fn plan_bounded_with_budget(input: &[u8]) -> Result<BudgetedLaunch, LaunchError> {
    let layout = plan_two_pt_image(input)?;
    let mut regions = [None; 2];
    let mut used = 0;
    for leaf in layout.leaves[..layout.len].iter().flatten() {
        let region = Some(leaf.virtual_address >> 21);
        if !regions[..used].contains(&region) {
            regions[used] = region;
            used += 1;
        }
    }
    Ok(budgeted(layout, 3 + used))
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
