//! Fail-closed TWO-PT user shadow hierarchy for bounded static ELF staging.
//!
//! Five private table frames form PML4 -> PDPT -> PD -> two 4-KiB PTs.
//! At most eight disjoint user leaves may reside in TWO 2-MiB regions of ONE
//! 1-GiB directory. No CR3 switch, HHDM borrow, PMM ownership, IRET or
//! user executable admission occurs here. Every rejected populate is atomic.

use crate::elf64_preflight::PAGE_BYTES;
use crate::user_vm_layout::{indices, ENTRY_COUNT, NX, PRESENT, USER, WRITABLE};
use crate::user_vm_multi::UserPage;
use crate::user_elf_launch_layout::{plan_two_pt_image, LaunchError, StaticLaunchLayout, MAX_LEAVES};

pub const TABLE_FRAMES: usize = 5;
pub const MAX_PAGES: usize = 8;
const PHYSICAL_END: u64 = 1 << 52;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwoPtError {
    EmptyOrOversized,
    InvalidPhysicalFrame,
    AliasedPhysicalFrame,
    InvalidVirtualPage,
    DifferentDirectory,
    TooManyPageTables,
    DuplicateVirtualPage,
    WriteExecute,
    DirtyDestination,
    MismatchedLayout,
}

#[derive(Clone, Copy)]
struct Layout {
    pml4: usize,
    pdpt: usize,
    regions: [Option<u64>; 2],
    any_writable: bool,
}

fn frame_ok(frame: u64) -> bool {
    frame != 0 && frame % PAGE_BYTES == 0 && frame < PHYSICAL_END
}

fn validate(frames: [u64; TABLE_FRAMES], pages: &[UserPage])
    -> Result<Layout, TwoPtError>
{
    if pages.is_empty() || pages.len() > MAX_PAGES {
        return Err(TwoPtError::EmptyOrOversized);
    }
    for (i, frame) in frames.iter().copied().enumerate() {
        if !frame_ok(frame) { return Err(TwoPtError::InvalidPhysicalFrame); }
        if frames[..i].contains(&frame) {
            return Err(TwoPtError::AliasedPhysicalFrame);
        }
    }
    let mut first = None;
    let mut regions = [None; 2];
    let mut regions_used = 0;
    let mut any_writable = false;
    for (i, page) in pages.iter().enumerate() {
        if !frame_ok(page.physical_frame) {
            return Err(TwoPtError::InvalidPhysicalFrame);
        }
        if frames.contains(&page.physical_frame)
            || pages[..i].iter().any(|earlier|
                earlier.physical_frame == page.physical_frame)
        {
            return Err(TwoPtError::AliasedPhysicalFrame);
        }
        if page.writable && page.executable {
            return Err(TwoPtError::WriteExecute);
        }
        let ix = indices(page.virtual_address)
            .map_err(|_| TwoPtError::InvalidVirtualPage)?;
        if let Some((pml4, pdpt)) = first {
            if pml4 != ix.pml4 || pdpt != ix.pdpt {
                return Err(TwoPtError::DifferentDirectory);
            }
        } else {
            first = Some((ix.pml4, ix.pdpt));
        }
        if pages[..i].iter().any(|earlier|
            earlier.virtual_address == page.virtual_address)
        {
            return Err(TwoPtError::DuplicateVirtualPage);
        }
        let region = page.virtual_address >> 21;
        if !regions[..regions_used].contains(&Some(region)) {
            if regions_used == 2 { return Err(TwoPtError::TooManyPageTables); }
            regions[regions_used] = Some(region);
            regions_used += 1;
        }
        any_writable |= page.writable;
    }
    let (pml4, pdpt) = first.expect("nonempty page list validated");
    Ok(Layout { pml4, pdpt, regions, any_writable })
}

fn parent(writable: bool) -> u64 {
    PRESENT | USER | if writable { WRITABLE } else { 0 }
}

fn leaf(page: &UserPage) -> u64 {
    page.physical_frame | PRESENT | USER
        | if page.writable { WRITABLE } else { 0 }
        | if page.executable { 0 } else { NX }
}

fn table_index(layout: &Layout, va: u64) -> usize {
    layout.regions.iter().position(|region| *region == Some(va >> 21))
        .expect("validated region must have a PT")
}

/// Write all five EMPTY tables only after validating every frame, user leaf,
/// permission, shared 1-GiB directory and destination entry. A failed call
/// must not modify any table or physical allocation.
pub fn populate(
    pml4: &mut [u64; ENTRY_COUNT],
    pdpt: &mut [u64; ENTRY_COUNT],
    pd: &mut [u64; ENTRY_COUNT],
    pt0: &mut [u64; ENTRY_COUNT],
    pt1: &mut [u64; ENTRY_COUNT],
    frames: [u64; TABLE_FRAMES],
    pages: &[UserPage],
) -> Result<(), TwoPtError> {
    let layout = validate(frames, pages)?;
    if pml4.iter().chain(pdpt.iter()).chain(pd.iter())
        .chain(pt0.iter()).chain(pt1.iter()).any(|entry| *entry != 0)
    {
        return Err(TwoPtError::DirtyDestination);
    }
    let flags = parent(layout.any_writable);
    pml4[layout.pml4] = frames[1] | flags;
    pdpt[layout.pdpt] = frames[2] | flags;
    for (i, region) in layout.regions.iter().enumerate() {
        if let Some(region) = region {
            pd[(*region & 511) as usize] = frames[3 + i] | flags;
        }
    }
    for page in pages {
        let index = ((page.virtual_address >> 12) & 511) as usize;
        if table_index(&layout, page.virtual_address) == 0 {
            pt0[index] = leaf(page);
        } else {
            pt1[index] = leaf(page);
        }
    }
    Ok(())
}

/// Compare ALL 2,560 entries against the exact expected two-PT hierarchy,
/// including unused PT and high-half PML4 slots. Even one extra executable
/// alias, parent bit escalation or swapped physical frame fails closed.
pub fn audit(
    pml4: &[u64; ENTRY_COUNT],
    pdpt: &[u64; ENTRY_COUNT],
    pd: &[u64; ENTRY_COUNT],
    pt0: &[u64; ENTRY_COUNT],
    pt1: &[u64; ENTRY_COUNT],
    frames: [u64; TABLE_FRAMES],
    pages: &[UserPage],
) -> Result<(), TwoPtError> {
    let layout = validate(frames, pages)?;
    let flags = parent(layout.any_writable);
    for i in 0..ENTRY_COUNT {
        let root_expected = if i == layout.pml4 { frames[1] | flags } else { 0 };
        let pdpt_expected = if i == layout.pdpt { frames[2] | flags } else { 0 };
        let mut pd_expected = 0;
        for (slot, region) in layout.regions.iter().enumerate() {
            if region.is_some_and(|region| (region & 511) as usize == i) {
                pd_expected = frames[3 + slot] | flags;
            }
        }
        if pml4[i] != root_expected || pdpt[i] != pdpt_expected
            || pd[i] != pd_expected
        {
            return Err(TwoPtError::MismatchedLayout);
        }
        for (slot, pt) in [pt0, pt1].into_iter().enumerate() {
            let expected = pages.iter().find(|page|
                layout.regions[slot] == Some(page.virtual_address >> 21)
                    && ((page.virtual_address >> 12) & 511) as usize == i
            ).map_or(0, leaf);
            if pt[i] != expected {
                return Err(TwoPtError::MismatchedLayout);
            }
        }
    }
    Ok(())
}

/// Exact ELF-to-PTE binding, independent of a caller's claimed page list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwoPtElfError {
    InvalidUserSlot,
    AddressOverflow,
    Image(LaunchError),
    MissingOrExtraPage,
    PermissionMismatch,
    Mapping(TwoPtError),
}

/// Check each LOAD leaf and the sole RW+NX stack against the immutable ELF.
/// Does not allocate any frames or touch the proposed destination tables.
pub fn validate_elf_bindings(
    image: &[u8],
    frames: [u64; TABLE_FRAMES],
    pages: &[UserPage],
) -> Result<StaticLaunchLayout, TwoPtElfError> {
    let layout = plan_two_pt_image(image).map_err(TwoPtElfError::Image)?;
    if pages.len() != layout.len {
        return Err(TwoPtElfError::MissingOrExtraPage);
    }
    for leaf in layout.leaves[..layout.len].iter().flatten() {
        let Some(page) = pages.iter().find(|page|
            page.virtual_address == leaf.virtual_address)
        else { return Err(TwoPtElfError::MissingOrExtraPage) };
        if page.writable != leaf.writable || page.executable != leaf.executable {
            return Err(TwoPtElfError::PermissionMismatch);
        }
    }
    validate(frames, pages).map_err(TwoPtElfError::Mapping)?;
    Ok(layout)
}

/// A bounded static ELF whose low virtual addresses have been placed
/// inside one explicitly selected, previously unused user PML4 slot.
/// `source` retains original ELF-relative load VAs for byte materialization;
/// `entry` and `stack_page` are addresses to use for a future Ring3 handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelocatedLaunchLayout {
    pub source: StaticLaunchLayout,
    pub user_pml4_slot: usize,
    pub base: u64,
    pub entry: u64,
    pub stack_page: u64,
}

/// Derive a relocated two-PT mapping from immutable ELF bytes, NEVER from
/// caller-provided target page metadata. Slots 0 and 256..511 are forbidden:
/// runtime selects an UNUSED slot in 1..255 from its still-active PML4.
/// The original image must fit wholly within low PML4 slot zero before shift,
/// so adding the base cannot silently relocate one leaf into another slot.
pub fn validate_relocated_elf_bindings(
    image: &[u8],
    user_pml4_slot: usize,
    frames: [u64; TABLE_FRAMES],
    pages: &[UserPage],
) -> Result<RelocatedLaunchLayout, TwoPtElfError> {
    if !(1..256).contains(&user_pml4_slot) {
        return Err(TwoPtElfError::InvalidUserSlot);
    }
    let source = plan_two_pt_image(image).map_err(TwoPtElfError::Image)?;
    const SLOT_SIZE: u64 = 1 << 39;
    let stack_top = source.stack_page.checked_add(PAGE_BYTES)
        .ok_or(TwoPtElfError::AddressOverflow)?;
    if stack_top > SLOT_SIZE || source.image.entry >= SLOT_SIZE {
        return Err(TwoPtElfError::AddressOverflow);
    }
    let base = (user_pml4_slot as u64) << 39;
    let entry = base.checked_add(source.image.entry)
        .ok_or(TwoPtElfError::AddressOverflow)?;
    let stack_page = base.checked_add(source.stack_page)
        .ok_or(TwoPtElfError::AddressOverflow)?;
    if pages.len() != source.len {
        return Err(TwoPtElfError::MissingOrExtraPage);
    }
    for leaf in source.leaves[..source.len].iter().flatten() {
        let va = base.checked_add(leaf.virtual_address)
            .ok_or(TwoPtElfError::AddressOverflow)?;
        let Some(page) = pages.iter().find(|p| p.virtual_address == va)
        else { return Err(TwoPtElfError::MissingOrExtraPage) };
        if page.writable != leaf.writable || page.executable != leaf.executable {
            return Err(TwoPtElfError::PermissionMismatch);
        }
    }
    validate(frames, pages).map_err(TwoPtElfError::Mapping)?;
    Ok(RelocatedLaunchLayout {
        source, user_pml4_slot, base, entry, stack_page,
    })
}

/// Immutable, fixed-capacity translation of one ELF layout into a concrete
/// PMM-backed relocated page set. Only `pages()` is a valid mapping slice;
/// unused array slots are intentionally inaccessible to PTE consumers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelocatedElfPages {
    pub layout: RelocatedLaunchLayout,
    pages: [UserPage; MAX_LEAVES],
    len: usize,
}

impl RelocatedElfPages {
    pub fn pages(&self) -> &[UserPage] { &self.pages[..self.len] }
    pub fn load_pages(&self) -> usize { self.len - 1 }
}

/// Turn genuine ELF PT_LOAD page boundaries and the fresh RW+NX stack into
/// exact user mappings, using *caller-owned* physical frames in ELF leaf order.
/// Caller never chooses VAs or permissions: only supplies the 5 distinct table
/// frames and exactly one separately owned data frame for each derived leaf.
/// Full prevalidation and alias checking occur before any page-table writes.
pub fn derive_relocated_elf_pages(
    image: &[u8],
    user_pml4_slot: usize,
    tables: [u64; TABLE_FRAMES],
    data_frames: &[u64],
) -> Result<RelocatedElfPages, TwoPtElfError> {
    if !(1..256).contains(&user_pml4_slot) {
        return Err(TwoPtElfError::InvalidUserSlot);
    }
    let source = plan_two_pt_image(image).map_err(TwoPtElfError::Image)?;
    if data_frames.len() != source.len {
        return Err(TwoPtElfError::MissingOrExtraPage);
    }
    let base = (user_pml4_slot as u64) << 39;
    let mut pages = [UserPage {
        virtual_address: 0, physical_frame: 0,
        writable: false, executable: false,
    }; MAX_LEAVES];
    for (i, leaf) in source.leaves[..source.len].iter().enumerate() {
        let leaf = leaf.ok_or(TwoPtElfError::MissingOrExtraPage)?;
        pages[i] = UserPage {
            virtual_address: base.checked_add(leaf.virtual_address)
                .ok_or(TwoPtElfError::AddressOverflow)?,
            physical_frame: data_frames[i],
            writable: leaf.writable,
            executable: leaf.executable,
        };
    }
    let layout = validate_relocated_elf_bindings(
        image, user_pml4_slot, tables, &pages[..source.len],
    )?;
    Ok(RelocatedElfPages { layout, pages, len: source.len })
}

/// Same exact 2,560-entry audit as the raw-VA path, after byte-derived,
/// slot-aware address relocation. Kernel high-half must still be empty;
/// a separate supervisor graft may follow after this full admission.
pub fn audit_relocated_elf_bindings(
    image: &[u8],
    user_pml4_slot: usize,
    pml4: &[u64; ENTRY_COUNT],
    pdpt: &[u64; ENTRY_COUNT],
    pd: &[u64; ENTRY_COUNT],
    pt0: &[u64; ENTRY_COUNT],
    pt1: &[u64; ENTRY_COUNT],
    frames: [u64; TABLE_FRAMES],
    pages: &[UserPage],
) -> Result<RelocatedLaunchLayout, TwoPtElfError> {
    let layout = validate_relocated_elf_bindings(
        image, user_pml4_slot, frames, pages,
    )?;
    audit(pml4, pdpt, pd, pt0, pt1, frames, pages)
        .map_err(TwoPtElfError::Mapping)?;
    Ok(layout)
}

/// Require both the byte-derived ELF contract and ALL real shadow PTEs.
/// Caller retains full exclusive PMM frame ownership and must independently
/// check HHDM pointer provenance, exact staged byte contents and stack zero.
pub fn audit_elf_bindings(
    image: &[u8],
    pml4: &[u64; ENTRY_COUNT],
    pdpt: &[u64; ENTRY_COUNT],
    pd: &[u64; ENTRY_COUNT],
    pt0: &[u64; ENTRY_COUNT],
    pt1: &[u64; ENTRY_COUNT],
    frames: [u64; TABLE_FRAMES],
    pages: &[UserPage],
) -> Result<StaticLaunchLayout, TwoPtElfError> {
    let layout = validate_elf_bindings(image, frames, pages)?;
    audit(pml4, pdpt, pd, pt0, pt1, frames, pages)
        .map_err(TwoPtElfError::Mapping)?;
    Ok(layout)
}
