//! Byte-derived, bounded one/two-PT mapping recipe shared by Ring3 launches.
//!
//! A recipe borrows no hardware or memory, owns no frames and cannot free
//! them. The caller authenticates PMM ownership, destination HHDM pointers,
//! payload bytes and kernel grafts separately before publishing a CR3.

use crate::{
    elf64_page_image::{materialize_bounded, MaterializeError, PageBacking, PageContents, PAGE_SIZE},
    elf64_preflight::{LoadSegment, PAGE_BYTES, USER_END},
    user_elf_launch_layout::{
        BudgetedLaunch, LaunchError, MAX_LEAVES, MAX_LOAD_PAGES, TWO_PT_TABLE_FRAMES, plan_bounded_with_budget,
    },
};

pub const ENTRIES: usize = 512;
const MAX_FRAMES: usize = TWO_PT_TABLE_FRAMES + MAX_LEAVES;
const P: u64 = 1;
const W: u64 = 2;
const U: u64 = 4;
const NX: u64 = 1 << 63;
const SLOT_SIZE: u64 = 1 << 39;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingError {
    Image(LaunchError),
    InvalidUserSlot,
    AddressRange,
    FrameCount,
    InvalidFrame,
    AliasedFrame,
    TableCount,
    DirtyTable,
    MismatchedTable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StageError {
    Image(LaunchError),
    ChangedImageLayout,
    BackingCount,
    BackingFrameMismatch { index: usize },
    DirtyOwnedPage { index: usize },
    MissingSource,
    Materialize(MaterializeError),
}

/// A caller-owned HHDM page accompanied by its claimed PMM frame number.
/// The caller must separately authenticate pointer-to-physical provenance.
pub struct OwnedLeafPage<'a> {
    pub physical_frame: u64,
    pub bytes: &'a mut [u8; PAGE_SIZE],
}

impl PageBacking for OwnedLeafPage<'_> {
    fn page_bytes_mut(&mut self) -> &mut [u8; PAGE_SIZE] { &mut *self.bytes }
}


/// Actual distinct caller-owned table buffers, rather than a fictitious
/// fifth table borrowed from a data page in a six/seven-frame launch.
pub struct TableBuffers<'a> {
    pub pml4: &'a mut [u64; ENTRIES],
    pub pdpt: &'a mut [u64; ENTRIES],
    pub pd: &'a mut [u64; ENTRIES],
    pub pt0: &'a mut [u64; ENTRIES],
    pub pt1: Option<&'a mut [u64; ENTRIES]>,
}

/// Immutable metadata, not an address-space owner or execution authorization.
/// Private fields prevent callers from changing the ELF-derived leaf recipe.
pub struct ElfPageTables {
    launch: BudgetedLaunch,
    slot: usize,
    base: u64,
    regions: [u64; 2],
    region_count: usize,
    frames: [u64; MAX_FRAMES],
}

impl ElfPageTables {
    /// Reparse the immutable ELF and bind its ordered leaves to an exact
    /// physical lease. No caller-chosen VA, flags, table count or padding is
    /// trusted. All unsupported input is rejected before table access.
    pub fn bind(image: &[u8], slot: usize, frames: &[u64]) -> Result<Self, MappingError> {
        if !(1..256).contains(&slot) {
            return Err(MappingError::InvalidUserSlot);
        }
        let launch = plan_bounded_with_budget(image).map_err(MappingError::Image)?;
        let stack_end = launch
            .layout
            .stack_page
            .checked_add(PAGE_BYTES)
            .ok_or(MappingError::AddressRange)?;
        let base = (slot as u64) << 39;
        // This bounded placement contract supports source slot zero only.
        // The eventual user RSP must also be canonical, not USER_END itself.
        if stack_end > SLOT_SIZE
            || launch.layout.image.entry >= SLOT_SIZE
            || base
                .checked_add(stack_end)
                .is_none_or(|top| top >= USER_END)
        {
            return Err(MappingError::AddressRange);
        }
        if frames.len() != launch.frames.total_frames || frames.len() > MAX_FRAMES {
            return Err(MappingError::FrameCount);
        }
        for (i, frame) in frames.iter().copied().enumerate() {
            if frame == 0 || frame >= 1 << 52 || frame & (PAGE_BYTES - 1) != 0 {
                return Err(MappingError::InvalidFrame);
            }
            if frames[..i].contains(&frame) {
                return Err(MappingError::AliasedFrame);
            }
        }
        let mut regions = [0; 2];
        let mut region_count = 0;
        for leaf in launch.layout.leaves[..launch.layout.len].iter().flatten() {
            let region = leaf.virtual_address >> 21;
            if !regions[..region_count].contains(&region) {
                regions[region_count] = region;
                region_count += 1;
            }
        }
        let mut owned = [0; MAX_FRAMES];
        owned[..frames.len()].copy_from_slice(frames);
        Ok(Self {
            launch,
            slot,
            base,
            regions,
            region_count,
            frames: owned,
        })
    }

    pub fn launch(&self) -> &BudgetedLaunch {
        &self.launch
    }
    pub fn entry(&self) -> u64 {
        self.base + self.launch.layout.image.entry
    }
    pub fn stack_page(&self) -> u64 {
        self.base + self.launch.layout.stack_page
    }

    /// Stage only validated PT_LOAD leaves into already-owned, zeroed PMM
    /// buffers from this exact page-table recipe. The stack is an independent
    /// zero-filled leaf, never taken from the ELF. All frame identities,
    /// destination cleanliness and source ranges are checked before any
    /// backing byte changes. No table entry, ownership or CR3 is mutated.
    ///
    /// The trusted caller must keep the ELF bytes stable from bind through
    /// staging and perform final HHDM, page-byte and table admission audits.
    pub fn stage_load_and_stack(
        &self,
        image: &[u8],
        loads: &mut [OwnedLeafPage<'_>],
        stack: &mut OwnedLeafPage<'_>,
    ) -> Result<[Option<PageContents>; MAX_LOAD_PAGES], StageError> {
        let again = plan_bounded_with_budget(image).map_err(StageError::Image)?;
        if again != self.launch {
            return Err(StageError::ChangedImageLayout);
        }
        let count = self.launch.layout.load_pages();
        if count == 0 || count > MAX_LOAD_PAGES || loads.len() != count {
            return Err(StageError::BackingCount);
        }
        let tables = self.launch.frames.table_frames;
        for (i, page) in loads.iter().enumerate() {
            if page.physical_frame != self.frames[tables + i] {
                return Err(StageError::BackingFrameMismatch { index: i });
            }
        }
        if stack.physical_frame != self.frames[tables + count] {
            return Err(StageError::BackingFrameMismatch { index: count });
        }
        for (i, page) in loads.iter().enumerate() {
            if page.bytes.iter().any(|byte| *byte != 0) {
                return Err(StageError::DirtyOwnedPage { index: i });
            }
        }
        if stack.bytes.iter().any(|byte| *byte != 0) {
            return Err(StageError::DirtyOwnedPage { index: count });
        }
        let first = self.launch.layout.image.segments[0]
            .as_ref().ok_or(StageError::MissingSource)?;
        let mut requests: [(&LoadSegment, u64); MAX_LOAD_PAGES] =
            [(first, 0); MAX_LOAD_PAGES];
        for (i, request) in requests[..count].iter_mut().enumerate() {
            let leaf = self.launch.layout.leaves[i].ok_or(StageError::MissingSource)?;
            let source = leaf.source_segment.ok_or(StageError::MissingSource)?;
            let segment = self.launch.layout.image.segments[source]
                .as_ref().ok_or(StageError::MissingSource)?;
            *request = (segment, leaf.virtual_address);
        }
        materialize_bounded::<MAX_LOAD_PAGES>(image, &requests[..count], loads)
            .map_err(StageError::Materialize)
    }

    fn check_buffers(&self, tables: &TableBuffers<'_>) -> Result<(), MappingError> {
        if tables.pt1.is_some() != (self.region_count == 2) {
            return Err(MappingError::TableCount);
        }
        Ok(())
    }

    /// Compute every expected entry independently of the destination tables.
    /// Parent NX stays clear for RX leaves; W is allowed at ancestors because
    /// the independently mapped RW/NX stack always requires it.
    fn expected(&self, level: usize, index: usize) -> u64 {
        let parent = P | W | U;
        match level {
            0 => {
                if index == self.slot {
                    self.frames[1] | parent
                } else {
                    0
                }
            }
            1 => {
                let first = self.launch.layout.leaves[0].expect("validated nonempty layout");
                if index == ((first.virtual_address >> 30) & 511) as usize {
                    self.frames[2] | parent
                } else {
                    0
                }
            }
            2 => self.regions[..self.region_count]
                .iter()
                .position(|region| (region & 511) as usize == index)
                .map_or(0, |pt| self.frames[3 + pt] | parent),
            _ => {
                let pt = level - 3;
                self.launch.layout.leaves[..self.launch.layout.len]
                    .iter()
                    .flatten()
                    .enumerate()
                    .find(|(_, leaf)| {
                        leaf.virtual_address >> 21 == self.regions[pt]
                            && ((leaf.virtual_address >> 12) & 511) as usize == index
                    })
                    .map_or(0, |(i, leaf)| {
                        self.frames[self.launch.frames.table_frames + i]
                            | P
                            | U
                            | if leaf.writable { W } else { 0 }
                            | if leaf.executable { 0 } else { NX }
                    })
            }
        }
    }

    /// Fill disconnected tables only after checking the entire destination
    /// bank. A missing, extra or dirty table leaves every byte unchanged.
    pub fn populate(&self, tables: &mut TableBuffers<'_>) -> Result<(), MappingError> {
        self.check_buffers(tables)?;
        if tables
            .pml4
            .iter()
            .chain(tables.pdpt.iter())
            .chain(tables.pd.iter())
            .chain(tables.pt0.iter())
            .any(|entry| *entry != 0)
            || tables
                .pt1
                .as_ref()
                .is_some_and(|pt| pt.iter().any(|entry| *entry != 0))
        {
            return Err(MappingError::DirtyTable);
        }
        for i in 0..ENTRIES {
            tables.pml4[i] = self.expected(0, i);
            tables.pdpt[i] = self.expected(1, i);
            tables.pd[i] = self.expected(2, i);
            tables.pt0[i] = self.expected(3, i);
            if let Some(pt) = tables.pt1.as_deref_mut() {
                pt[i] = self.expected(4, i);
            }
        }
        Ok(())
    }

    /// Inspect every entry, including all unmapped gaps and supervisor slots,
    /// BEFORE a separate trusted high-half graft or hardware CR3 activation.
    pub fn audit(&self, tables: &TableBuffers<'_>) -> Result<(), MappingError> {
        self.check_buffers(tables)?;
        for i in 0..ENTRIES {
            if tables.pml4[i] != self.expected(0, i)
                || tables.pdpt[i] != self.expected(1, i)
                || tables.pd[i] != self.expected(2, i)
                || tables.pt0[i] != self.expected(3, i)
                || tables
                    .pt1
                    .as_ref()
                    .is_some_and(|pt| pt[i] != self.expected(4, i))
            {
                return Err(MappingError::MismatchedTable);
            }
        }
        Ok(())
    }
}
