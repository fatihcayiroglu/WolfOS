//! WolfOS P1 scalable bootstrap frame allocator.
//! Bitmap memory is reserved from Limine MEMMAP_USABLE RAM, accessed via HHDM.
//! There is no fixed 64-GiB RAM cap or 2-MiB static bitmap.
//! Metadata is backed by usable RAM, NOT by unbounded kernel BSS.
//!
//! IMPORTANT LIMITS: up to 256 usable regions in the bootstrap directory,
//! no memory hot-plug or NUMA awareness yet. Maskable same-CPU IRQ
//! reentry is excluded while locked, but NMI and synchronous recursive
//! allocator calls remain unsupported.
//! Pointers require Limine's HHDM mapping to remain installed.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use limine::memmap::{Entry, MEMMAP_USABLE};

use crate::pmm_bitmap_scan::first_clear_bit;
use crate::pmm_layout::{bitmap_bytes_for_frames, metadata_pages_for_frames, PAGE_SIZE};

const MAX_REGIONS: usize = 256;

#[derive(Clone, Copy)]
struct Region {
    start: u64,
    pages: usize,
    first_bit: usize,
}

impl Region {
    const EMPTY: Self = Self { start: 0, pages: 0, first_bit: 0 };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitError {
    AlreadyInitialized,
    TooManyRegions,
    CapacityExceeded,
    InvalidMemoryMap,
    OverlappingRegions,
    NoUsableMemory,
    NoContiguousMetadataRegion,
    InvalidHhdm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreeError {
    NotInitialized,
    NotAligned,
    NotManaged,
    DoubleFree,
    MetadataReserved,
}

#[derive(Clone, Copy)]
pub struct Statistics {
    pub usable_regions: usize,
    pub total_frames: usize,
    pub metadata_frames: usize,
    pub allocated_frames: usize,
    pub bitmap_bytes: usize,
}

impl Statistics {
    pub fn free_frames(self) -> usize {
        self.total_frames - self.metadata_frames - self.allocated_frames
    }
}

struct FrameState {
    regions: [Region; MAX_REGIONS],
    count: usize,
    total: usize,
    used: usize,
    next: usize,
    bitmap_addr: usize,
    bitmap_bytes: usize,
    metadata_phys: u64,
    metadata_frames: usize,
    metadata_first_bit: usize,
    initialized: bool,
}

impl FrameState {
    const fn empty() -> Self {
        Self {
            regions: [Region::EMPTY; MAX_REGIONS],
            count: 0,
            total: 0,
            used: 0,
            next: 0,
            bitmap_addr: 0,
            bitmap_bytes: 0,
            metadata_phys: 0,
            metadata_frames: 0,
            metadata_first_bit: 0,
            initialized: false,
        }
    }

    fn stats(&self) -> Statistics {
        Statistics {
            usable_regions: self.count,
            total_frames: self.total,
            metadata_frames: self.metadata_frames,
            allocated_frames: self.used,
            bitmap_bytes: self.bitmap_bytes,
        }
    }

    fn is_metadata_bit(&self, index: usize) -> bool {
        index >= self.metadata_first_bit
            && index - self.metadata_first_bit < self.metadata_frames
    }

    fn is_used(&self, index: usize) -> bool {
        debug_assert!(self.initialized && index < self.total);
        let index_byte = index / 8;
        debug_assert!(index_byte < self.bitmap_bytes);
        // SAFETY: bitmap_addr points to reserved HHDM-mapped usable RAM,
        // its size covers every frame bit, and the allocator lock is held.
        let value = unsafe { (self.bitmap_addr as *const u8).add(index_byte).read() };
        (value & (1 << (index % 8))) != 0
    }

    fn mark(&mut self, index: usize, used: bool) {
        debug_assert!(self.initialized && index < self.total);
        let index_byte = index / 8;
        debug_assert!(index_byte < self.bitmap_bytes);
        // SAFETY: validated, exclusive, HHDM-mapped metadata allocation.
        unsafe {
            let ptr = (self.bitmap_addr as *mut u8).add(index_byte);
            let mut value = ptr.read();
            let mask = 1_u8 << (index % 8);
            if used { value |= mask; } else { value &= !mask; }
            ptr.write(value);
        }
    }

    fn physical_address(&self, index: usize) -> Option<u64> {
        for r in self.regions[..self.count].iter() {
            if index >= r.first_bit && index - r.first_bit < r.pages {
                return Some(r.start + ((index - r.first_bit) as u64) * PAGE_SIZE as u64);
            }
        }
        None
    }

    fn allocate(&mut self) -> Option<u64> {
        if !self.initialized || self.used + self.metadata_frames == self.total {
            return None;
        }
        let pivot = self.next;
        for (begin, end) in [(pivot, self.total), (0, pivot)] {
            // SAFETY: init reserved an HHDM-backed bitmap of exactly this
            // length. The allocator lock excludes all other PMM mutations.
            // This temporary shared slice ends before mark() writes the bit.
            let free = {
                let bitmap = unsafe {
                    core::slice::from_raw_parts(
                        self.bitmap_addr as *const u8, self.bitmap_bytes,
                    )
                };
                first_clear_bit(bitmap, begin, end)
            };
            if let Some(index) = free {
                let addr = self.physical_address(index)?;
                self.mark(index, true);
                self.used += 1;
                self.next = (index + 1) % self.total;
                return Some(addr);
            }
        }
        None
    }

    fn free(&mut self, addr: u64) -> Result<(), FreeError> {
        if !self.initialized { return Err(FreeError::NotInitialized); }
        if addr % PAGE_SIZE as u64 != 0 { return Err(FreeError::NotAligned); }
        for r in self.regions[..self.count].iter() {
            if addr < r.start { continue; }
            let offset = addr - r.start;
            if offset / PAGE_SIZE as u64 >= r.pages as u64 { continue; }
            let index = r.first_bit + (offset / PAGE_SIZE as u64) as usize;
            if self.is_metadata_bit(index) { return Err(FreeError::MetadataReserved); }
            if !self.is_used(index) { return Err(FreeError::DoubleFree); }
            self.mark(index, false);
            self.used -= 1;
            self.next = self.next.min(index);
            return Ok(());
        }
        Err(FreeError::NotManaged)
    }
}

/// Bootstrap exclusive lock. Local maskable IRQs must be disabled before
/// acquisition, otherwise an interrupt on the holder CPU can deadlock while
/// spinning for the same lock. NMI and synchronous recursion are unsupported.
struct LockedState {
    held: AtomicBool,
    inner: UnsafeCell<FrameState>,
}

// SAFETY: all access uses the exclusive lock. IRQ reentry is prohibited.
unsafe impl Sync for LockedState {}

impl LockedState {
    const fn new() -> Self {
        Self { held: AtomicBool::new(false), inner: UnsafeCell::new(FrameState::empty()) }
    }

    fn with<R>(&self, operation: impl FnOnce(&mut FrameState) -> R) -> R {
        // Save IF and mask local interrupts *before* taking the lock. The
        // release guard drops before without_interrupts restores the caller's
        // original IF state. Another CPU may still contend normally.
        x86_64::instructions::interrupts::without_interrupts(|| {
            while self.held.compare_exchange_weak(
                false, true, Ordering::Acquire, Ordering::Relaxed
            ).is_err() {
                core::hint::spin_loop();
            }
            struct Release<'a>(&'a AtomicBool);
            impl Drop for Release<'_> {
                fn drop(&mut self) { self.0.store(false, Ordering::Release); }
            }
            let _release = Release(&self.held);
            // SAFETY: the lock excludes all other mutable accesses to FrameState.
            operation(unsafe { &mut *self.inner.get() })
        })
    }
}

static FRAMES: LockedState = LockedState::new();

/// Initialize from Limine's usable RAM ranges and its higher-half direct map.
/// Bitmap backing pages are taken from a single usable region and reserved.
/// The initial memory map must not overlap the kernel, bootloader or modules.
pub fn initialize(entries: &[&Entry], hhdm_offset: u64) -> Result<Statistics, InitError> {
    FRAMES.with(|state| {
        if state.initialized { return Err(InitError::AlreadyInitialized); }
        if hhdm_offset % PAGE_SIZE as u64 != 0 { return Err(InitError::InvalidHhdm); }
        state.count = 0;
        let mut total = 0usize;
        for entry in entries.iter().copied().filter(|e| e.type_ == MEMMAP_USABLE) {
            let end = entry.base.checked_add(entry.length).ok_or(InitError::InvalidMemoryMap)?;
            let start = entry.base.checked_add(PAGE_SIZE as u64 - 1)
                .ok_or(InitError::InvalidMemoryMap)? & !(PAGE_SIZE as u64 - 1);
            let end_aligned = end & !(PAGE_SIZE as u64 - 1);
            if end_aligned <= start { continue; }

            if state.count >= MAX_REGIONS { return Err(InitError::TooManyRegions); }
            let pages_u64 = (end_aligned - start) / PAGE_SIZE as u64;
            let pages = usize::try_from(pages_u64).map_err(|_| InitError::CapacityExceeded)?;
            let new_total = total.checked_add(pages).ok_or(InitError::CapacityExceeded)?;

            for existing in state.regions[..state.count].iter() {
                let old_end = existing.start
                    .checked_add((existing.pages as u64) * PAGE_SIZE as u64)
                    .ok_or(InitError::InvalidMemoryMap)?;
                if start < old_end && existing.start < end_aligned {
                    return Err(InitError::OverlappingRegions);
                }
            }
            state.regions[state.count] = Region { start, pages, first_bit: total };
            state.count += 1;
            total = new_total;
        }
        if total == 0 { return Err(InitError::NoUsableMemory); }

        let bitmap_bytes = bitmap_bytes_for_frames(total).ok_or(InitError::CapacityExceeded)?;
        let metadata_frames = metadata_pages_for_frames(total).ok_or(InitError::CapacityExceeded)?;
        let Some(metadata_region) = state.regions[..state.count].iter()
            .copied().find(|region| region.pages >= metadata_frames)
        else { return Err(InitError::NoContiguousMetadataRegion); };

        let metadata_end = metadata_region.start
            .checked_add((metadata_frames as u64) * PAGE_SIZE as u64)
            .ok_or(InitError::InvalidMemoryMap)?;
        let _ = metadata_end; // the region-size check already bounds the placement.
        let virtual_address = hhdm_offset
            .checked_add(metadata_region.start)
            .ok_or(InitError::InvalidHhdm)?;
        let bitmap_addr = usize::try_from(virtual_address)
            .map_err(|_| InitError::InvalidHhdm)?;
        if bitmap_addr == 0 { return Err(InitError::InvalidHhdm); }

        // SAFETY: Limine maps MEMMAP_USABLE physical pages in its HHDM.
        // This is done only after full map validation; metadata resides
        // wholly inside one usable region and stays reserved permanently.
        unsafe {
            core::ptr::write_bytes(bitmap_addr as *mut u8, 0, bitmap_bytes);
        }
        state.total = total;
        state.bitmap_addr = bitmap_addr;
        state.bitmap_bytes = bitmap_bytes;
        state.metadata_phys = metadata_region.start;
        state.metadata_frames = metadata_frames;
        state.metadata_first_bit = metadata_region.first_bit;
        state.used = 0;
        state.next = 0;
        state.initialized = true;

        for i in metadata_region.first_bit..(metadata_region.first_bit + metadata_frames) {
            state.mark(i, true);
        }
        Ok(state.stats())
    })
}

pub fn allocate_frame() -> Option<u64> {
    FRAMES.with(FrameState::allocate)
}

pub fn free_frame(addr: u64) -> Result<(), FreeError> {
    FRAMES.with(|state| state.free(addr))
}

pub fn statistics() -> Statistics {
    FRAMES.with(|state| state.stats())
}

/// Verify bitmap address reservation, unique pages, double-free guards and
/// 10,000 allocation/free cycles inside real QEMU boot.
pub fn self_test() -> bool {
    let interrupt_state_before = x86_64::instructions::interrupts::are_enabled();
    let before = statistics();
    if before.free_frames() < 128 { return false; }

    let mut frames = [0_u64; 128];
    for i in 0..frames.len() {
        let Some(frame) = allocate_frame() else { return false; };
        if frame % PAGE_SIZE as u64 != 0 || frames[..i].contains(&frame) {
            return false;
        }
        frames[i] = frame;
    }
    if statistics().allocated_frames != before.allocated_frames + 128 { return false; }

    for frame in frames.iter().rev().copied() {
        if free_frame(frame).is_err() { return false; }
    }
    if free_frame(frames[0]) != Err(FreeError::DoubleFree) { return false; }
    if free_frame(frames[0] + 1) != Err(FreeError::NotAligned) { return false; }

    for _ in 0..10_000 {
        let Some(frame) = allocate_frame() else { return false; };
        if free_frame(frame).is_err() { return false; }
    }
    let after = statistics();
    after.allocated_frames == before.allocated_frames
        && after.free_frames() == before.free_frames()
        && x86_64::instructions::interrupts::are_enabled() == interrupt_state_before
}