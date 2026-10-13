//! WolfOS P1 bootstrap physical frame allocator.
//! Only MEMMAP_USABLE RAM. No physical memory dereference or disk access.
//! This is a single-core bootstrap allocator; do not invoke from interrupts.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use limine::memmap::{Entry, MEMMAP_USABLE};

const PAGE_SIZE: u64 = 4096;
const MAX_REGIONS: usize = 128;
const BITMAP_BYTES: usize = 2 * 1024 * 1024; // capacity: 64 GiB usable RAM
const MAX_FRAMES: usize = BITMAP_BYTES * 8;

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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreeError {
    NotInitialized,
    NotAligned,
    NotManaged,
    DoubleFree,
}

#[derive(Clone, Copy)]
pub struct Statistics {
    pub usable_regions: usize,
    pub total_frames: usize,
    pub allocated_frames: usize,
}

impl Statistics {
    pub fn free_frames(self) -> usize {
        self.total_frames - self.allocated_frames
    }
}

struct FrameState {
    regions: [Region; MAX_REGIONS],
    count: usize,
    total: usize,
    used: usize,
    next: usize,
    allocated: [u8; BITMAP_BYTES],
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
            allocated: [0; BITMAP_BYTES],
            initialized: false,
        }
    }

    fn stats(&self) -> Statistics {
        Statistics {
            usable_regions: self.count,
            total_frames: self.total,
            allocated_frames: self.used,
        }
    }

    fn is_used(&self, index: usize) -> bool {
        (self.allocated[index / 8] & (1 << (index % 8))) != 0
    }

    fn mark(&mut self, index: usize, used: bool) {
        let byte = &mut self.allocated[index / 8];
        let mask = 1_u8 << (index % 8);
        if used { *byte |= mask; } else { *byte &= !mask; }
    }

    fn physical_address(&self, index: usize) -> Option<u64> {
        for r in self.regions[..self.count].iter() {
            if index >= r.first_bit && index - r.first_bit < r.pages {
                return Some(r.start + ((index - r.first_bit) as u64) * PAGE_SIZE);
            }
        }
        None
    }

    fn allocate(&mut self) -> Option<u64> {
        if !self.initialized || self.used == self.total { return None; }
        let pivot = self.next;
        for (begin, end) in [(pivot, self.total), (0, pivot)] {
            for index in begin..end {
                if !self.is_used(index) {
                    let addr = self.physical_address(index)?;
                    self.mark(index, true);
                    self.used += 1;
                    self.next = (index + 1) % self.total;
                    return Some(addr);
                }
            }
        }
        None
    }

    fn free(&mut self, addr: u64) -> Result<(), FreeError> {
        if !self.initialized { return Err(FreeError::NotInitialized); }
        if addr % PAGE_SIZE != 0 { return Err(FreeError::NotAligned); }
        for r in self.regions[..self.count].iter() {
            let offset = addr.wrapping_sub(r.start);
            if addr >= r.start && offset / PAGE_SIZE < r.pages as u64 {
                let index = r.first_bit + (offset / PAGE_SIZE) as usize;
                if !self.is_used(index) { return Err(FreeError::DoubleFree); }
                self.mark(index, false);
                self.used -= 1;
                self.next = self.next.min(index);
                return Ok(());
            }
        }
        Err(FreeError::NotManaged)
    }
}

/// Lock serializes callers. IRQ re-entrancy is NOT yet supported.
struct LockedState {
    held: AtomicBool,
    inner: UnsafeCell<FrameState>,
}

// SAFETY: exclusive access is provided by the atomic lock. Until the
// IRQ-safe allocator milestone, callers must never enter from interrupts.
unsafe impl Sync for LockedState {}

impl LockedState {
    const fn new() -> Self {
        Self { held: AtomicBool::new(false), inner: UnsafeCell::new(FrameState::empty()) }
    }

    fn with<R>(&self, operation: impl FnOnce(&mut FrameState) -> R) -> R {
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
        // SAFETY: the exclusive lock is held for the mutable borrow.
        operation(unsafe { &mut *self.inner.get() })
    }
}

static FRAMES: LockedState = LockedState::new();

/// Initialize once from the bootloader memory map. Reject invalid ranges.
pub fn initialize(entries: &[&Entry]) -> Result<Statistics, InitError> {
    FRAMES.with(|state| {
        if state.initialized { return Err(InitError::AlreadyInitialized); }
        let mut total = 0_usize;
        for entry in entries.iter().copied().filter(|e| e.type_ == MEMMAP_USABLE) {
            let end = entry.base.checked_add(entry.length).ok_or(InitError::InvalidMemoryMap)?;
            let start = entry.base.checked_add(PAGE_SIZE - 1)
                .ok_or(InitError::InvalidMemoryMap)? & !(PAGE_SIZE - 1);
            let end_aligned = end & !(PAGE_SIZE - 1);
            if end_aligned <= start { continue; }

            if state.count >= MAX_REGIONS { return Err(InitError::TooManyRegions); }
            let pages_u64 = (end_aligned - start) / PAGE_SIZE;
            let pages = usize::try_from(pages_u64).map_err(|_| InitError::CapacityExceeded)?;
            let new_total = total.checked_add(pages).ok_or(InitError::CapacityExceeded)?;
            if new_total > MAX_FRAMES { return Err(InitError::CapacityExceeded); }

            for existing in state.regions[..state.count].iter() {
                let existing_end = existing.start + (existing.pages as u64) * PAGE_SIZE;
                if start < existing_end && existing.start < end_aligned {
                    return Err(InitError::OverlappingRegions);
                }
            }

            state.regions[state.count] = Region { start, pages, first_bit: total };
            state.count += 1;
            total = new_total;
        }
        if total == 0 { return Err(InitError::NoUsableMemory); }
        state.total = total;
        state.initialized = true;
        Ok(state.stats())
    })
}

/// Returns a physical page base, not a mapped virtual pointer.
pub fn allocate_frame() -> Option<u64> {
    FRAMES.with(FrameState::allocate)
}

pub fn free_frame(addr: u64) -> Result<(), FreeError> {
    FRAMES.with(|state| state.free(addr))
}

pub fn statistics() -> Statistics {
    FRAMES.with(|state| state.stats())
}

/// QEMU acceptance test: unique frames, free checks and 10,000 cycles.
pub fn self_test() -> bool {
    let before = statistics();
    if before.free_frames() < 128 { return false; }

    let mut frames = [0_u64; 128];
    for i in 0..frames.len() {
        let Some(frame) = allocate_frame() else { return false; };
        if frame % PAGE_SIZE != 0 || frames[..i].contains(&frame) { return false; }
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
}
