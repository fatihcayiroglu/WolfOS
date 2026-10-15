//! P2 validated ELF64 PT_LOAD -> single 4096-byte page materialization.
//! This only initializes an already-owned kernel buffer/frame; it does NOT
//! map pages, grant Ring 3 access, change CR3 or execute image contents.
//!
//! Every byte not backed by PT_LOAD p_filesz is ZERO, including first-page
//! padding, BSS, last-page tail and fully zero-only pages.
//! On any error destination is UNMODIFIED (caller must not map it).

use crate::elf64_preflight::{LoadSegment, PAGE_BYTES, USER_END, USER_MIN};

pub const PAGE_SIZE: usize = PAGE_BYTES as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterializeError {
    InvalidPage, InvalidSegment, InvalidFile, InvalidPermissions,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageContents {
    pub copied: usize,
    pub zeroed: usize,
    pub writable: bool,
    pub executable: bool,
}

/// Require a segment from a trusted preflight ImagePlan. Revalidate the
/// critical fields independently so a forged descriptor is never blindly
/// copied into a page. In particular, W^X cannot be bypassed via this API.
pub fn materialize(
    input: &[u8],
    segment: &LoadSegment,
    page_virtual: u64,
    target: &mut [u8; PAGE_SIZE],
) -> Result<PageContents, MaterializeError> {
    if segment.executable && segment.writable {
        return Err(MaterializeError::InvalidPermissions);
    }
    if segment.file_size > segment.memory_size || segment.memory_size == 0 {
        return Err(MaterializeError::InvalidSegment);
    }
    let memory_end = segment.virtual_address.checked_add(segment.memory_size)
        .ok_or(MaterializeError::InvalidSegment)?;
    let file_va_end = segment.virtual_address.checked_add(segment.file_size)
        .ok_or(MaterializeError::InvalidSegment)?;
    let file_end = segment.file_offset.checked_add(segment.file_size)
        .ok_or(MaterializeError::InvalidFile)?;
    let file_end_usize = usize::try_from(file_end)
        .map_err(|_| MaterializeError::InvalidFile)?;
    if file_end_usize > input.len() {
        return Err(MaterializeError::InvalidFile);
    }
    let expected_start = segment.virtual_address & !(PAGE_BYTES - 1);
    let expected_end = memory_end.checked_add(PAGE_BYTES - 1)
        .ok_or(MaterializeError::InvalidSegment)? & !(PAGE_BYTES - 1);
    if expected_start < USER_MIN || memory_end > USER_END
        || expected_end > USER_END
        || segment.page_start != expected_start
        || segment.page_end != expected_end
        || segment.virtual_address % PAGE_BYTES != segment.file_offset % PAGE_BYTES
    {
        return Err(MaterializeError::InvalidSegment);
    }
    let page_end = page_virtual.checked_add(PAGE_BYTES)
        .ok_or(MaterializeError::InvalidPage)?;
    if page_virtual % PAGE_BYTES != 0
        || page_virtual < expected_start || page_end > expected_end
    {
        return Err(MaterializeError::InvalidPage);
    }

    let copy_start = page_virtual.max(segment.virtual_address);
    let copy_end = page_end.min(file_va_end);
    let (from, into, copied) = if copy_start < copy_end {
        let offset = copy_start - segment.virtual_address;
        let start = segment.file_offset.checked_add(offset)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(MaterializeError::InvalidFile)?;
        let size = usize::try_from(copy_end - copy_start)
            .map_err(|_| MaterializeError::InvalidFile)?;
        let src_end = start.checked_add(size).ok_or(MaterializeError::InvalidFile)?;
        if src_end > input.len() {
            return Err(MaterializeError::InvalidFile);
        }
        let dest_start = usize::try_from(copy_start - page_virtual)
            .map_err(|_| MaterializeError::InvalidPage)?;
        (start, dest_start, size)
    } else {
        (0, 0, 0)
    };
    target.fill(0);
    if copied != 0 {
        target[into..into + copied].copy_from_slice(&input[from..from + copied]);
    }
    Ok(PageContents {
        copied,
        zeroed: PAGE_SIZE - copied,
        writable: segment.writable,
        executable: segment.executable,
    })
}
