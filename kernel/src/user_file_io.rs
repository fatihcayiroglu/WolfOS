//! Bounded WolfOS user-facing VFS syscall backend (P2 contract stage).
//!
//! Syscall register convention reserved for the next isolated CPL3 gate:
//!   5 WRITE_PTR (already proven by #76), 6 OPEN_RO, 7 READ, 8 CLOSE.
//!   OPEN_RO: RDI=user path VA, RSI=path byte count (no trailing NUL).
//!   READ: RDI=opaque fd, RSI=user destination VA, RDX=byte count.
//!   CLOSE: RDI=opaque fd, RSI=RDX=0.
//!   All return RAX: nonnegative success or negative errno encoded as u64.
//!
//! The caller MUST supply physical access limited to its own CR3 tables
//! and PMM-owned leaves (as in #76), with IRQs disabled / memory pinned
//! for the entire call. No untrusted virtual address is dereferenced.
//! This module is pure plumbing, not a connected hardware INT80 handler:
//! no generic concurrent processes, user fault recovery or stable POSIX ABI.
use crate::user_copy::{self, MAX_COPY};
use crate::vfs::{Descriptor, Mode, Vfs, VfsError, MAX_OPEN};

pub const SYS_OPEN_RO: u64 = 6;
pub const SYS_READ: u64 = 7;
pub const SYS_CLOSE: u64 = 8;
pub const MAX_PATH_BYTES: usize = 63;

pub const ENOENT: i64 = -2;
pub const EIO: i64 = -5;
pub const EBADF: i64 = -9;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EBUSY: i64 = -16;
pub const EINVAL: i64 = -22;
pub const EMFILE: i64 = -24;

fn negative(errno: i64) -> u64 { errno as u64 }

fn vfs_errno(error: VfsError) -> u64 {
    let errno = match error {
        VfsError::InvalidPid | VfsError::InvalidPath | VfsError::InvalidSeek => EINVAL,
        VfsError::StaleDescriptor => EBADF,
        VfsError::PermissionDenied => EACCES,
        VfsError::Full | VfsError::GenerationExhausted => EMFILE,
        VfsError::Busy => EBUSY,
        VfsError::Backend(_) => ENOENT,
    };
    negative(errno)
}

// 8 low bits for slot; 56 high bits for generation. The VFS checks both
// the generation AND owner PID on EVERY operation; handles never expose
// a live kernel memory address.
fn encode_fd(fd: Descriptor) -> Option<u64> {
    if fd.slot >= MAX_OPEN || fd.slot >= 256
        || fd.generation == 0 || fd.generation > (u64::MAX >> 8)
    { return None }
    Some((fd.generation << 8) | fd.slot as u64)
}
fn decode_fd(handle: u64) -> Option<Descriptor> {
    let slot = (handle & 255) as usize;
    let generation = handle >> 8;
    if slot >= MAX_OPEN || generation == 0 { return None }
    Some(Descriptor { slot, generation })
}

/// Copy an explicitly counted user pathname through the #76 4-level
/// page-table walker, then open read-only in the PID-owned VFS.
/// A failed descriptor encoding is rolled back instead of leaking a slot.
pub fn open_read_only<const FILES: usize, const CAP: usize>(
    fs: &mut Vfs<FILES, CAP>,
    pid: u64,
    root: u64,
    path_va: u64,
    path_len: u64,
    authorized_path: &str,
    pte: impl FnMut(u64) -> Option<u64>,
    read_phys: impl FnMut(u64) -> Option<u8>,
) -> u64 {
    let Ok(len) = usize::try_from(path_len) else { return negative(EINVAL) };
    if len == 0 || len > MAX_PATH_BYTES || pid == 0 {
        return negative(EINVAL)
    }
    let mut path = [0u8; MAX_PATH_BYTES];
    if user_copy::copy_from(root, path_va, &mut path[..len], pte, read_phys).is_err() {
        return negative(EFAULT)
    }
    // Preserve the strict ASCII slash/path policy from RamFS rather than
    // silently accepting lossy UTF-8 or NUL-terminated ambiguous strings.
    if !path[..len].is_ascii() || path[..len].contains(&0) {
        return negative(EINVAL)
    }
    let Ok(name) = core::str::from_utf8(&path[..len]) else {
        return negative(EINVAL)
    };
    // Check the exact path copied from the verified user page table before
    // allocating a descriptor. Prefix matches are NEVER sufficient.
    if name != authorized_path { return negative(EACCES) }
    let token = match fs.open(pid, name, Mode::Read) {
        Ok(fd) => fd,
        Err(error) => return vfs_errno(error),
    };
    if let Some(handle) = encode_fd(token) { handle }
    else {
        let _ = fs.close(pid, token);
        negative(EMFILE)
    }
}

/// Canonical pathname on a validated PID-owned live descriptor. The caller
/// enforces its current policy lease against this pathname on EVERY READ.
pub fn read_target_path<const FILES: usize, const CAP: usize>(
    fs: &Vfs<FILES, CAP>, pid: u64, handle: u64,
) -> Result<&str, u64> {
    let token = decode_fd(handle).ok_or_else(|| negative(EBADF))?;
    fs.descriptor_path(pid, token).map_err(vfs_errno)
}

/// Read up to #76's maximum buffer size, transferring only through
/// copy_to's checked user PTE walk. On failure the VFS cursor is restored
/// to avoid consuming bytes from a rejected user destination.
/// No partial-copy guarantee can be made if caller permits concurrent
/// page-table remapping; this contract explicitly forbids that.
pub fn read_into_user<const FILES: usize, const CAP: usize>(
    fs: &mut Vfs<FILES, CAP>,
    pid: u64,
    handle: u64,
    root: u64,
    dst_va: u64,
    count: u64,
    pte: impl FnMut(u64) -> Option<u64>,
    write_phys: impl FnMut(u64, Option<u8>) -> Option<u8>,
) -> u64 {
    let Some(token) = decode_fd(handle) else { return negative(EBADF) };
    let Ok(len) = usize::try_from(count) else { return negative(EINVAL) };
    if len > MAX_COPY { return negative(EINVAL) }
    let cursor = match fs.tell(pid, token) {
        Ok(x) => x,
        Err(error) => return vfs_errno(error),
    };
    if len == 0 { return 0 }
    let mut staging = [0u8; MAX_COPY];
    let n = match fs.read(pid, token, &mut staging[..len]) {
        Ok(n) => n,
        Err(error) => return vfs_errno(error),
    };
    if n == 0 { return 0 }
    if user_copy::copy_to(root, dst_va, &staging[..n], pte, write_phys).is_err() {
        // Real VFS remains serialized for this operation; a later
        // concurrent implementation needs per-open locking and pinning.
        if fs.seek(pid, token, cursor).is_err() { return negative(EIO) }
        return negative(EFAULT)
    }
    n as u64
}

/// PID-scoped opaque descriptor release. Call Vfs::close_all(pid) at exit.
pub fn close_handle<const FILES: usize, const CAP: usize>(
    fs: &mut Vfs<FILES, CAP>, pid: u64, handle: u64,
) -> u64 {
    let Some(token) = decode_fd(handle) else { return negative(EBADF) };
    match fs.close(pid, token) {
        Ok(()) => 0,
        Err(error) => vfs_errno(error),
    }
}
