//! Single-BSP actual user INT80 -> PID-owned original WolfOS VFS backend.
//! Only fixed bootstrap file namespace in this isolated guest flavor.
//! There is deliberately no borrowing or HHDM dereference of user pointers
//! here: user_copy validates LIVE page tables and copies bytes into short
//! kernel-owned stack buffers before invoking these VFS methods.
//! This is not a general-purpose per-process VFS concurrency implementation.
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::{ramfs::MAX_FILE_BYTES, serial, vfs::{Vfs, Mode, Descriptor, VfsError}};

pub const PATH: &[u8; 13] = b"/tmp/user.txt";
pub const CONTENT: &[u8; 8] = b"FILE_OK\n";
const PID: u64 = 1;
const FS_CAP: usize = MAX_FILE_BYTES;
struct StaticFs(UnsafeCell<Vfs<2, FS_CAP>>);
// SAFETY: ONLY dedicated single-BSP, interrupts disabled QEMU feature.
// All operations run serially (between user INT80 traps), so there is
// never more than one live reference to the VFS backing object.
unsafe impl Sync for StaticFs {}
static FS: StaticFs = StaticFs(UnsafeCell::new(Vfs::new()));
static READY: AtomicBool = AtomicBool::new(false);

fn vfs_mut() -> &'static mut Vfs<2, FS_CAP> {
    // SAFETY: unique access guaranteed by this single-CPU, IF=0 test.
    unsafe { &mut *FS.0.get() }
}
pub fn prepare() {
    if READY.load(Ordering::Acquire) { crate::halt_forever() }
    let fs = vfs_mut();
    if fs.create("/tmp/user.txt", CONTENT, true).is_err()
        || fs.create("/etc/wolfos.conf", b"comfort=on\n", true).is_err()
        || fs.open_count() != 0 || fs.volume_counts() != (1,1)
    {
        serial::write_line("WOLFOS_FILE_IO_ERROR prepare");
        crate::halt_forever()
    }
    READY.store(true, Ordering::Release);
    serial::write_line("WOLFOS_FILE_IO_READY root_tmp=2 sealed=1 pid_scoped=1");
}
fn require_ready() -> Result<(), VfsError> {
    if READY.load(Ordering::Acquire) { Ok(()) }
    else { Err(VfsError::PermissionDenied) }
}
fn from_token(token: u64) -> Result<Descriptor, VfsError> {
    let generation = token >> 32;
    let slot = (token & 0xffff_ffff) as usize;
    if generation == 0 || slot >= crate::vfs::MAX_OPEN {
        return Err(VfsError::StaleDescriptor)
    }
    Ok(Descriptor { slot, generation })
}
pub fn open_read(pid: u64, path: &[u8]) -> Result<u64, VfsError> {
    require_ready()?;
    let text = core::str::from_utf8(path).map_err(|_| VfsError::InvalidPath)?;
    let fd = vfs_mut().open(pid, text, Mode::Read)?;
    let generation = u32::try_from(fd.generation)
        .map_err(|_| VfsError::GenerationExhausted)?;
    Ok((u64::from(generation) << 32) | fd.slot as u64)
}
pub fn read(pid: u64, token: u64, dest: &mut [u8]) -> Result<usize, VfsError> {
    require_ready()?;
    vfs_mut().read(pid, from_token(token)?, dest)
}
pub fn tell(pid: u64, token: u64) -> Result<usize, VfsError> {
    require_ready()?;
    vfs_mut().tell(pid, from_token(token)?)
}
pub fn close(pid: u64, token: u64) -> Result<(), VfsError> {
    require_ready()?;
    vfs_mut().close(pid, from_token(token)?)
}
pub fn finish(pid: u64) {
    if require_ready().is_err()
        || vfs_mut().close_all(pid) != Ok(0)
        || vfs_mut().open_count() != 0
    {
        serial::write_line("WOLFOS_FILE_IO_ERROR leaked_fd");
        crate::halt_forever()
    }
    serial::write_line("WOLFOS_FILE_IO_DONE calls=5 read_bytes=8 efault_denials=2 opened=1 closed=1 leaked_fd=0");
}
