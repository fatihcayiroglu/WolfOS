//! One-BSP QEMU adapter for the new original RAMFS.
//!
//! Boot fixture ELF is inserted into an actual in-memory file, sealed,
//! reopened and then borrowed as immutable file bytes by the EXISTING
//! strict ELF loader. That loader still independently preflights and maps
//! RX text / RW data+BSS, executes CPL3 and checks PMM ownership on EXIT.
//! No global VFS, no persistent storage, no user-space file descriptor ABI.
//!
//! ONLY under the single-vCPU, IF=0 user-ramfs-smoke feature: static UnsafeCell
//! is mutated exactly once before READY=Release; later reads are immutable.
//! There is no way to reenter prepare() or mutate the sealed executable.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::{ramfs::{FileId, FileInfo, FsError, RamFs, MAX_FILE_BYTES}, serial};

const CAP: usize = MAX_FILE_BYTES;
const FILES: usize = 2;
const PATH: &str = "/bin/hello.elf";
const CONFIG: &str = "/etc/wolfos.conf";
const CONFIG_CONTENT: &[u8] = b"ui=comfortable\n";

struct StaticFs(UnsafeCell<RamFs<FILES, CAP>>);
// SAFETY: access is exclusive during prepare(), before READY is published.
// All post-READY calls borrow contents immutably. One BSP, IF disabled, no
// other tasks run, and no process or VFS can mutate this private instance.
unsafe impl Sync for StaticFs {}
static FS: StaticFs = StaticFs(UnsafeCell::new(RamFs::new()));
static READY: AtomicBool = AtomicBool::new(false);

fn fail(reason: &str) -> ! {
    serial::write_fmt(format_args!("WOLFOS_RAMFS_ERROR {reason}\n"));
    crate::halt_forever()
}

/// Prepare must run once on the original kernel CR3 before any IRETQ.
/// The whole file is copied into RAMFS storage, not directly into an ELF
/// destination frame, and afterward borrowed from that file by the loader.
pub fn prepare(elf: &[u8]) {
    if READY.load(Ordering::Acquire)
        || elf.len() < 64 || elf.len() > CAP
    { fail("already_ready_or_invalid_source") }
    // SAFETY: exclusive access is guaranteed until the one and only
    // READY publication; no other CPU or interrupt handler accesses FS.
    let fs = unsafe { &mut *FS.0.get() };
    let Ok(id) = fs.create(PATH) else { fail("create_elf") };
    if fs.write(id, 0, elf) != Ok(elf.len()) { fail("write_elf") }
    if fs.seal(id).is_err() || fs.open(PATH) != Ok(id)
        || fs.info(id) != Ok(FileInfo { size: elf.len(), sealed: true })
        || fs.write(id, 0, b"evil") != Err(FsError::Sealed)
    { fail("sealed_elf_contract") }
    let mut head = [0u8; 64];
    if fs.read(id, 0, &mut head) != Ok(head.len())
        || head != elf[..64]
    { fail("read_elf_header") }

    // Demonstrate an independent configurable file and stale-handle
    // rejection without mutating the SEALED executable itself.
    let Ok(config) = fs.create(CONFIG) else { fail("create_config") };
    if fs.write(config, 0, CONFIG_CONTENT) != Ok(CONFIG_CONTENT.len())
    { fail("write_config") }
    let mut buf = [0u8; CONFIG_CONTENT.len()];
    if fs.read(config, 0, &mut buf) != Ok(buf.len()) || buf != CONFIG_CONTENT {
        fail("config_readback")
    }
    if fs.create("/etc/../bin/hello.elf") != Err(FsError::InvalidPath)
        || fs.create(PATH) != Err(FsError::Duplicate)
        || fs.create("/third") != Err(FsError::Full)
        || fs.unlink(config).is_err()
        || fs.read(config, 0, &mut buf) != Err(FsError::StaleHandle)
        || fs.files() != 1
    { fail("paths_capacity_or_stale_handle") }
    let Ok(current) = fs.open(PATH) else { fail("lost_elf") };
    if current != id { fail("identity_changed") }
    READY.store(true, Ordering::Release);
    serial::write_fmt(format_args!(
        "WOLFOS_RAMFS_READY slots=2 capacity={} elf_path={} elf_bytes={} sealed=1 reopen=1 path_denial=1 stale_denial=1\n",
        CAP, PATH, elf.len(),
    ));
}

/// Return the file-owned immutable ELF byte slice, NEVER the original
/// embedded fixture. Source data cannot change after READY is published.
pub fn elf_file() -> &'static [u8] {
    if !READY.load(Ordering::Acquire) { fail("not_prepared") }
    // SAFETY: READY makes all prior modifications visible and no code
    // mutates FS ever again. Storage is static and not freed.
    let fs: &'static RamFs<FILES, CAP> = unsafe { &*FS.0.get() };
    let Ok(id) = fs.open(PATH) else { fail("file_open_after_ready") };
    let Ok(bytes) = fs.contents(id) else { fail("file_read_after_ready") };
    bytes
}

pub fn report_elf_exit() {
    if !READY.load(Ordering::Acquire) { fail("lost_ready_state") }
    let bytes = elf_file();
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" {
        fail("elf_corrupted_before_exit")
    }
    serial::write_line("WOLFOS_RAMFS_EXEC_OK staged_elf=1 file_backed_loader=1 cpl3=1 hello=1 exited=1 pmm_no_leak=1 persistent=0");
}
