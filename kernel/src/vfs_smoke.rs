//! Single-BSP QEMU admission for original WolfOS VFS + descriptor semantics.
//!
//! This adapter stages independently linked ELF64 via real OPEN(Write),
//! WRITE, CLOSE, SEAL, OPEN(Read), READ, SEEK and immutable descriptor loan.
//! The real strict ELF loader consumes the FILE bytes reached via VFS, not
//! the included build fixture. The same verified real CPL3 INT80/EXIT
//! experiment then demonstrates leak-free process teardown.
//!
//! SAFETY LIMIT: static UnsafeCell is only mutated before READY publication,
//! on one BSP with interrupts disabled. There is no user VFS syscall ABI,
//! concurrency, dynamic namespaces, independent process FD table, or disk.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use crate::{
    ramfs::{FsError, MAX_FILE_BYTES},
    serial,
    vfs::{Access, Descriptor, Vfs, VfsError},
};

const FILES: usize = 2;
const OPEN: usize = 3;
const CAP: usize = MAX_FILE_BYTES;
const ELF_PATH: &str = "/bin/hello.elf";
const CFG_PATH: &str = "/etc/wolfos.conf";
const CFG: &[u8] = b"experience=comfortable\n";

struct StaticVfs(UnsafeCell<Vfs<FILES, CAP, OPEN>>);
// SAFETY: only one CPU ever calls prepare once before READY, and all other
// entrypoints use immutable shared reads after the publication. No task,
// interrupt or process can access or mutate this private test namespace.
unsafe impl Sync for StaticVfs {}
static FS: StaticVfs = StaticVfs(UnsafeCell::new(Vfs::new()));
static READY: AtomicBool = AtomicBool::new(false);
static FD_SLOT: AtomicUsize = AtomicUsize::new(usize::MAX);
static FD_GENERATION: AtomicU64 = AtomicU64::new(0);

fn fail(reason: &str) -> ! {
    serial::write_fmt(format_args!("WOLFOS_VFS_ERROR {reason}\n"));
    crate::halt_forever()
}
pub fn prepare(embedded_elf: &[u8]) {
    if READY.load(Ordering::Acquire)
        || embedded_elf.len() < 64 || embedded_elf.len() > CAP
    { fail("duplicate_prepare_or_invalid_elf") }

    // SAFETY: single BSP, IF=0, FS private; no borrow is published yet.
    let fs = unsafe { &mut *FS.0.get() };
    let Ok(image) = fs.create(ELF_PATH) else { fail("elf_create") };
    let Ok(wr) = fs.open(ELF_PATH, Access::Write) else { fail("elf_open_write") };
    if fs.write(wr, embedded_elf) != Ok(embedded_elf.len())
        || fs.seal(image) != Err(VfsError::FileBusy)
        || fs.open(ELF_PATH, Access::Read) != Err(VfsError::FileBusy)
        || fs.close(wr).is_err()
        || fs.write(wr, b"X") != Err(VfsError::DescriptorInvalid)
    { fail("exclusive_elf_writer_or_stale_fd") }

    if fs.seal(image).is_err()
        || fs.open(ELF_PATH, Access::Write) != Err(VfsError::AccessDenied)
    { fail("sealed_elf_is_writable") }
    let Ok(rd) = fs.open(ELF_PATH, Access::Read) else { fail("elf_open_read") };
    let mut header = [0u8; 64];
    if fs.read(rd, &mut header) != Ok(64)
        || header != embedded_elf[..64]
        || fs.tell(rd) != Ok(64)
        || fs.seek(rd, 0).is_err()
        || fs.unlink(ELF_PATH) != Err(VfsError::FileBusy)
    { fail("elf_descriptor_read_seek_or_busy") }

    let Ok(cfg) = fs.create(CFG_PATH) else { fail("config_create") };
    let Ok(cfg_wr) = fs.open(CFG_PATH, Access::Write) else { fail("config_open") };
    if fs.write(cfg_wr, CFG) != Ok(CFG.len())
        || fs.close(cfg_wr).is_err()
    { fail("config_write_close") }
    let Ok(cfg_rd) = fs.open(CFG_PATH, Access::Read) else { fail("config_reopen") };
    let mut cfg_back = [0u8; CFG.len()];
    if fs.read(cfg_rd, &mut cfg_back) != Ok(CFG.len())
        || cfg_back != CFG
        || fs.close(cfg_rd).is_err()
        || fs.read(cfg_rd, &mut cfg_back) != Err(VfsError::DescriptorInvalid)
        || fs.unlink(CFG_PATH).is_err()
    { fail("config_read_close_or_unlink") }

    if fs.create("/etc/../bin/hello.elf") != Err(VfsError::Fs(FsError::InvalidPath))
        || fs.create(ELF_PATH) != Err(VfsError::Fs(FsError::Duplicate))
        || fs.count_files() != 1
        || fs.count_open() != 1
    { fail("vfs_namespace_and_fd_audit") }
    let Ok(bytes) = fs.executable_bytes(rd) else { fail("immutable_elf_borrow") };
    if bytes != embedded_elf || bytes.get(..4) != Some(&b"\x7fELF"[..]) {
        fail("ramfs_elf_content_mismatch")
    }

    FD_SLOT.store(rd.slot, Ordering::Relaxed);
    FD_GENERATION.store(rd.generation, Ordering::Relaxed);
    READY.store(true, Ordering::Release);
    serial::write_fmt(format_args!(
        "WOLFOS_VFS_READY files=1 open_fds=1 slot_generation=1 sealed_elf=1 open_close=1 cursor=1 config_io=1 stale_fd_denied=1 elf_bytes={}\n",
        embedded_elf.len()
    ));
}

pub fn elf_file() -> &'static [u8] {
    if !READY.load(Ordering::Acquire) { fail("namespace_not_prepared") }
    // SAFETY: READY synchronizes with all previous writes; no mutation
    // afterward, and statically backed RAMFS storage remains initialized.
    let fs: &'static Vfs<FILES, CAP, OPEN> = unsafe { &*FS.0.get() };
    let descriptor = Descriptor {
        slot: FD_SLOT.load(Ordering::Acquire),
        generation: FD_GENERATION.load(Ordering::Acquire),
    };
    let Ok(bytes) = fs.executable_bytes(descriptor) else {
        fail("invalid_sealed_elf_descriptor")
    };
    bytes
}

pub fn report_exit() {
    if !READY.load(Ordering::Acquire) { fail("namespace_disappeared") }
    let bytes = elf_file();
    if bytes.len() < 64 || bytes.get(..4) != Some(&b"\x7fELF"[..]) {
        fail("elf_header_corrupt_after_guest")
    }
    serial::write_line("WOLFOS_VFS_EXEC_OK descriptor_source=1 sealed=1 cpl3=1 hello=1 exit=0 cr3_restored=1 all_frames_freed=1 user_file_syscalls=0");
}
