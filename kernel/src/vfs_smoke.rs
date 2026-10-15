//! Isolated one-BSP VFS smoke: a REAL ELF is staged into the WolfOS VFS,
//! opened via a generation-checked PID-scoped FD, then loaded ONLY from
//! the immutable contents of the sealed /bin/hello.elf file.
//!
//! A distinct /tmp mount is exercised with independent data, per-FD cursor,
//! read-only/write mode, wrong-PID isolation, busy unlink, stale token
//! rejection and process-owner descriptor cleanup.
//!
//! This smoke does NOT expose VFS operations as user syscalls yet. Those
//! require bounded user-pointer copying and a stable process FD registry.
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool,Ordering};
use crate::{
    serial, vfs::{Descriptor,Mode,Vfs,VfsError},
    ramfs::{FsError, MAX_FILE_BYTES},
};

const ELF_PATH: &str = "/bin/hello.elf";
const TMP_PATH: &str = "/tmp/session.log";
const ROOT_PREFIX_PATH: &str = "/tmpx/marker";
const CAP: usize = MAX_FILE_BYTES;
const FILES: usize = 2;
struct StaticVfs(UnsafeCell<Vfs<FILES,CAP>>);
// SAFETY: sole BSP initializes before READY=Release. After READY, no
// mutable access occurs, only immutable byte borrow. IF=0, one vCPU.
unsafe impl Sync for StaticVfs {}
static VFS: StaticVfs = StaticVfs(UnsafeCell::new(Vfs::new()));
static READY: AtomicBool = AtomicBool::new(false);

fn fail(why: &str) -> ! {
    serial::write_fmt(format_args!("WOLFOS_VFS_ERROR {why}\n"));
    crate::halt_forever()
}

pub fn prepare(embedded_elf: &[u8]) {
    if READY.load(Ordering::Acquire)
        || embedded_elf.len() < 64 || embedded_elf.len() > CAP
    { fail("invalid_source_or_duplicate_prepare") }

    // SAFETY: no other task/CPU touches VFS until READY=Release; thereafter
    // the instance is never mutated again during this single-vCPU smoke.
    let fs = unsafe { &mut *VFS.0.get() };
    if fs.create(ELF_PATH, embedded_elf, true).is_err()
        || fs.create(TMP_PATH, b"config=easy", false).is_err()
        || fs.create(ROOT_PREFIX_PATH, b"root!", false).is_err()
        || fs.volume_counts() != (2,1)
    { fail("mount_or_file_stage") }

    let Ok(elf_fd) = fs.open(1, ELF_PATH, Mode::Read)
    else { fail("elf_descriptor_open") };
    let mut magic = [0u8; 4];
    if fs.read(1, elf_fd, &mut magic) != Ok(4) || &magic != b"\x7fELF"
        || fs.tell(1, elf_fd) != Ok(4)
        || fs.read(2, elf_fd, &mut magic) != Err(VfsError::PermissionDenied)
        || fs.open(1, ELF_PATH, Mode::ReadWrite)
            != Err(VfsError::PermissionDenied)
        || fs.unlink(ELF_PATH) != Err(VfsError::Busy)
        || fs.seek(1, elf_fd, embedded_elf.len()+1) != Err(VfsError::InvalidSeek)
    { fail("sealed_elf_fd_policy") }
    if fs.close(1, elf_fd).is_err()
        || fs.read(1, elf_fd, &mut magic) != Err(VfsError::StaleDescriptor)
    { fail("stale_elf_fd") }

    let Ok(tmp) = fs.open(1, TMP_PATH, Mode::ReadWrite)
    else { fail("tmp_descriptor") };
    let mut first = [0u8; 6];
    if fs.read(1,tmp,&mut first) != Ok(6) || &first != b"config"
        || fs.tell(1,tmp) != Ok(6)
        || fs.write(1,tmp,b"=ok") != Ok(3)
        || fs.tell(1,tmp) != Ok(9)
        || fs.seek(1,tmp,0).is_err()
    { fail("tmp_cursor_or_rw") }
    let mut all = [0u8;9];
    if fs.read(1,tmp,&mut all) != Ok(9) || &all != b"config=ok"
        || fs.read(2,tmp,&mut all) != Err(VfsError::PermissionDenied)
        || fs.unlink(TMP_PATH) != Err(VfsError::Busy)
        || fs.open(1, "/tmp/../bin/hello.elf", Mode::Read)
            != Err(VfsError::Backend(FsError::InvalidPath))
    { fail("tmp_mount_or_pid_isolation") }

    let Ok(rootfd) = fs.open(2, ROOT_PREFIX_PATH, Mode::Read)
    else { fail("prefix_root_descriptor") };
    let mut prefix = [0u8;5];
    if fs.read(2, rootfd, &mut prefix) != Ok(5) || &prefix != b"root!"
    { fail("tmp_prefix_routing") }

    // PID 1 cleanup may not close PID 2's descriptor.
    if fs.close_all(1) != Ok(1)
        || fs.tell(1, tmp) != Err(VfsError::StaleDescriptor)
        || fs.tell(2, rootfd) != Ok(5)
        || fs.close_all(2) != Ok(1)
        || fs.open_count() != 0
    { fail("fd_owner_close_all") }
    if fs.unlink(TMP_PATH).is_err()
        || fs.volume_counts() != (2,0)
        || fs.immutable(ELF_PATH).ok() != Some(embedded_elf)
    { fail("sealed_elf_or_temp_cleanup") }

    READY.store(true,Ordering::Release);
    serial::write_fmt(format_args!(
        "WOLFOS_VFS_READY root_mount=1 tmp_mount=1 owner_fds=1 stale_fds=1 busy_unlink=1 sealed_elf=1 path_denial=1 elf_bytes={} cap=32768\n",
        embedded_elf.len(),
    ));
}

pub fn elf_file() -> &'static [u8] {
    if !READY.load(Ordering::Acquire) { fail("not_ready") }
    // SAFETY: RAMFS is static, after READY no code mutates storage; all
    // process execution only borrows immutable file data.
    let fs: &'static Vfs<FILES,CAP> = unsafe { &*VFS.0.get() };
    match fs.immutable(ELF_PATH) {
        Ok(elf) => elf,
        Err(_) => fail("sealed_elf_lost"),
    }
}

pub fn report_exit() {
    if !READY.load(Ordering::Acquire) { fail("vfs_unprepared_exit") }
    if elf_file().get(0..4) != Some(&b"\x7fELF"[..]) {
        fail("elf_mutated_during_execution")
    }
    serial::write_line("WOLFOS_VFS_EXEC_OK file_backed_elf=1 hardware_cpl3=1 root_tmp=2 owner_fd=1 sealed=1 exited=1 pmm_no_leak=1 persistent=0");
}
