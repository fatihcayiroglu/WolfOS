//! Feature-isolated real CPL3 INT80 OPEN/READ/CLOSE bridge.
//! Single BSP, IF=0, one PID, immutable live CR3 and exactly seven PMM
//! frames under a checked allowlist in user_elf_run_smoke; NOT production IO.
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::{
    serial,
    user_elf_run_smoke::{private_byte, private_pte, private_rw_byte},
    user_file_io::{self, SYS_OPEN_RO, SYS_READ, SYS_CLOSE},
    vfs::Vfs,
};

const PID: u64 = 1;
const CONTENT: &[u8; 8] = b"FILE_OK\n";
const PATH: &str = "/tmp/msg.txt";
struct OneCpuFs(UnsafeCell<Vfs<2, 256>>);
// SAFETY: This feature executes ONLY on the BSP with interrupts disabled;
// no AP may borrow it, and every syscall finishes before the next trap.
unsafe impl Sync for OneCpuFs {}
static FS: OneCpuFs = OneCpuFs(UnsafeCell::new(Vfs::new()));
static READY: AtomicBool = AtomicBool::new(false);

fn fail(msg: &str) -> ! {
    serial::write_fmt(format_args!("WOLFOS_FILE_IO_ERROR {msg}\n"));
    crate::halt_forever()
}

pub fn prepare() {
    if READY.load(Ordering::Acquire) { fail("duplicate_prepare") }
    // SAFETY: no other code or core can access FS until READY=Release.
    let fs = unsafe { &mut *FS.0.get() };
    if fs.create(PATH, CONTENT, true).is_err()
        || fs.open_count() != 0 || fs.volume_counts() != (0, 1)
    { fail("file_stage") }
    READY.store(true, Ordering::Release);
    serial::write_line("WOLFOS_FILE_IO_READY tmp_mount=1 sealed_file=1 pid_owner=1");
}

/// Only the caller can enable this interface after verifying a genuine
/// trusted CPL3 trap frame, active CR3 and PID. All physical access is
/// independently restricted to current-process PMM-owned frames.
pub fn dispatch(pid: u64, cr3: u64, nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    if !READY.load(Ordering::Acquire) || pid != PID || cr3 == 0 {
        fail("wrong_pid_or_root")
    }
    // SAFETY: serialized BSP INT80, IF=0, no mutable aliases / remappers.
    let fs = unsafe { &mut *FS.0.get() };
    match nr {
        SYS_OPEN_RO if a2 == 0 =>
            user_file_io::open_read_only(
                fs, pid, cr3, a0, a1, private_pte, private_byte
            ),
        SYS_READ =>
            user_file_io::read_into_user(
                fs, pid, a0, cr3, a1, a2, private_pte, private_rw_byte
            ),
        SYS_CLOSE if a1 == 0 && a2 == 0 =>
            user_file_io::close_handle(fs, pid, a0),
        _ => user_file_io::EINVAL as u64,
    }
}

pub fn verify_exit(pid: u64) {
    if !READY.load(Ordering::Acquire) || pid != PID { fail("invalid_exit") }
    // SAFETY: still single-BSP, IF=0, and no VFS borrow escapes INT80.
    let fs = unsafe { &mut *FS.0.get() };
    if fs.open_count() != 0 || fs.close_all(pid) != Ok(0)
        || fs.immutable(PATH).ok() != Some(CONTENT.as_slice())
    { fail("descriptor_leak_or_file_corruption") }
    serial::write_line("WOLFOS_FILE_IO_FDS_OK open=0 stale_denied=1 pid_cleanup=1");
}
