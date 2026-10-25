//! Feature-isolated WolfOS Shield FILE_READ permission over real CPL3
//! INT80 OPEN/READ, backed by PID-owned VFS descriptors. Default deny,
//! trusted kernel grant/revoke, and retire on exit are mandatory in QEMU.
//! Single BSP, IF=0, fixed ELF, seven PMM frames: NOT a general policy UI.
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use crate::{
    app_permissions::{AppPermissions, Permission, PermissionError},
    serial,
    user_elf_run_smoke::{private_byte, private_pte, private_rw_byte},
    user_file_io::{self, SYS_OPEN_RO, SYS_READ, SYS_CLOSE},
    vfs::Vfs,
};

const PID: u64 = 1;
const CONTENT: &[u8; 8] = b"FILE_OK\n";
const PATH: &str = "/tmp/msg.txt";
struct FileService {
    fs: Vfs<2, 256>,
    grants: AppPermissions<2>,
}
struct OneCpuService(UnsafeCell<FileService>);
// SAFETY: only the BSP with interrupts disabled may access the feature's
// state, all operations finish before another trap, no refs escape.
unsafe impl Sync for OneCpuService {}
static SERVICE: OneCpuService = OneCpuService(UnsafeCell::new(FileService {
    fs: Vfs::new(), grants: AppPermissions::new(),
}));
static READY: AtomicBool = AtomicBool::new(false);

fn fail(msg: &str) -> ! {
    serial::write_fmt(format_args!("WOLFOS_FILE_IO_ERROR {msg}\n"));
    crate::halt_forever()
}

pub fn prepare() {
    if READY.load(Ordering::Acquire) { fail("duplicate_prepare") }
    // SAFETY: this isolated flavor has no other access before READY.
    let state = unsafe { &mut *SERVICE.0.get() };
    if state.fs.create(PATH, CONTENT, true).is_err()
        || state.fs.open_count() != 0
        || state.fs.volume_counts() != (0, 1)
        || state.grants.enroll(PID).is_err()
        || state.grants.allows(PID, Permission::FileRead)
    { fail("file_stage_or_default_deny") }
    READY.store(true, Ordering::Release);
    serial::write_line("WOLFOS_FILE_IO_READY tmp_mount=1 sealed_file=1 pid_owner=1");
}

fn checked(pid: u64) -> &'static mut FileService {
    if !READY.load(Ordering::Acquire) || pid != PID {
        fail("unauthenticated_permission_owner")
    }
    // SAFETY: single-BSP IF=0 QEMU flavor; the trusted caller has
    // authenticated current PID and no mutable reference escapes.
    unsafe { &mut *SERVICE.0.get() }
}

/// The caller first authenticated the genuine CPL3 INT80, registers and
/// active user CR3. A denied OPEN must not allocate ANY VFS descriptor.
pub fn prove_default_denial(pid: u64) {
    let state = checked(pid);
    if state.fs.open_count() != 0
        || state.grants.allows(pid, Permission::FileRead)
    { fail("permission_default_deny_bypass") }
    serial::write_line("WOLFOS_SHIELD_FILE_DENIED_OK pid=1 fd_open=0 policy_default_deny=1");
}

/// Trusted kernel-only QEMU policy action, never an exposed user syscall.
pub fn grant_file_read(pid: u64, expected_open: usize) {
    let state = checked(pid);
    if state.fs.open_count() != expected_open
        || state.grants.allows(pid, Permission::FileRead)
        || state.grants.grant(pid, Permission::FileRead).is_err()
        || !state.grants.allows(pid, Permission::FileRead)
    { fail("permission_grant_transition") }
    if expected_open == 0 {
        serial::write_line("WOLFOS_SHIELD_FILE_GRANT_OK pid=1 handles=0");
    } else {
        serial::write_line("WOLFOS_SHIELD_FILE_REGRANT_OK pid=1 handles=1");
    }
}

pub fn revoke_file_read(pid: u64) {
    let state = checked(pid);
    if state.fs.open_count() != 1
        || !state.grants.allows(pid, Permission::FileRead)
        || state.grants.revoke(pid, Permission::FileRead).is_err()
        || state.grants.allows(pid, Permission::FileRead)
    { fail("permission_live_revoke") }
    serial::write_line("WOLFOS_SHIELD_FILE_REVOKE_OK pid=1 handles=1");
}

pub fn prove_revoked_read(pid: u64) {
    let state = checked(pid);
    if state.fs.open_count() != 1
        || state.grants.allows(pid, Permission::FileRead)
    { fail("permission_revoked_descriptor_bypass") }
    serial::write_line("WOLFOS_SHIELD_READ_DENIED_OK pid=1 retained_fd=1");
}

/// Only the caller can enable this interface after verifying a genuine
/// CPL3 trap frame, active CR3 and PID. No untrusted user pointer is
/// followed before the FILE_READ policy gate succeeds.
pub fn dispatch(pid: u64, cr3: u64, nr: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    if cr3 == 0 { fail("zero_cr3") }
    let state = checked(pid);
    match nr {
        SYS_OPEN_RO if a2 == 0 => {
            if !state.grants.allows(pid, Permission::FileRead) {
                user_file_io::EACCES as u64
            } else {
                user_file_io::open_read_only(
                    &mut state.fs, pid, cr3, a0, a1, private_pte, private_byte
                )
            }
        },
        SYS_READ => {
            if !state.grants.allows(pid, Permission::FileRead) {
                user_file_io::EACCES as u64
            } else {
                user_file_io::read_into_user(
                    &mut state.fs, pid, a0, cr3, a1, a2,
                    private_pte, private_rw_byte
                )
            }
        },
        // CLOSE is always permitted so an app can release its own handle
        // after READ permission has been revoked.
        SYS_CLOSE if a1 == 0 && a2 == 0 =>
            user_file_io::close_handle(&mut state.fs, pid, a0),
        _ => user_file_io::EINVAL as u64,
    }
}

pub fn verify_exit(pid: u64) {
    let state = checked(pid);
    if state.fs.open_count() != 0
        || state.fs.close_all(pid) != Ok(0)
        || state.fs.immutable(PATH).ok() != Some(CONTENT.as_slice())
        || !state.grants.allows(pid, Permission::FileRead)
        || state.grants.retire(pid).is_err()
        || state.grants.allows(pid, Permission::FileRead)
        || state.grants.live() != 0
        || state.grants.grant(pid, Permission::FileRead)
            != Err(PermissionError::NotRegistered)
    { fail("descriptor_leak_or_permission_retirement") }
    serial::write_line("WOLFOS_SHIELD_RETIRED_OK pid=1 grants=0 stale_denied=1");
    serial::write_line("WOLFOS_FILE_IO_FDS_OK open=0 stale_denied=1 pid_cleanup=1");
}
