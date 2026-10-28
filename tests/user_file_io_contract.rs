//! Host integration proof of real four-level page-table user copy + PID VFS.
//! Keep these tests inside 'make test' before enabling a new CPL3 QEMU gate.
#[path = "../kernel/src/user_copy.rs"]
mod user_copy;
#[path = "../kernel/src/vfs.rs"]
mod vfs;
#[path = "../kernel/src/user_file_io.rs"]
mod user_file_io;

use user_file_io::*;
use vfs::{Mode, Vfs};

const ROOT: u64 = 0x1000;
const PATH_VA: u64 = 0x403000;
const OUT_VA: u64 = 0x403100;
const NAME: &[u8] = b"/tmp/msg.txt";

#[derive(Clone)]
struct Guest {
    tables: [[u64; 512]; 4],
    data: [u8; 4096],
}
impl Guest {
    fn new() -> Self {
        let mut tables = [[0u64; 512]; 4];
        tables[0][0] = 0x2000 | 7;
        tables[1][0] = 0x3000 | 7;
        tables[2][2] = 0x4000 | 7;
        tables[3][1] = 0x5000 | 5; // RX user text, NOT writable
        tables[3][3] = 0x6000 | 7; // RW user data, PMM-owned
        let mut data = [0u8; 4096];
        data[..NAME.len()].copy_from_slice(NAME);
        Self { tables, data }
    }
}
fn pte(tables: &[[u64; 512]; 4], addr: u64) -> Option<u64> {
    let i = usize::try_from(addr.checked_sub(0x1000)? / 4096).ok()?;
    let slot = ((addr & 4095) / 8) as usize;
    tables.get(i)?.get(slot).copied()
}
fn read_owned(data: &[u8; 4096], phys: u64) -> Option<u8> {
    let offset = usize::try_from(phys.checked_sub(0x6000)?).ok()?;
    data.get(offset).copied()
}
fn access_owned(data: &mut [u8; 4096], phys: u64, write: Option<u8>) -> Option<u8> {
    let offset = usize::try_from(phys.checked_sub(0x6000)?).ok()?;
    let cell = data.get_mut(offset)?;
    if let Some(value) = write { *cell = value; }
    Some(*cell)
}
fn fixture() -> (Vfs<3, 128>, Guest) {
    let mut fs = Vfs::new();
    fs.create("/tmp/msg.txt", b"FILE_OK\n", false).unwrap();
    fs.create("/bin/locked", b"ELF", true).unwrap();
    (fs, Guest::new())
}
fn open(fs: &mut Vfs<3, 128>, guest: &Guest, pid: u64) -> u64 {
    let tables = guest.tables;
    open_read_only(fs, pid, ROOT, PATH_VA, NAME.len() as u64, "/tmp/msg.txt",
        |a| pte(&tables, a), |a| read_owned(&guest.data, a))
}
fn read(fs: &mut Vfs<3, 128>, guest: &mut Guest, pid: u64,
        fd: u64, addr: u64, count: u64) -> u64 {
    let tables = guest.tables;
    read_into_user(fs, pid, fd, ROOT, addr, count,
        |a| pte(&tables, a), |a, b| access_owned(&mut guest.data, a, b))
}

#[test]
fn syscall_numbers_preserve_the_existing_user_pointer_write_five() {
    assert_eq!((SYS_OPEN_RO, SYS_READ, SYS_CLOSE), (6,7,8));
    assert_ne!(SYS_OPEN_RO, 5);
    assert_eq!((MAX_PATH_BYTES, user_copy::MAX_COPY), (63,256));
}
#[test]
fn actual_walked_path_open_read_eof_and_close() {
    let (mut fs, mut guest) = fixture();
    let fd = open(&mut fs, &guest, 7);
    assert_eq!(fd, 256);
    assert_eq!(read(&mut fs, &mut guest, 7, fd, OUT_VA, 4), 4);
    assert_eq!(&guest.data[256..260], b"FILE");
    assert_eq!(read(&mut fs, &mut guest, 7, fd, OUT_VA+4, 64), 4);
    assert_eq!(&guest.data[256..264], b"FILE_OK\n");
    assert_eq!(read(&mut fs, &mut guest, 7, fd, OUT_VA, 5), 0);
    assert_eq!(close_handle(&mut fs, 7, fd), 0);
    assert_eq!(close_handle(&mut fs, 7, fd), EBADF as u64);
    assert_eq!(read(&mut fs, &mut guest, 7, fd, OUT_VA, 2), EBADF as u64);
}
#[test]
fn supervisor_and_rx_target_refusals_restore_cursor() {
    let (mut fs, mut guest) = fixture();
    let fd = open(&mut fs, &guest, 1);
    for addr in [0, 0xffff_8000_0000_0000, 0x401000, 0x7fff_ffff_ffff] {
        assert_eq!(read(&mut fs, &mut guest, 1, fd, addr, 4), EFAULT as u64);
    }
    assert_eq!(read(&mut fs, &mut guest, 1, fd, OUT_VA, 8), 8);
    assert_eq!(&guest.data[256..264], b"FILE_OK\n");
    assert_eq!(read(&mut fs, &mut guest, 1, fd, OUT_VA, 257), EINVAL as u64);
}
#[test]
fn forged_cross_pid_stale_and_invalid_handles_are_rejected() {
    let (mut fs, mut guest) = fixture();
    let a = open(&mut fs, &guest, 11);
    assert_eq!(read(&mut fs, &mut guest, 12, a, OUT_VA, 3), EACCES as u64);
    assert_eq!(close_handle(&mut fs, 12, a), EACCES as u64);
    for handle in [0, 1, u64::MAX] {
        assert_eq!(close_handle(&mut fs, 11, handle), EBADF as u64);
    }
    assert_eq!(close_handle(&mut fs, 11, a), 0);
    let b = open(&mut fs, &guest, 11);
    assert_ne!(a,b);
    assert_eq!(read(&mut fs, &mut guest, 11, a, OUT_VA, 2), EBADF as u64);
    assert_eq!(read(&mut fs, &mut guest, 11, b, OUT_VA, 2), 2);
    assert_eq!(fs.close_all(11), Ok(1));
    assert_eq!(close_handle(&mut fs, 11, b), EBADF as u64);
}
#[test]
fn path_fault_or_traversal_never_opens_descriptor() {
    let (mut fs, mut guest) = fixture();
    let tables = guest.tables;
    assert_eq!(open_read_only(&mut fs, 1, ROOT, 0, NAME.len() as u64, "/tmp/msg.txt",
        |a|pte(&tables,a),|a|read_owned(&guest.data,a)), EFAULT as u64);
    assert_eq!(open_read_only(&mut fs, 1, ROOT, 0x403fff, NAME.len() as u64, "/tmp/msg.txt",
        |a|pte(&tables,a),|a|read_owned(&guest.data,a)), EFAULT as u64);
    assert_eq!(open_read_only(&mut fs, 1, ROOT, PATH_VA, 64, "/tmp/msg.txt",
        |a|pte(&tables,a),|a|read_owned(&guest.data,a)), EINVAL as u64);
    guest.data[..10].copy_from_slice(b"/tmp/../xx");
    assert_ne!(open(&mut fs, &guest, 1), 256);
    assert_eq!(fs.open_count(), 0);
}
#[test]
fn Vfs_is_not_exposed_as_readwrite_to_user_processes() {
    let (mut fs, guest) = fixture();
    let fd = open(&mut fs, &guest, 2);
    assert!(fd > 0);
    let writer = fs.open(3, "/tmp/msg.txt", Mode::ReadWrite).unwrap();
    assert_eq!(fs.write(2, writer, b"NO"), Err(vfs::VfsError::PermissionDenied));
    assert_eq!(fs.close_all(2), Ok(1));
    assert_eq!(fs.close_all(3), Ok(1));
}
#[test]
fn scoped_open_rejects_real_other_file_before_fd_allocation() {
    let (mut fs, mut guest) = fixture();
    fs.create("/tmp/private.txt", b"NOPE", true).unwrap();
    guest.data[..16].copy_from_slice(b"/tmp/private.txt");
    let tables = guest.tables;
    assert_eq!(open_read_only(&mut fs, 7, ROOT, PATH_VA, 16,
        "/tmp/msg.txt", |a| pte(&tables, a), |a| read_owned(&guest.data, a)),
        EACCES as u64);
    assert_eq!(fs.open_count(), 0);
    guest.data[..NAME.len()].copy_from_slice(NAME);
    let fd = open(&mut fs, &guest, 7);
    assert_eq!(read_target_path(&fs, 7, fd), Ok("/tmp/msg.txt"));
    assert_eq!(read_target_path(&fs, 8, fd), Err(EACCES as u64));
    assert_eq!(read_target_path(&fs, 7, 0), Err(EBADF as u64));
    assert_eq!(fs.close_all(7), Ok(1));
    assert_eq!(read_target_path(&fs, 7, fd), Err(EBADF as u64));
}

