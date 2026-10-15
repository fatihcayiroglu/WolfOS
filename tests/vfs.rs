//! Compile and execute the actual no_std RamFS and VFS modules together.
//! The same sources are compiled into the WolfOS kernel in isolated QEMU.
#[path = "../kernel/src/ramfs.rs"]
mod ramfs;
#[path = "../kernel/src/vfs.rs"]
mod vfs;

#[test]
fn vfs_and_ramfs_kernel_interfaces_match() {
    let mut fs = vfs::Vfs::<2, 4096, 2>::new();
    let file = fs.create("/etc/wolfos.conf").unwrap();
    let wr = fs.open("/etc/wolfos.conf", vfs::Access::Write).unwrap();
    fs.write(wr, b"experience=comfortable\n").unwrap();
    fs.close(wr).unwrap();
    fs.seal(file).unwrap();
    let rd = fs.open("/etc/wolfos.conf", vfs::Access::Read).unwrap();
    assert_eq!(fs.executable_bytes(rd).unwrap(), b"experience=comfortable\n");
}
