//! WolfOS original VFS: two independent fixed RamFS mounts, PID-owned FDs.
//! Exact /tmp/ component matching; /tmpx belongs to root. Backend rejects
//! .. traversal, control bytes and aliases. No heap or filesystem syscall yet.
//! File descriptor generations reject reuse; PID ownership blocks cross-PID
//! read/write/close; each descriptor keeps an independent cursor.
//! File unlink blocked while open. Sealed files stay immutable.
//! No concurrency, on-disk persistence, generic mount graph or user pointers.
#[cfg(test)]
#[path = "ramfs.rs"]
mod standalone_ramfs;
#[cfg(test)]
use standalone_ramfs::{FileId, FsError, RamFs};
#[cfg(not(test))]
use crate::ramfs::{FileId, FsError, RamFs};

pub const MAX_OPEN: usize = 8;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VfsError {
    InvalidPid, InvalidPath, Full, StaleDescriptor, PermissionDenied,
    Busy, InvalidSeek, Backend(FsError), GenerationExhausted,
}
impl From<FsError> for VfsError {
    fn from(e: FsError) -> Self { Self::Backend(e) }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode { Read, ReadWrite }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Volume { Root, Temp }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descriptor { pub slot: usize, pub generation: u64 }
#[derive(Clone, Copy)]
struct OpenFile {
    used: bool,
    generation: u64,
    owner: u64,
    volume: Volume,
    file: FileId,
    cursor: usize,
    mode: Mode,
}
impl OpenFile {
    const fn empty() -> Self {
        Self { used: false, generation: 0, owner: 0, volume: Volume::Root,
            file: FileId { slot: 0, generation: 0 }, cursor: 0, mode: Mode::Read }
    }
}

pub struct Vfs<const FILES: usize, const CAP: usize> {
    root: RamFs<FILES, CAP>,
    temp: RamFs<FILES, CAP>,
    descriptors: [OpenFile; MAX_OPEN],
}
impl<const FILES: usize, const CAP: usize> Vfs<FILES, CAP> {
    pub const fn new() -> Self {
        Self { root: RamFs::new(), temp: RamFs::new(),
            descriptors: [const { OpenFile::empty() }; MAX_OPEN] }
    }
    pub fn open_count(&self) -> usize {
        self.descriptors.iter().filter(|fd| fd.used).count()
    }
    pub fn volume_counts(&self) -> (usize, usize) {
        (self.root.files(), self.temp.files())
    }
    fn volume(path: &str) -> Result<Volume, VfsError> {
        if !path.starts_with('/') || path == "/tmp" || path == "/tmp/" {
            return Err(VfsError::InvalidPath)
        }
        if path.starts_with("/tmp/") { Ok(Volume::Temp) }
        else { Ok(Volume::Root) }
    }
    fn backend(&self, vol: Volume) -> &RamFs<FILES, CAP> {
        match vol { Volume::Root => &self.root, Volume::Temp => &self.temp }
    }
    fn backend_mut(&mut self, vol: Volume) -> &mut RamFs<FILES, CAP> {
        match vol { Volume::Root => &mut self.root, Volume::Temp => &mut self.temp }
    }
    /// Atomic create: a failed file write rolls back the new node.
    pub fn create(&mut self, path: &str, data: &[u8], sealed: bool)
        -> Result<(), VfsError>
    {
        let vol = Self::volume(path)?;
        let fs = self.backend_mut(vol);
        let id = fs.create(path)?;
        if let Err(err) = fs.write(id, 0, data) {
            fs.unlink(id)?;
            return Err(err.into())
        }
        if sealed { fs.seal(id)?; }
        Ok(())
    }
    pub fn immutable(&self, path: &str) -> Result<&[u8], VfsError> {
        let fs = self.backend(Self::volume(path)?);
        let id = fs.open(path)?;
        if !fs.info(id)?.sealed { return Err(VfsError::PermissionDenied) }
        Ok(fs.contents(id)?)
    }
    pub fn open(&mut self, pid: u64, path: &str, mode: Mode)
        -> Result<Descriptor, VfsError>
    {
        if pid == 0 { return Err(VfsError::InvalidPid) }
        let vol = Self::volume(path)?;
        let fs = self.backend(vol);
        let id = fs.open(path)?;
        if mode == Mode::ReadWrite && fs.info(id)?.sealed {
            return Err(VfsError::PermissionDenied)
        }
        let slot = self.descriptors.iter().position(|fd| !fd.used)
            .ok_or(VfsError::Full)?;
        let fd = &mut self.descriptors[slot];
        let generation = fd.generation.checked_add(1)
            .ok_or(VfsError::GenerationExhausted)?;
        *fd = OpenFile { used: true, generation, owner: pid, volume: vol,
            file: id, cursor: 0, mode };
        Ok(Descriptor { slot, generation })
    }
    fn fd(&self, pid: u64, token: Descriptor) -> Result<&OpenFile, VfsError> {
        if pid == 0 { return Err(VfsError::InvalidPid) }
        let fd = self.descriptors.get(token.slot)
            .ok_or(VfsError::StaleDescriptor)?;
        if !fd.used || token.generation == 0
            || fd.generation != token.generation
        { return Err(VfsError::StaleDescriptor) }
        if fd.owner != pid { return Err(VfsError::PermissionDenied) }
        Ok(fd)
    }
    pub fn close(&mut self, pid: u64, token: Descriptor)
        -> Result<(), VfsError>
    {
        self.fd(pid, token)?;
        let fd = &mut self.descriptors[token.slot];
        fd.used = false;
        fd.owner = 0;
        fd.cursor = 0;
        Ok(())
    }
    pub fn tell(&self, pid: u64, token: Descriptor) -> Result<usize, VfsError> {
        Ok(self.fd(pid,token)?.cursor)
    }
    pub fn seek(&mut self, pid: u64, token: Descriptor, offset: usize)
        -> Result<(), VfsError>
    {
        let fd = *self.fd(pid,token)?;
        if offset > self.backend(fd.volume).info(fd.file)?.size {
            return Err(VfsError::InvalidSeek)
        }
        self.descriptors[token.slot].cursor = offset;
        Ok(())
    }
    pub fn read(&mut self, pid: u64, token: Descriptor, dst: &mut [u8])
        -> Result<usize, VfsError>
    {
        let fd = *self.fd(pid,token)?;
        let n = self.backend(fd.volume).read(fd.file, fd.cursor, dst)?;
        self.descriptors[token.slot].cursor =
            fd.cursor.checked_add(n).ok_or(VfsError::InvalidSeek)?;
        Ok(n)
    }
    pub fn write(&mut self, pid: u64, token: Descriptor, src: &[u8])
        -> Result<usize, VfsError>
    {
        let fd = *self.fd(pid,token)?;
        if fd.mode != Mode::ReadWrite { return Err(VfsError::PermissionDenied) }
        let n = self.backend_mut(fd.volume).write(fd.file, fd.cursor, src)?;
        self.descriptors[token.slot].cursor =
            fd.cursor.checked_add(n).ok_or(VfsError::InvalidSeek)?;
        Ok(n)
    }
    pub fn unlink(&mut self, path: &str) -> Result<(), VfsError> {
        let vol = Self::volume(path)?;
        let id = self.backend(vol).open(path)?;
        if self.descriptors.iter().any(|fd|
            fd.used && fd.volume == vol && fd.file == id
        ) { return Err(VfsError::Busy) }
        self.backend_mut(vol).unlink(id)?;
        Ok(())
    }
    /// Closing all descriptors on PID exit prevents handle leaks and
    /// cross-process use when PID generations increase.
    pub fn close_all(&mut self, pid: u64) -> Result<usize, VfsError> {
        if pid == 0 { return Err(VfsError::InvalidPid) }
        let mut count = 0;
        for fd in &mut self.descriptors {
            if fd.used && fd.owner == pid {
                fd.used = false;
                fd.owner = 0;
                fd.cursor = 0;
                count += 1;
            }
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fs() -> Vfs<3,96> { Vfs::new() }
    #[test]
    fn mount_boundaries_and_isolated_namespaces() {
        let mut fs = fs();
        fs.create("/tmp/a",b"TEMP",false).unwrap();
        fs.create("/tmpx/a",b"ROOT",false).unwrap();
        assert_eq!(fs.volume_counts(),(1,1));
        let a = fs.open(1,"/tmp/a",Mode::Read).unwrap();
        let b = fs.open(1,"/tmpx/a",Mode::Read).unwrap();
        let mut out = [0;4];
        assert_eq!(fs.read(1,a,&mut out),Ok(4));
        assert_eq!(&out,b"TEMP");
        assert_eq!(fs.read(1,b,&mut out),Ok(4));
        assert_eq!(&out,b"ROOT");
        assert_eq!(fs.open(1,"/tmp",Mode::Read),Err(VfsError::InvalidPath));
        assert_eq!(fs.open(1,"/tmp/a/../b",Mode::Read),
            Err(VfsError::Backend(FsError::InvalidPath)));
    }
    #[test]
    fn pid_owner_cursor_generation_and_mode() {
        let mut fs = fs();
        fs.create("/notes",b"abcdef",false).unwrap();
        let a = fs.open(11,"/notes",Mode::ReadWrite).unwrap();
        let b = fs.open(11,"/notes",Mode::Read).unwrap();
        let mut two = [0;2];
        assert_eq!(fs.read(11,a,&mut two),Ok(2));
        assert_eq!(&two,b"ab");
        assert_eq!(fs.tell(11,a),Ok(2));
        assert_eq!(fs.tell(11,b),Ok(0));
        assert_eq!(fs.read(12,a,&mut two),Err(VfsError::PermissionDenied));
        assert_eq!(fs.close(12,a),Err(VfsError::PermissionDenied));
        assert_eq!(fs.write(11,b,b"x"),Err(VfsError::PermissionDenied));
        assert_eq!(fs.seek(11,a,7),Err(VfsError::InvalidSeek));
        fs.seek(11,a,2).unwrap();
        fs.write(11,a,b"QQ").unwrap();
        assert_eq!(fs.tell(11,a),Ok(4));
        fs.close(11,a).unwrap();
        let c = fs.open(11,"/notes",Mode::Read).unwrap();
        assert_eq!(c.slot,a.slot);
        assert_ne!(c.generation,a.generation);
        assert_eq!(fs.read(11,a,&mut two),Err(VfsError::StaleDescriptor));
    }
    #[test]
    fn sealed_elf_busy_and_stale_fd() {
        let mut fs = fs();
        fs.create("/bin/hello.elf",b"\x7fELF",true).unwrap();
        assert_eq!(fs.immutable("/bin/hello.elf"),Ok(&b"\x7fELF"[..]));
        assert_eq!(fs.open(1,"/bin/hello.elf",Mode::ReadWrite),
            Err(VfsError::PermissionDenied));
        let fd = fs.open(1,"/bin/hello.elf",Mode::Read).unwrap();
        assert_eq!(fs.unlink("/bin/hello.elf"),Err(VfsError::Busy));
        fs.close(1,fd).unwrap();
        fs.unlink("/bin/hello.elf").unwrap();
        fs.create("/bin/hello.elf",b"NEW",true).unwrap();
        assert_eq!(fs.read(1,fd,&mut [0;1]),Err(VfsError::StaleDescriptor));
        assert_eq!(fs.immutable("/bin/hello.elf"),Ok(&b"NEW"[..]));
    }
    #[test]
    fn failed_create_is_rolled_back_and_owner_cleanup_isolation() {
        let mut fs = fs();
        assert_eq!(fs.create("/too_big",&[1;97],false),
            Err(VfsError::Backend(FsError::NoSpace)));
        assert_eq!(fs.volume_counts(),(0,0));
        assert_eq!(fs.create("/tmp/../bad",b"x",false),
            Err(VfsError::Backend(FsError::InvalidPath)));
        fs.create("/ok",b"safe",true).unwrap();
        assert_eq!(fs.immutable("/ok"),Ok(&b"safe"[..]));
        let a = fs.open(1,"/ok",Mode::Read).unwrap();
        let b = fs.open(2,"/ok",Mode::Read).unwrap();
        assert_eq!(fs.close_all(1),Ok(1));
        assert_eq!(fs.close_all(1),Ok(0));
        assert_eq!(fs.tell(1,a),Err(VfsError::StaleDescriptor));
        assert_eq!(fs.tell(2,b),Ok(0));
        assert_eq!(fs.open_count(),1);
        assert_eq!(fs.close_all(0),Err(VfsError::InvalidPid));
    }
}
