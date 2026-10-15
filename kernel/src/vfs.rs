//! WolfOS VFS foundation: capability-like per-open descriptors over RamFS.
//!
//! One mounted backend only (the original bounded RAMFS). Each open returns
//! a generation-tagged descriptor, with independent cursor, read/write mode,
//! EOF semantics and explicit CLOSE. Rejects stale/forged descriptors, sealed
//! writes, conflicting writers, unlink of open files and file-size overflow.
//! An immutable, sealed, read-only descriptor may expose executable image
//! bytes to the strict ELF loader without bypassing descriptor validation.
//!
//! This is a kernel-internal, no_std, no-heap building block. No user-supplied
//! pointers, user-visible OPEN/READ/WRITE syscalls, mounts, permissions,
//! concurrent process handle tables, persistent storage or POSIX semantics.

use crate::ramfs::{FileId, FileInfo, FsError, RamFs};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access { Read, Write }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Descriptor { pub slot: usize, pub generation: u64 }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VfsError {
    Fs(FsError), DescriptorInvalid, DescriptorsFull, GenerationExhausted,
    AccessDenied, FileBusy, NotSealed, InvalidSeek,
}
impl From<FsError> for VfsError {
    fn from(e: FsError) -> Self { Self::Fs(e) }
}
#[derive(Clone, Copy)]
struct OpenFile {
    active: bool,
    generation: u64,
    file: FileId,
    mode: Access,
    cursor: usize,
}
impl OpenFile {
    const fn empty() -> Self {
        Self { active: false, generation: 0,
            file: FileId { slot: 0, generation: 0 },
            mode: Access::Read, cursor: 0 }
    }
}

pub struct Vfs<const FILES: usize, const CAP: usize, const OPEN: usize> {
    files: RamFs<FILES, CAP>,
    descriptors: [OpenFile; OPEN],
}
impl<const FILES: usize, const CAP: usize, const OPEN: usize>
    Vfs<FILES, CAP, OPEN>
{
    pub const fn new() -> Self {
        Self {
            files: RamFs::new(),
            descriptors: [const { OpenFile::empty() }; OPEN],
        }
    }

    pub fn create(&mut self, path: &str) -> Result<FileId, VfsError> {
        Ok(self.files.create(path)?)
    }
    pub fn count_files(&self) -> usize { self.files.files() }
    pub fn count_open(&self) -> usize {
        self.descriptors.iter().filter(|entry| entry.active).count()
    }

    pub fn open(&mut self, path: &str, mode: Access)
        -> Result<Descriptor, VfsError>
    {
        let file = self.files.open(path)?;
        let metadata = self.files.info(file)?;
        if mode == Access::Write && metadata.sealed {
            return Err(VfsError::AccessDenied)
        }
        // A writer is exclusive, preventing writer/read-only image aliases.
        if self.descriptors.iter().any(|d| d.active && d.file == file
            && (mode == Access::Write || d.mode == Access::Write))
        { return Err(VfsError::FileBusy) }
        let (slot, item) = self.descriptors.iter_mut().enumerate()
            .find(|(_, d)| !d.active).ok_or(VfsError::DescriptorsFull)?;
        let generation = item.generation.checked_add(1)
            .ok_or(VfsError::GenerationExhausted)?;
        *item = OpenFile { active: true, generation,
            file, mode, cursor: 0 };
        Ok(Descriptor { slot, generation })
    }

    fn slot(&self, descriptor: Descriptor) -> Result<&OpenFile, VfsError> {
        let entry = self.descriptors.get(descriptor.slot)
            .ok_or(VfsError::DescriptorInvalid)?;
        if !entry.active || descriptor.generation == 0
            || entry.generation != descriptor.generation
        { return Err(VfsError::DescriptorInvalid) }
        Ok(entry)
    }
    fn slot_mut(&mut self, descriptor: Descriptor)
        -> Result<&mut OpenFile, VfsError>
    {
        let entry = self.descriptors.get_mut(descriptor.slot)
            .ok_or(VfsError::DescriptorInvalid)?;
        if !entry.active || descriptor.generation == 0
            || entry.generation != descriptor.generation
        { return Err(VfsError::DescriptorInvalid) }
        Ok(entry)
    }

    pub fn info(&self, descriptor: Descriptor) -> Result<FileInfo, VfsError> {
        let file = self.slot(descriptor)?.file;
        Ok(self.files.info(file)?)
    }
    pub fn tell(&self, descriptor: Descriptor) -> Result<usize, VfsError> {
        Ok(self.slot(descriptor)?.cursor)
    }
    pub fn seek(&mut self, descriptor: Descriptor, at: usize)
        -> Result<(), VfsError>
    {
        let current = *self.slot(descriptor)?;
        let bound = if current.mode == Access::Read {
            self.files.info(current.file)?.size
        } else { CAP };
        if at > bound { return Err(VfsError::InvalidSeek) }
        self.slot_mut(descriptor)?.cursor = at;
        Ok(())
    }
    pub fn read(&mut self, descriptor: Descriptor, output: &mut [u8])
        -> Result<usize, VfsError>
    {
        let current = *self.slot(descriptor)?;
        if current.mode != Access::Read { return Err(VfsError::AccessDenied) }
        let count = self.files.read(current.file, current.cursor, output)?;
        let end = current.cursor.checked_add(count)
            .ok_or(VfsError::InvalidSeek)?;
        self.slot_mut(descriptor)?.cursor = end;
        Ok(count)
    }
    pub fn write(&mut self, descriptor: Descriptor, input: &[u8])
        -> Result<usize, VfsError>
    {
        let current = *self.slot(descriptor)?;
        if current.mode != Access::Write { return Err(VfsError::AccessDenied) }
        let count = self.files.write(current.file, current.cursor, input)?;
        let end = current.cursor.checked_add(count)
            .ok_or(VfsError::InvalidSeek)?;
        self.slot_mut(descriptor)?.cursor = end;
        Ok(count)
    }
    pub fn close(&mut self, descriptor: Descriptor) -> Result<(), VfsError> {
        let item = self.slot_mut(descriptor)?;
        item.active = false;
        item.cursor = 0;
        Ok(())
    }
    pub fn seal(&mut self, file: FileId) -> Result<(), VfsError> {
        // Reject changing image mutability with any active writer.
        self.files.info(file)?;
        if self.descriptors.iter().any(|d| d.active && d.file == file
            && d.mode == Access::Write)
        { return Err(VfsError::FileBusy) }
        Ok(self.files.seal(file)?)
    }
    pub fn unlink(&mut self, path: &str) -> Result<(), VfsError> {
        let file = self.files.open(path)?;
        if self.descriptors.iter().any(|d| d.active && d.file == file) {
            return Err(VfsError::FileBusy)
        }
        Ok(self.files.unlink(file)?)
    }

    /// Require a READ descriptor referencing a SEALED immutable file.
    /// The borrow cannot coexist with any mutable VFS operation in safe
    /// Rust. The isolated QEMU adapter publishes the entire VFS read-only
    /// after ELF file staging and holds this descriptor for execution.
    pub fn executable_bytes(&self, descriptor: Descriptor)
        -> Result<&[u8], VfsError>
    {
        let current = self.slot(descriptor)?;
        if current.mode != Access::Read { return Err(VfsError::AccessDenied) }
        if !self.files.info(current.file)?.sealed {
            return Err(VfsError::NotSealed)
        }
        Ok(self.files.contents(current.file)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    type F = Vfs<3, 128, 3>;
    #[test]
    fn generation_checked_descriptors_are_isolated() {
        let mut v = F::new();
        v.create("/a").unwrap();
        let a = v.open("/a", Access::Write).unwrap();
        assert_eq!(v.write(a, b"abc"), Ok(3));
        assert_eq!(v.tell(a), Ok(3));
        assert_eq!(v.read(a, &mut [0u8; 1]), Err(VfsError::AccessDenied));
        assert_eq!(v.open("/a", Access::Read), Err(VfsError::FileBusy));
        assert_eq!(v.unlink("/a"), Err(VfsError::FileBusy));
        v.close(a).unwrap();
        assert_eq!(v.write(a, b"x"), Err(VfsError::DescriptorInvalid));
        let rd = v.open("/a", Access::Read).unwrap();
        assert_eq!(a.slot, rd.slot);
        assert!(rd.generation > a.generation);
        let mut out = [0xaau8; 5];
        assert_eq!(v.read(rd, &mut out), Ok(3));
        assert_eq!(&out[..3], b"abc");
        assert_eq!(v.read(rd, &mut out), Ok(0));
        v.seek(rd, 1).unwrap();
        assert_eq!(v.read(rd, &mut out), Ok(2));
        assert_eq!(&out[..2], b"bc");
        assert_eq!(v.tell(rd), Ok(3));
        assert_eq!(v.seek(rd, 4), Err(VfsError::InvalidSeek));
        assert_eq!(v.write(rd, b"x"), Err(VfsError::AccessDenied));
        assert_eq!(v.read(a, &mut out), Err(VfsError::DescriptorInvalid));
        assert_eq!(v.info(Descriptor { slot: 9999, generation: 1 }),
            Err(VfsError::DescriptorInvalid));
    }

    #[test]
    fn sealed_executable_never_mutable_and_cannot_unlink_if_open() {
        let mut v = F::new();
        let file = v.create("/bin/hello").unwrap();
        let wr = v.open("/bin/hello", Access::Write).unwrap();
        assert_eq!(v.seal(file), Err(VfsError::FileBusy));
        v.write(wr, b"\x7fELF").unwrap();
        v.close(wr).unwrap();
        let r1 = v.open("/bin/hello", Access::Read).unwrap();
        assert_eq!(v.executable_bytes(r1), Err(VfsError::NotSealed));
        v.seal(file).unwrap();
        assert_eq!(v.executable_bytes(r1).unwrap(), b"\x7fELF");
        assert_eq!(v.open("/bin/hello", Access::Write),
            Err(VfsError::AccessDenied));
        let r2 = v.open("/bin/hello", Access::Read).unwrap();
        assert_ne!(r1, r2);
        assert_eq!(v.unlink("/bin/hello"), Err(VfsError::FileBusy));
        v.close(r1).unwrap();
        v.close(r2).unwrap();
        v.unlink("/bin/hello").unwrap();
        assert_eq!(v.open("/bin/hello", Access::Read),
            Err(VfsError::Fs(FsError::NotFound)));
        let newer = v.create("/bin/hello").unwrap();
        assert!(newer.generation > file.generation);
        assert_eq!(v.seal(file), Err(VfsError::Fs(FsError::StaleHandle)));
    }

    #[test]
    fn quota_seek_and_failed_writes_never_advance_cursors() {
        let mut v = F::new();
        for path in ["/a", "/b", "/c"] { v.create(path).unwrap(); }
        let a = v.open("/a", Access::Write).unwrap();
        let b = v.open("/b", Access::Write).unwrap();
        let c = v.open("/c", Access::Write).unwrap();
        assert_eq!(v.open("/a", Access::Read), Err(VfsError::FileBusy));
        assert_eq!(v.open("/bad", Access::Read),
            Err(VfsError::Fs(FsError::NotFound)));
        assert_eq!(v.count_open(), 3);
        assert_eq!(v.open("/c", Access::Write), Err(VfsError::FileBusy));
        v.close(a).unwrap();
        let a = v.open("/a", Access::Read).unwrap();
        assert_eq!(v.open("/a", Access::Read),
            Err(VfsError::DescriptorsFull));
        v.close(a).unwrap();
        v.seek(b, 127).unwrap();
        assert_eq!(v.write(b, b"xx"),
            Err(VfsError::Fs(FsError::NoSpace)));
        assert_eq!(v.tell(b), Ok(127));
        assert_eq!(v.write(b, b"Z"), Ok(1));
        assert_eq!(v.info(b).unwrap().size, 128);
        assert_eq!(v.seek(c, 129), Err(VfsError::InvalidSeek));
        assert_eq!(v.tell(c), Ok(0));
        v.close(b).unwrap(); v.close(c).unwrap();
        assert_eq!(v.count_open(), 0);
    }
}
