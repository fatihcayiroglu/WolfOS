//! Original bounded WolfOS in-memory FS: no_std, no heap, no disk.
//! Fixed slots with generation-checked handles and strict absolute paths.
//! Writes are atomic (all or nothing), seals make files read-only,
//! unlink zeroes contents, and stale handles cannot address reused slots.
//! NOT a VFS, directory manager, access-control or persistent filesystem.

pub const MAX_NAME: usize = 63;
pub const MAX_FILE_BYTES: usize = 32 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    InvalidPath, NameTooLong, Duplicate, Full, NotFound, StaleHandle,
    InvalidOffset, NoSpace, Sealed, ExhaustedGeneration,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId { pub slot: usize, pub generation: u64 }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileInfo { pub size: usize, pub sealed: bool }

struct Node<const CAP: usize> {
    used: bool,
    sealed: bool,
    name_len: usize,
    name: [u8; MAX_NAME],
    size: usize,
    generation: u64,
    bytes: [u8; CAP],
}
impl<const CAP: usize> Node<CAP> {
    const fn empty() -> Self {
        Self { used: false, sealed: false, name_len: 0,
            name: [0; MAX_NAME], size: 0, generation: 0,
            bytes: [0; CAP] }
    }
}
pub struct RamFs<const N: usize, const CAP: usize> {
    slots: [Node<CAP>; N],
}
impl<const N: usize, const CAP: usize> RamFs<N, CAP> {
    pub const fn new() -> Self {
        Self { slots: [const { Node::empty() }; N] }
    }
    pub fn files(&self) -> usize {
        self.slots.iter().filter(|node| node.used).count()
    }
    fn path(name: &str) -> Result<&[u8], FsError> {
        let bytes = name.as_bytes();
        if bytes.len() > MAX_NAME { return Err(FsError::NameTooLong) }
        if bytes.len() < 2 || bytes[0] != b'/'
            || bytes[1] == b'/' || bytes.last() == Some(&b'/')
            || bytes.iter().any(|b| *b <= 32 || *b >= 127 || *b == b'\\')
        { return Err(FsError::InvalidPath) }
        if bytes[1..].split(|b| *b == b'/').any(|part| {
            part.is_empty() || part == b"." || part == b".."
        }) { return Err(FsError::InvalidPath) }
        Ok(bytes)
    }
    pub fn create(&mut self, name: &str) -> Result<FileId, FsError> {
        let bytes = Self::path(name)?;
        if self.slots.iter().any(|node| node.used && node.name_len == bytes.len()
            && &node.name[..node.name_len] == bytes
        ) { return Err(FsError::Duplicate) }
        let (slot, node) = self.slots.iter_mut().enumerate()
            .find(|(_, node)| !node.used).ok_or(FsError::Full)?;
        let generation = node.generation.checked_add(1)
            .ok_or(FsError::ExhaustedGeneration)?;
        node.bytes.fill(0);
        node.name.fill(0);
        node.name[..bytes.len()].copy_from_slice(bytes);
        node.name_len = bytes.len();
        node.size = 0;
        node.used = true;
        node.sealed = false;
        node.generation = generation;
        Ok(FileId { slot, generation })
    }
    pub fn open(&self, name: &str) -> Result<FileId, FsError> {
        let bytes = Self::path(name)?;
        self.slots.iter().enumerate().find(|(_, node)| node.used
            && node.name_len == bytes.len()
            && &node.name[..node.name_len] == bytes)
            .map(|(slot, node)| FileId { slot, generation: node.generation })
            .ok_or(FsError::NotFound)
    }
    fn get(&self, id: FileId) -> Result<&Node<CAP>, FsError> {
        let node = self.slots.get(id.slot).ok_or(FsError::StaleHandle)?;
        if !node.used || node.generation != id.generation || id.generation == 0 {
            return Err(FsError::StaleHandle)
        }
        Ok(node)
    }
    fn get_mut(&mut self, id: FileId) -> Result<&mut Node<CAP>, FsError> {
        let node = self.slots.get_mut(id.slot).ok_or(FsError::StaleHandle)?;
        if !node.used || node.generation != id.generation || id.generation == 0 {
            return Err(FsError::StaleHandle)
        }
        Ok(node)
    }
    pub fn info(&self, id: FileId) -> Result<FileInfo, FsError> {
        let node = self.get(id)?;
        Ok(FileInfo { size: node.size, sealed: node.sealed })
    }
    pub fn write(&mut self, id: FileId, offset: usize, input: &[u8])
        -> Result<usize, FsError>
    {
        let node = self.get_mut(id)?;
        if node.sealed { return Err(FsError::Sealed) }
        let end = offset.checked_add(input.len()).ok_or(FsError::InvalidOffset)?;
        if end > CAP { return Err(FsError::NoSpace) }
        if offset > node.size { node.bytes[node.size..offset].fill(0); }
        node.bytes[offset..end].copy_from_slice(input);
        node.size = node.size.max(end);
        Ok(input.len())
    }
    pub fn read(&self, id: FileId, offset: usize, output: &mut [u8])
        -> Result<usize, FsError>
    {
        let node = self.get(id)?;
        if offset > node.size { return Err(FsError::InvalidOffset) }
        let count = output.len().min(node.size - offset);
        output[..count].copy_from_slice(&node.bytes[offset..offset+count]);
        Ok(count)
    }
    /// Safe shared borrow disallows concurrent mutation through Rust references.
    pub fn contents(&self, id: FileId) -> Result<&[u8], FsError> {
        let node = self.get(id)?;
        Ok(&node.bytes[..node.size])
    }
    pub fn seal(&mut self, id: FileId) -> Result<(), FsError> {
        self.get_mut(id)?.sealed = true;
        Ok(())
    }
    pub fn unlink(&mut self, id: FileId) -> Result<(), FsError> {
        let node = self.get_mut(id)?;
        node.bytes.fill(0);
        node.name.fill(0);
        node.size = 0;
        node.name_len = 0;
        node.sealed = false;
        node.used = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fs() -> RamFs<3, 128> { RamFs::new() }
    #[test]
    fn create_open_read_write_eof() {
        let mut fs = fs();
        let id = fs.create("/bin/hello.elf").unwrap();
        assert_eq!(fs.open("/bin/hello.elf"), Ok(id));
        assert_eq!(fs.write(id, 0, b"ELF"), Ok(3));
        let mut out = [0xaau8; 8];
        assert_eq!(fs.read(id, 0, &mut out), Ok(3));
        assert_eq!(&out[..3], b"ELF");
        assert_eq!(&out[3..], &[0xaa;5]);
        assert_eq!(fs.read(id, 3, &mut out), Ok(0));
        assert_eq!(fs.read(id, 4, &mut out), Err(FsError::InvalidOffset));
        assert_eq!(fs.info(id), Ok(FileInfo { size: 3, sealed: false }));
    }
    #[test]
    fn sparse_write_failure_is_atomic() {
        let mut fs = fs();
        let id = fs.create("/notes").unwrap();
        assert_eq!(fs.write(id, 10, b"OK"), Ok(2));
        let mut out = [0xff; 12];
        assert_eq!(fs.read(id, 0, &mut out), Ok(12));
        assert_eq!(&out[..10], &[0;10]);
        assert_eq!(&out[10..], b"OK");
        let orig = fs.contents(id).unwrap().to_vec();
        assert_eq!(fs.write(id, 127, b"two"), Err(FsError::NoSpace));
        assert_eq!(fs.write(id, usize::MAX, b"bad"), Err(FsError::InvalidOffset));
        assert_eq!(fs.contents(id).unwrap(), orig);
    }
    #[test]
    fn seal_delete_and_stale_generation() {
        let mut fs = fs();
        let id = fs.create("/a").unwrap();
        fs.write(id, 0, b"protected").unwrap();
        fs.seal(id).unwrap();
        assert_eq!(fs.write(id, 0, b"bad"), Err(FsError::Sealed));
        fs.unlink(id).unwrap();
        assert_eq!(fs.info(id), Err(FsError::StaleHandle));
        let next = fs.create("/b").unwrap();
        assert_eq!(id.slot, next.slot);
        assert!(next.generation > id.generation);
        assert_eq!(fs.read(id, 0, &mut [0u8; 2]), Err(FsError::StaleHandle));
        assert_eq!(fs.contents(next).unwrap(), b"");
    }
    #[test]
    fn strict_paths_duplicate_full_and_forged_handles() {
        let mut fs = fs();
        for bad in ["", "/", "hello", "/.", "/..", "/tmp/../x",
            "/x/./y", "//a", "/a//b", "/a/", "/a\n", "/a\\b",
            "/ü", "/x\u{0}", "/a b"
        ] {
            assert_eq!(fs.create(bad), Err(FsError::InvalidPath), "{bad:?}");
        }
        assert_eq!(fs.create(&format!("/{}", "a".repeat(70))),
            Err(FsError::NameTooLong));
        let a = fs.create("/a").unwrap();
        assert_eq!(fs.create("/a"), Err(FsError::Duplicate));
        fs.create("/b").unwrap();
        fs.create("/c").unwrap();
        assert_eq!(fs.create("/d"), Err(FsError::Full));
        assert_eq!(fs.open("/missing"), Err(FsError::NotFound));
        assert_eq!(fs.files(), 3);
        assert_eq!(fs.info(FileId {slot:usize::MAX,generation:1}),
            Err(FsError::StaleHandle));
        assert_eq!(fs.info(FileId {slot:a.slot,generation:99}),
            Err(FsError::StaleHandle));
    }
}
