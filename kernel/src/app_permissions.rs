//! WolfOS Shield foundation: bounded, default-deny, PID-generation-scoped
//! application permissions. No heap, filesystem or user pointer access.
//!
//! This is only a *policy ledger*. Trusted kernel code authenticates a
//! process and makes grant/revoke decisions; user syscalls cannot invoke
//! grant/revoke. Hardware enforcement is integrated first for file READ.
//! Network/microphone/camera enumerants are reserved policy domains, not
//! working device drivers, prompts, or production sandboxes.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    FileRead,
    Network,
    Microphone,
    Camera,
}
impl Permission {
    const fn bit(self) -> u8 {
        match self {
            Self::FileRead => 1,
            Self::Network => 2,
            Self::Microphone => 4,
            Self::Camera => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PermissionError {
    InvalidPid,
    StalePid,
    Full,
    NotRegistered,
    InvalidPath,
    PathRequired,
    UnverifiedImage,
    ImageMismatch,
    ImageTooLarge,
    AlreadyVerified,
}

#[derive(Clone, Copy)]
struct Entry {
    pid: u64,
    grants: u8,
    file_path: Option<&'static str>,
    approved_image: Option<&'static [u8]>,
}
impl Entry {
    const fn empty() -> Self { Self { pid: 0, grants: 0, file_path: None, approved_image: None } }
}

pub struct AppPermissions<const SLOTS: usize> {
    entries: [Entry; SLOTS],
    last_pid: u64,
}
impl<const SLOTS: usize> AppPermissions<SLOTS> {
    pub const fn new() -> Self {
        Self { entries: [const { Entry::empty() }; SLOTS], last_pid: 0 }
    }

    pub fn live(&self) -> usize {
        self.entries.iter().filter(|e| e.pid != 0).count()
    }

    /// A PID is minted elsewhere by ProcessTable; never accept recycled or
    /// zero generations. On failure neither slots nor watermark change.
    pub fn enroll(&mut self, pid: u64) -> Result<(), PermissionError> {
        if pid == 0 { return Err(PermissionError::InvalidPid) }
        if pid <= self.last_pid { return Err(PermissionError::StalePid) }
        let Some(index) = self.entries.iter().position(|e| e.pid == 0)
        else { return Err(PermissionError::Full) };
        self.entries[index] = Entry { pid, grants: 0, file_path: None, approved_image: None };
        self.last_pid = pid;
        Ok(())
    }

    /// Default deny: unknown, stale or unregistered PIDs have zero rights.
    pub fn allows(&self, pid: u64, permission: Permission) -> bool {
        pid != 0 && self.entries.iter()
            .find(|e| e.pid == pid)
            .is_some_and(|e| e.grants & permission.bit() != 0)
    }

    /// Bind the ProcessTable-minted PID to an *immutable kernel-approved*
    /// exact ELF image. The caller must supply the actual admitted ELF bytes
    /// and a separately controlled static allowlist image after verifying its
    /// owned CR3, process state and mapped bytes. This is a local built-in
    /// image allowlist, NOT a signature check for downloaded executables.
    pub fn bind_verified_image(&mut self, pid: u64, loaded: &[u8],
        approved: &'static [u8]) -> Result<(), PermissionError>
    {
        const MAX_APPROVED_IMAGE: usize = 32768;
        let entry = self.entry_mut(pid)?;
        if entry.approved_image.is_some() { return Err(PermissionError::AlreadyVerified) }
        if loaded.is_empty() || loaded.len() > MAX_APPROVED_IMAGE
            || approved.is_empty() || approved.len() > MAX_APPROVED_IMAGE
        { return Err(PermissionError::ImageTooLarge) }
        // Full byte equality, never merely filename, size, PID or a
        // collision-prone short hash. Failure never mutates the ledger.
        if loaded != approved { return Err(PermissionError::ImageMismatch) }
        entry.approved_image = Some(approved);
        Ok(())
    }

    pub fn image_verified(&self, pid: u64) -> bool {
        pid != 0 && self.entries.iter()
            .find(|entry| entry.pid == pid)
            .is_some_and(|entry| entry.approved_image.is_some())
    }

    /// Exact absolute path only: no aliases, traversal, NUL or ambiguous
    /// components. Deliberately matches the current bounded RamFS syntax.
    fn valid_scope(path: &str) -> bool {
        let bytes = path.as_bytes();
        bytes.len() >= 2 && bytes.len() <= 63 && bytes[0] == b'/'
            && bytes[1] != b'/' && bytes.last() != Some(&b'/')
            && bytes.iter().all(|b| (33..127).contains(b) && *b != b'\\')
            && bytes[1..].split(|b| *b == b'/').all(|part| {
                !part.is_empty() && part != b"." && part != b".."
            })
    }

    /// Single-path FILE_READ lease, issued only by a trusted kernel action.
    /// Re-scoping stops READ through old descriptors because the service
    /// rechecks the descriptor's canonical VFS pathname on each READ.
    pub fn grant_file_read_path(&mut self, pid: u64, path: &'static str)
        -> Result<(), PermissionError>
    {
        if !Self::valid_scope(path) { return Err(PermissionError::InvalidPath) }
        let entry = self.entry_mut(pid)?;
        if entry.approved_image.is_none() { return Err(PermissionError::UnverifiedImage) }
        entry.file_path = Some(path);
        entry.grants |= Permission::FileRead.bit();
        Ok(())
    }

    pub fn file_read_scope(&self, pid: u64) -> Option<&'static str> {
        if pid == 0 { return None }
        self.entries.iter().find(|entry| entry.pid == pid).and_then(|entry| {
            if entry.grants & Permission::FileRead.bit() != 0 {
                entry.file_path
            } else { None }
        })
    }

    pub fn allows_file_read_path(&self, pid: u64, path: &str) -> bool {
        self.file_read_scope(pid).is_some_and(|allowed| allowed == path)
    }

    fn entry_mut(&mut self, pid: u64) -> Result<&mut Entry, PermissionError> {
        if pid == 0 { return Err(PermissionError::InvalidPid) }
        self.entries.iter_mut().find(|e| e.pid == pid)
            .ok_or(PermissionError::NotRegistered)
    }

    /// ONLY an independently authenticated kernel policy decision may call
    /// grant, never a user-provided PID or capability mask.
    pub fn grant(&mut self, pid: u64, permission: Permission)
        -> Result<(), PermissionError>
    {
        if permission == Permission::FileRead {
            return Err(PermissionError::PathRequired)
        }
        let entry = self.entry_mut(pid)?;
        if entry.approved_image.is_none() { return Err(PermissionError::UnverifiedImage) }
        entry.grants |= permission.bit();
        Ok(())
    }

    /// Revocation takes effect on the NEXT protected operation, including
    /// access through a previously opened PID-owned file descriptor.
    pub fn revoke(&mut self, pid: u64, permission: Permission)
        -> Result<(), PermissionError>
    {
        let entry = self.entry_mut(pid)?;
        entry.grants &= !permission.bit();
        if permission == Permission::FileRead { entry.file_path = None; }
        Ok(())
    }

    /// Forget all grants on exit/fault. Never reuse a PID generation even
    /// after a slot becomes free.
    pub fn retire(&mut self, pid: u64) -> Result<(), PermissionError> {
        *self.entry_mut(pid)? = Entry::empty();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const APPROVED_ELF: &[u8] = b"\x7fELF-WolfOS-approved";
    fn approve<const N: usize>(ledger: &mut AppPermissions<N>, pid: u64) {
        ledger.bind_verified_image(pid, APPROVED_ELF, APPROVED_ELF).unwrap();
    }

    #[test]
    fn every_domain_denies_by_default_and_only_kernel_grant_activates() {
        let mut ledger = AppPermissions::<2>::new();
        for permission in [
            Permission::FileRead, Permission::Network,
            Permission::Microphone, Permission::Camera,
        ] {
            assert!(!ledger.allows(0, permission));
            assert!(!ledger.allows(1, permission));
            assert!(!ledger.allows(2, permission));
        }
        ledger.enroll(1).unwrap();
        ledger.enroll(2).unwrap();
        approve(&mut ledger, 1);
        approve(&mut ledger, 2);
        ledger.grant_file_read_path(1, "/tmp/msg.txt").unwrap();
        assert!(ledger.allows(1, Permission::FileRead));
        assert!(!ledger.allows(2, Permission::FileRead));
        assert!(!ledger.allows(1, Permission::Network));
        ledger.grant(2, Permission::Camera).unwrap();
        assert!(ledger.allows(2, Permission::Camera));
        assert!(!ledger.allows(1, Permission::Camera));
    }

    #[test]
    fn live_revoke_and_regrant_never_leak_to_other_permissions() {
        let mut ledger = AppPermissions::<1>::new();
        ledger.enroll(7).unwrap();
        approve(&mut ledger, 7);
        ledger.grant_file_read_path(7, "/tmp/msg.txt").unwrap();
        ledger.grant(7, Permission::Microphone).unwrap();
        ledger.revoke(7, Permission::FileRead).unwrap();
        assert!(!ledger.allows(7, Permission::FileRead));
        assert!(ledger.allows(7, Permission::Microphone));
        ledger.grant_file_read_path(7, "/tmp/msg.txt").unwrap();
        assert!(ledger.allows(7, Permission::FileRead));
        ledger.revoke(7, Permission::Microphone).unwrap();
        assert!(!ledger.allows(7, Permission::Microphone));
        assert!(ledger.allows(7, Permission::FileRead));
    }

    #[test]
    fn retire_revokes_every_domain_and_stale_pid_cannot_reenroll() {
        let mut ledger = AppPermissions::<1>::new();
        ledger.enroll(99).unwrap();
        approve(&mut ledger, 99);
        for permission in [
            Permission::FileRead, Permission::Network,
            Permission::Microphone, Permission::Camera,
        ] { if permission == Permission::FileRead {
            ledger.grant_file_read_path(99, "/tmp/msg.txt").unwrap();
        } else { ledger.grant(99, permission).unwrap(); } }
        assert_eq!(ledger.live(), 1);
        ledger.retire(99).unwrap();
        assert_eq!(ledger.live(), 0);
        for permission in [
            Permission::FileRead, Permission::Network,
            Permission::Microphone, Permission::Camera,
        ] { assert!(!ledger.allows(99, permission)); }
        assert_eq!(ledger.enroll(99), Err(PermissionError::StalePid));
        assert_eq!(ledger.grant_file_read_path(99, "/tmp/msg.txt"),
                   Err(PermissionError::NotRegistered));
        assert_eq!(ledger.retire(99), Err(PermissionError::NotRegistered));
        ledger.enroll(100).unwrap();
        assert!(!ledger.allows(100, Permission::FileRead));
    }

    #[test]
    fn capacity_duplicate_zero_and_pid_regression_fail_closed() {
        let mut ledger = AppPermissions::<1>::new();
        assert_eq!(ledger.enroll(0), Err(PermissionError::InvalidPid));
        assert_eq!(ledger.grant(0, Permission::Network),
                   Err(PermissionError::InvalidPid));
        ledger.enroll(4).unwrap();
        approve(&mut ledger, 4);
        ledger.grant_file_read_path(4, "/tmp/msg.txt").unwrap();
        assert_eq!(ledger.enroll(4), Err(PermissionError::StalePid));
        assert_eq!(ledger.enroll(3), Err(PermissionError::StalePid));
        assert_eq!(ledger.enroll(5), Err(PermissionError::Full));
        assert_eq!(ledger.live(), 1);
        assert!(ledger.allows(4, Permission::FileRead));
        ledger.retire(4).unwrap();
        ledger.enroll(5).unwrap();
        assert!(!ledger.allows(5, Permission::FileRead));
        assert!(!ledger.allows(4, Permission::FileRead));
    }
    #[test]
    fn exact_scope_rejects_nearby_names_traversal_and_bad_grants() {
        let mut ledger = AppPermissions::<2>::new();
        ledger.enroll(10).unwrap();
        assert_eq!(ledger.grant(10, Permission::FileRead),
                   Err(PermissionError::PathRequired));
        assert!(!ledger.allows_file_read_path(10, "/tmp/msg.txt"));
        assert_eq!(ledger.grant_file_read_path(10, "/tmp/msg.txt"),
                   Err(PermissionError::UnverifiedImage));
        approve(&mut ledger, 10);
        for invalid in ["", "/", "tmp/msg.txt", "/tmp/", "//tmp/file",
            "/tmp/../msg.txt", "/tmp/./msg.txt", "/tmp//msg.txt",
            "/tmp/msg.txt/", "/tmp/m\\sg.txt", "/tmp/m sg.txt", "/tmp/é",
        ] {
            assert_eq!(ledger.grant_file_read_path(10, invalid),
                       Err(PermissionError::InvalidPath), "{invalid:?}");
            assert_eq!(ledger.file_read_scope(10), None);
        }
        ledger.grant_file_read_path(10, "/tmp/msg.txt").unwrap();
        assert!(ledger.allows_file_read_path(10, "/tmp/msg.txt"));
        for other in ["/tmp/msg.txt.bak", "/tmp/msg", "/tmpx/msg.txt",
                      "/tmp/private.txt", "/tmp/msg.txt/../msg.txt"] {
            assert!(!ledger.allows_file_read_path(10, other));
        }
        ledger.grant_file_read_path(10, "/tmp/private.txt").unwrap();
        assert!(!ledger.allows_file_read_path(10, "/tmp/msg.txt"));
        assert!(ledger.allows_file_read_path(10, "/tmp/private.txt"));
        assert!(!ledger.allows_file_read_path(11, "/tmp/private.txt"));
        ledger.revoke(10, Permission::FileRead).unwrap();
        assert_eq!(ledger.file_read_scope(10), None);
        ledger.retire(10).unwrap();
        ledger.enroll(11).unwrap();
        assert_eq!(ledger.file_read_scope(11), None);
    }

    #[test]
    fn tampered_elf_never_enables_any_permission_or_changes_ledger() {
        let mut ledger = AppPermissions::<2>::new();
        ledger.enroll(21).unwrap();
        assert_eq!(ledger.grant(21, Permission::Network),
                   Err(PermissionError::UnverifiedImage));
        assert_eq!(ledger.grant_file_read_path(21, "/tmp/msg.txt"),
                   Err(PermissionError::UnverifiedImage));
        let mut corrupted = APPROVED_ELF.to_vec();
        corrupted[6] ^= 0x01;
        assert_eq!(ledger.bind_verified_image(21, &corrupted, APPROVED_ELF),
                   Err(PermissionError::ImageMismatch));
        assert_eq!(ledger.bind_verified_image(21, &APPROVED_ELF[..4], APPROVED_ELF),
                   Err(PermissionError::ImageMismatch));
        assert_eq!(ledger.bind_verified_image(21, &[], APPROVED_ELF),
                   Err(PermissionError::ImageTooLarge));
        assert!(!ledger.image_verified(21));
        assert_eq!(ledger.live(), 1);
        assert!(!ledger.allows(21, Permission::FileRead));
        approve(&mut ledger, 21);
        assert!(ledger.image_verified(21));
        assert_eq!(ledger.bind_verified_image(21, APPROVED_ELF, APPROVED_ELF),
                   Err(PermissionError::AlreadyVerified));
        ledger.grant_file_read_path(21, "/tmp/msg.txt").unwrap();
        ledger.retire(21).unwrap();
        assert!(!ledger.image_verified(21));
        assert_eq!(ledger.bind_verified_image(21, APPROVED_ELF, APPROVED_ELF),
                   Err(PermissionError::NotRegistered));
        ledger.enroll(22).unwrap();
        assert!(!ledger.image_verified(22));
        assert_eq!(ledger.grant_file_read_path(22, "/tmp/msg.txt"),
                   Err(PermissionError::UnverifiedImage));
    }

    #[test]
    fn admission_requires_nonempty_bounded_trusted_image() {
        static OVERSIZED: [u8; 32769] = [0xa5; 32769];
        let mut ledger = AppPermissions::<1>::new();
        ledger.enroll(1).unwrap();
        assert_eq!(ledger.bind_verified_image(1, &OVERSIZED, &OVERSIZED),
                   Err(PermissionError::ImageTooLarge));
        assert_eq!(ledger.bind_verified_image(1, b"x", &[]),
                   Err(PermissionError::ImageTooLarge));
        assert!(!ledger.image_verified(1));
        approve(&mut ledger, 1);
        assert!(ledger.image_verified(1));
    }

}
