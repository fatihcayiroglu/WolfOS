//! P2 ELF64 ET_EXEC *preflight*, without allocation, mapping or execution.
//!
//! Pure, allocation-free validation of untrusted file bytes, never casting
//! file bytes to Rust structs. Produces a checked, fixed-size page mapping
//! plan for a future userspace loader. All ranges are exclusive-end.
//! This is NOT Ring 3, CR3 isolation, a complete ELF loader or dynamic linker.

pub const PAGE_BYTES: u64 = 4096;
pub const USER_MIN: u64 = 0x1_0000;
pub const USER_END: u64 = 0x0000_8000_0000_0000;
pub const MAX_PROGRAM_HEADERS: usize = 32;
pub const MAX_LOAD_SEGMENTS: usize = 8;
const ELF_HEADER: usize = 64;
const PROGRAM_HEADER: usize = 56;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    Truncated, Magic, UnsupportedIdentity, UnsupportedFile,
    ProgramTable, UnsupportedSegment, InvalidAlignment,
    InvalidRange, InvalidFileRange, InvalidPermissions,
    OverlappingPages, TooManySegments, EntryNotExecutable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadSegment {
    pub file_offset: u64,
    pub file_size: u64,
    pub virtual_address: u64,
    pub memory_size: u64,
    pub page_start: u64,
    pub page_end: u64,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImagePlan {
    pub entry: u64,
    pub segments: [Option<LoadSegment>; MAX_LOAD_SEGMENTS],
    pub len: usize,
}

fn read<const N: usize>(input: &[u8], at: usize) -> Result<[u8; N], ElfError> {
    let end = at.checked_add(N).ok_or(ElfError::Truncated)?;
    input.get(at..end).ok_or(ElfError::Truncated)?
        .try_into().map_err(|_| ElfError::Truncated)
}

fn u16_at(input: &[u8], at: usize) -> Result<u16, ElfError> {
    Ok(u16::from_le_bytes(read::<2>(input, at)?))
}
fn u32_at(input: &[u8], at: usize) -> Result<u32, ElfError> {
    Ok(u32::from_le_bytes(read::<4>(input, at)?))
}
fn u64_at(input: &[u8], at: usize) -> Result<u64, ElfError> {
    Ok(u64::from_le_bytes(read::<8>(input, at)?))
}

fn page_up(address: u64) -> Result<u64, ElfError> {
    Ok(address.checked_add(PAGE_BYTES - 1)
        .ok_or(ElfError::InvalidRange)? & !(PAGE_BYTES - 1))
}

/// Strict first executable: ELF64, little-endian x86-64 ET_EXEC only.
/// Refuse interpreters, relocatable/shared images, TLS, writable+executable
/// mappings, page-sharing LOADs, noncanonical/low userspace pointers and
/// entry points not actually backed by executable bytes.
///
/// No file contents are copied or executed; returned plans are metadata.
pub fn preflight(input: &[u8]) -> Result<ImagePlan, ElfError> {
    if input.len() < ELF_HEADER {
        return Err(ElfError::Truncated);
    }
    if input.get(..4) != Some(&b"\x7fELF"[..]) {
        return Err(ElfError::Magic);
    }
    if input[4] != 2 || input[5] != 1 || input[6] != 1
        || input[7] != 0 || input[8..16].iter().any(|byte| *byte != 0)
    {
        return Err(ElfError::UnsupportedIdentity);
    }
    if u16_at(input, 16)? != 2 // ET_EXEC, not ET_DYN
        || u16_at(input, 18)? != 62 // AMD64
        || u32_at(input, 20)? != 1
        || u32_at(input, 48)? != 0 // no architecture-specific flags
        || u16_at(input, 52)? as usize != ELF_HEADER
    {
        return Err(ElfError::UnsupportedFile);
    }
    let entry = u64_at(input, 24)?;
    if !(USER_MIN..USER_END).contains(&entry) {
        return Err(ElfError::InvalidRange);
    }
    let phoff = usize::try_from(u64_at(input, 32)?)
        .map_err(|_| ElfError::ProgramTable)?;
    let entsize = usize::from(u16_at(input, 54)?);
    let phnum = usize::from(u16_at(input, 56)?);
    if phoff < ELF_HEADER || entsize != PROGRAM_HEADER
        || phnum == 0 || phnum > MAX_PROGRAM_HEADERS
    {
        return Err(ElfError::ProgramTable);
    }
    let bytes = phnum.checked_mul(entsize)
        .and_then(|n| phoff.checked_add(n))
        .ok_or(ElfError::ProgramTable)?;
    if bytes > input.len() {
        return Err(ElfError::ProgramTable);
    }
    let mut plan = ImagePlan {
        entry,
        segments: [None; MAX_LOAD_SEGMENTS],
        len: 0,
    };
    let mut entry_executable = false;
    for index in 0..phnum {
        let at = phoff + index * PROGRAM_HEADER; // bounded above
        let kind = u32_at(input, at)?;
        let flags = u32_at(input, at + 4)?;
        if kind == PT_INTERP || kind == PT_DYNAMIC || kind == PT_TLS {
            return Err(ElfError::UnsupportedSegment);
        }
        if kind == PT_GNU_STACK {
            if flags & PF_X != 0 || flags & !(PF_R | PF_W | PF_X) != 0 {
                return Err(ElfError::InvalidPermissions);
            }
            continue;
        }
        // PT_NULL, PT_NOTE, PT_PHDR, PT_GNU_RELRO, PT_GNU_PROPERTY
        // are permitted as inert metadata. All unknown types fail closed.
        if matches!(kind, 0 | 4 | 6 | 0x6474_e552 | 0x6474_e553) {
            continue;
        }
        if kind != PT_LOAD {
            return Err(ElfError::UnsupportedSegment);
        }
        if flags & !(PF_R | PF_W | PF_X) != 0
            || flags & PF_R == 0
            || flags & (PF_W | PF_X) == (PF_W | PF_X)
        {
            return Err(ElfError::InvalidPermissions);
        }
        if plan.len == MAX_LOAD_SEGMENTS {
            return Err(ElfError::TooManySegments);
        }
        let file_offset = u64_at(input, at + 8)?;
        let virtual_address = u64_at(input, at + 16)?;
        let file_size = u64_at(input, at + 32)?;
        let memory_size = u64_at(input, at + 40)?;
        let alignment = u64_at(input, at + 48)?;
        if alignment > 1
            && (!alignment.is_power_of_two()
                || virtual_address % alignment != file_offset % alignment)
        {
            return Err(ElfError::InvalidAlignment);
        }
        // We do not support fractured file-to-page offsets.
        if virtual_address % PAGE_BYTES != file_offset % PAGE_BYTES {
            return Err(ElfError::InvalidAlignment);
        }
        if memory_size == 0 || file_size > memory_size {
            return Err(ElfError::InvalidRange);
        }
        let end = virtual_address.checked_add(memory_size)
            .ok_or(ElfError::InvalidRange)?;
        let page_start = virtual_address & !(PAGE_BYTES - 1);
        let page_end = page_up(end)?;
        if page_start < USER_MIN || end > USER_END || page_end > USER_END
            || end <= virtual_address
        {
            return Err(ElfError::InvalidRange);
        }
        let file_end = file_offset.checked_add(file_size)
            .ok_or(ElfError::InvalidFileRange)?;
        if file_end > input.len() as u64 {
            return Err(ElfError::InvalidFileRange);
        }
        for old in plan.segments[..plan.len].iter().flatten() {
            if page_start < old.page_end && old.page_start < page_end {
                return Err(ElfError::OverlappingPages);
            }
        }
        if flags & PF_X != 0
            && entry >= virtual_address
            && entry < virtual_address + file_size
        {
            entry_executable = true;
        }
        plan.segments[plan.len] = Some(LoadSegment {
            file_offset, file_size, virtual_address, memory_size,
            page_start, page_end,
            writable: flags & PF_W != 0,
            executable: flags & PF_X != 0,
        });
        plan.len += 1;
    }
    if !entry_executable {
        return Err(ElfError::EntryNotExecutable);
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put16(b: &mut [u8], at: usize, value: u16) {
        b[at..at+2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(b: &mut [u8], at: usize, value: u32) {
        b[at..at+4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(b: &mut [u8], at: usize, value: u64) {
        b[at..at+8].copy_from_slice(&value.to_le_bytes());
    }

    fn fixture() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4..7].copy_from_slice(&[2, 1, 1]);
        put16(&mut b, 16, 2); // ET_EXEC
        put16(&mut b, 18, 62); // AMD64
        put32(&mut b, 20, 1);
        put64(&mut b, 24, 0x401100);
        put64(&mut b, 32, 64);
        put16(&mut b, 52, 64);
        put16(&mut b, 54, 56);
        put16(&mut b, 56, 1);
        put32(&mut b, 64, PT_LOAD);
        put32(&mut b, 68, PF_R | PF_X);
        put64(&mut b, 72, 0x100);
        put64(&mut b, 80, 0x401100);
        put64(&mut b, 96, 8);
        put64(&mut b, 104, 0x900); // remainder must be zero-filled
        put64(&mut b, 112, PAGE_BYTES);
        b[0x100] = 0xc3; // return instruction, not executed by preflight
        b
    }

    #[test]
    fn validates_file_backed_text_bss_and_page_plan() {
        let b = fixture();
        let plan = preflight(&b).unwrap();
        assert_eq!(plan.entry, 0x401100);
        assert_eq!(plan.len, 1);
        let segment = plan.segments[0].unwrap();
        assert_eq!((segment.page_start, segment.page_end), (0x401000, 0x402000));
        assert_eq!((segment.file_size, segment.memory_size), (8, 0x900));
        assert!(!segment.writable && segment.executable);
    }

    #[test]
    fn rejects_corrupt_identity_and_executable_type() {
        let mut b = fixture();
        b[0] = 0;
        assert_eq!(preflight(&b), Err(ElfError::Magic));
        let mut b = fixture();
        b[4] = 1;
        assert_eq!(preflight(&b), Err(ElfError::UnsupportedIdentity));
        let mut b = fixture();
        put16(&mut b, 16, 3); // ET_DYN unsupported until relocations exist
        assert_eq!(preflight(&b), Err(ElfError::UnsupportedFile));
        let mut b = fixture();
        put16(&mut b, 18, 3);
        assert_eq!(preflight(&b), Err(ElfError::UnsupportedFile));
        assert_eq!(preflight(&b""[..]), Err(ElfError::Truncated));
    }

    #[test]
    fn refuses_truncated_tables_and_bogus_counts() {
        let mut b = fixture();
        put16(&mut b, 56, 32); // cannot fit in 512-byte fixture
        assert_eq!(preflight(&b), Err(ElfError::ProgramTable));
        let mut b = fixture();
        put64(&mut b, 32, u64::MAX);
        assert_eq!(preflight(&b), Err(ElfError::ProgramTable));
        let mut b = fixture();
        put16(&mut b, 54, 0);
        assert_eq!(preflight(&b), Err(ElfError::ProgramTable));
    }

    #[test]
    fn refuses_writable_executable_and_unsupported_interpreter() {
        let mut b = fixture();
        put32(&mut b, 68, PF_R | PF_W | PF_X);
        assert_eq!(preflight(&b), Err(ElfError::InvalidPermissions));
        let mut b = fixture();
        put32(&mut b, 64, PT_INTERP);
        assert_eq!(preflight(&b), Err(ElfError::UnsupportedSegment));
        let mut b = fixture();
        put32(&mut b, 64, PT_DYNAMIC);
        assert_eq!(preflight(&b), Err(ElfError::UnsupportedSegment));
        let mut b = fixture();
        put32(&mut b, 64, PT_TLS);
        assert_eq!(preflight(&b), Err(ElfError::UnsupportedSegment));
    }

    #[test]
    fn rejects_noncongruent_alignment_and_out_of_file() {
        let mut b = fixture();
        put64(&mut b, 72, 0x101);
        assert_eq!(preflight(&b), Err(ElfError::InvalidAlignment));
        let mut b = fixture();
        put64(&mut b, 112, 3);
        assert_eq!(preflight(&b), Err(ElfError::InvalidAlignment));
        let mut b = fixture();
        put64(&mut b, 96, 513);
        assert_eq!(preflight(&b), Err(ElfError::InvalidFileRange));
        let mut b = fixture();
        put64(&mut b, 104, 1);
        assert_eq!(preflight(&b), Err(ElfError::InvalidRange));
    }

    #[test]
    fn refuses_kernel_addresses_low_null_and_overflowing_ranges() {
        let mut b = fixture();
        put64(&mut b, 24, 0xffff_ffff_8000_0000);
        assert_eq!(preflight(&b), Err(ElfError::InvalidRange));
        let mut b = fixture();
        put64(&mut b, 80, 0);
        put64(&mut b, 72, 0);
        assert_eq!(preflight(&b), Err(ElfError::InvalidRange));
        let mut b = fixture();
        put64(&mut b, 80, 0xffff_ffff_ffff_f100);
        put64(&mut b, 104, u64::MAX);
        assert_eq!(preflight(&b), Err(ElfError::InvalidRange));
    }

    #[test]
    fn entry_must_be_file_backed_and_executable() {
        let mut b = fixture();
        put32(&mut b, 68, PF_R | PF_W);
        assert_eq!(preflight(&b), Err(ElfError::EntryNotExecutable));
        let mut b = fixture();
        put64(&mut b, 24, 0x401200); // only within BSS
        assert_eq!(preflight(&b), Err(ElfError::EntryNotExecutable));
    }

    #[test]
    fn refuses_loads_that_overlap_even_only_at_page_granularity() {
        let mut b = fixture();
        put16(&mut b, 56, 2);
        b.copy_within(64..120, 120);
        put32(&mut b, 120 + 4, PF_R);
        put64(&mut b, 120 + 8, 0x180);
        put64(&mut b, 120 + 16, 0x401180);
        put64(&mut b, 120 + 32, 8);
        put64(&mut b, 120 + 40, 0x30);
        assert_eq!(preflight(&b), Err(ElfError::OverlappingPages));
    }

    #[test]
    fn rejects_executable_user_stack() {
        let mut b = fixture();
        put16(&mut b, 56, 2);
        put32(&mut b, 120, PT_GNU_STACK);
        put32(&mut b, 124, PF_R | PF_W | PF_X);
        assert_eq!(preflight(&b), Err(ElfError::InvalidPermissions));
    }
}
