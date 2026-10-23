//! P2 validated ELF64 PT_LOAD -> 4096-byte page materialization.
//! Initializes only caller-owned buffers/PMM frames. No CR3, PTE writes
//! or Ring3 transfers occur here. No allocation or heap is required.
//!
//! Single-page and bounded batch APIs never mutate their destinations on
//! validation failure. The batch validates EVERY page before touching ANY
//! destination, avoiding partially initialized multi-page ELF images.

use crate::elf64_preflight::{LoadSegment, PAGE_BYTES, USER_END, USER_MIN};

pub const PAGE_SIZE: usize = PAGE_BYTES as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaterializeError {
    InvalidPage, InvalidSegment, InvalidFile, InvalidPermissions,
    DuplicateVirtualPage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageContents {
    pub copied: usize,
    pub zeroed: usize,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Copy)]
struct CheckedPage {
    from: usize,
    into: usize,
    copied: usize,
    contents: PageContents,
}

/// Validate all source and destination bounds without writing to the page.
/// The checked offsets are only valid for this unchanged input byte slice.
fn inspect(
    input: &[u8],
    segment: &LoadSegment,
    page_virtual: u64,
) -> Result<CheckedPage, MaterializeError> {
    if segment.executable && segment.writable {
        return Err(MaterializeError::InvalidPermissions);
    }
    if segment.file_size > segment.memory_size || segment.memory_size == 0 {
        return Err(MaterializeError::InvalidSegment);
    }
    let memory_end = segment.virtual_address.checked_add(segment.memory_size)
        .ok_or(MaterializeError::InvalidSegment)?;
    let file_va_end = segment.virtual_address.checked_add(segment.file_size)
        .ok_or(MaterializeError::InvalidSegment)?;
    let file_end = segment.file_offset.checked_add(segment.file_size)
        .ok_or(MaterializeError::InvalidFile)?;
    let file_end_usize = usize::try_from(file_end)
        .map_err(|_| MaterializeError::InvalidFile)?;
    if file_end_usize > input.len() {
        return Err(MaterializeError::InvalidFile);
    }
    let expected_start = segment.virtual_address & !(PAGE_BYTES - 1);
    let expected_end = memory_end.checked_add(PAGE_BYTES - 1)
        .ok_or(MaterializeError::InvalidSegment)? & !(PAGE_BYTES - 1);
    if expected_start < USER_MIN || memory_end > USER_END
        || expected_end > USER_END
        || segment.page_start != expected_start
        || segment.page_end != expected_end
        || segment.virtual_address % PAGE_BYTES != segment.file_offset % PAGE_BYTES
    {
        return Err(MaterializeError::InvalidSegment);
    }
    let page_end = page_virtual.checked_add(PAGE_BYTES)
        .ok_or(MaterializeError::InvalidPage)?;
    if page_virtual % PAGE_BYTES != 0
        || page_virtual < expected_start || page_end > expected_end
    {
        return Err(MaterializeError::InvalidPage);
    }

    let copy_start = page_virtual.max(segment.virtual_address);
    let copy_end = page_end.min(file_va_end);
    let (from, into, copied) = if copy_start < copy_end {
        let offset = copy_start - segment.virtual_address;
        let start = segment.file_offset.checked_add(offset)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(MaterializeError::InvalidFile)?;
        let size = usize::try_from(copy_end - copy_start)
            .map_err(|_| MaterializeError::InvalidFile)?;
        let src_end = start.checked_add(size).ok_or(MaterializeError::InvalidFile)?;
        if src_end > input.len() {
            return Err(MaterializeError::InvalidFile);
        }
        let dest_start = usize::try_from(copy_start - page_virtual)
            .map_err(|_| MaterializeError::InvalidPage)?;
        (start, dest_start, size)
    } else {
        (0, 0, 0)
    };
    Ok(CheckedPage {
        from,
        into,
        copied,
        contents: PageContents {
            copied,
            zeroed: PAGE_SIZE - copied,
            writable: segment.writable,
            executable: segment.executable,
        },
    })
}

fn commit(input: &[u8], target: &mut [u8; PAGE_SIZE], page: CheckedPage) {
    target.fill(0);
    if page.copied != 0 {
        target[page.into..page.into + page.copied]
            .copy_from_slice(&input[page.from..page.from + page.copied]);
    }
}

/// Strict single-page copy. No destination mutation on any error.
pub fn materialize(
    input: &[u8],
    segment: &LoadSegment,
    page_virtual: u64,
    target: &mut [u8; PAGE_SIZE],
) -> Result<PageContents, MaterializeError> {
    let checked = inspect(input, segment, page_virtual)?;
    commit(input, target, checked);
    Ok(checked.contents)
}

/// Stage validation of every PT_LOAD page first; mutate ALL destinations
/// only after every segment, source slice and page VA passes. Distinct
/// mutable borrows enforce non-overlapping physical destination buffers.
/// Reject duplicate virtual pages independently of their backing addresses.
///
/// The trusted caller must keep the ELF bytes stable while this synchronous
/// copy runs. The caller still must independently audit page ownership,
/// map PTEs, pin backing frames and handle PMM rollback before any IRET.
pub fn materialize_batch<const N: usize>(
    input: &[u8],
    requests: [(&LoadSegment, u64); N],
    destinations: [&mut [u8; PAGE_SIZE]; N],
) -> Result<[PageContents; N], MaterializeError> {
    let mut checked: [Option<CheckedPage>; N] = [None; N];
    for (i, (segment, va)) in requests.iter().copied().enumerate() {
        if requests[..i].iter().any(|(_, earlier)| *earlier == va) {
            return Err(MaterializeError::DuplicateVirtualPage);
        }
        checked[i] = Some(inspect(input, segment, va)?);
    }
    let mut contents = [PageContents {
        copied: 0, zeroed: PAGE_SIZE, writable: false, executable: false,
    }; N];
    for (i, dest) in destinations.into_iter().enumerate() {
        let page = checked[i].expect("all materialization pages inspected");
        commit(input, dest, page);
        contents[i] = page.contents;
    }
    Ok(contents)
}

/// Failure after a completed batch cannot be ignored during admission:
/// a PTE may have the correct flags while its PMM-backed *bytes* do not
/// match the immutable ELF source, including the zeroed BSS and page tails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageAuditError {
    InvalidRequest(MaterializeError),
    ContentMismatch { index: usize, offset: usize },
}

/// Revalidate every bounded page request against its source ELF bytes and
/// then read every byte of every already-populated backing page. Never
/// mutate buffers or table entries. A first mismatch fails closed.
///
/// A trusted caller must keep image bytes and PMM pages stable throughout
/// validation, and audit PTE physical ownership/permissions separately.
/// This does not map or execute a userspace image or change hardware CR3.
pub fn audit_materialized_batch<const N: usize>(
    input: &[u8],
    requests: [(&LoadSegment, u64); N],
    pages: [&[u8; PAGE_SIZE]; N],
) -> Result<[PageContents; N], PageAuditError> {
    let mut checked: [Option<CheckedPage>; N] = [None; N];
    // Validate ALL layouts before interpreting any page content.
    for (i, (segment, va)) in requests.iter().copied().enumerate() {
        if requests[..i].iter().any(|(_, old_va)| *old_va == va) {
            return Err(PageAuditError::InvalidRequest(
                MaterializeError::DuplicateVirtualPage,
            ));
        }
        checked[i] = Some(
            inspect(input, segment, va).map_err(PageAuditError::InvalidRequest)?
        );
    }
    let mut summaries = [PageContents {
        copied: 0, zeroed: PAGE_SIZE, writable: false, executable: false,
    }; N];
    for (index, backing) in pages.into_iter().enumerate() {
        let check = checked[index].expect("each checked page is valid");
        for (offset, actual) in backing.iter().copied().enumerate() {
            let expected = if offset >= check.into
                && offset - check.into < check.copied
            {
                input[check.from + (offset - check.into)]
            } else {
                0 // full zero BSS plus every unused first/last page byte
            };
            if actual != expected {
                return Err(PageAuditError::ContentMismatch { index, offset });
            }
        }
        summaries[index] = check.contents;
    }
    Ok(summaries)
}

/// A user stack is intentionally NOT an ELF PT_LOAD page. Check all 4 KiB,
/// including bytes that would otherwise leak a previous PMM owner's data.
pub fn audit_zeroed_stack(page: &[u8; PAGE_SIZE]) -> Result<(), usize> {
    match page.iter().position(|byte| *byte != 0) {
        Some(offset) => Err(offset),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> ([u8; 512], LoadSegment, LoadSegment) {
        let mut image = [0u8; 512];
        image[0x100..0x108].copy_from_slice(&[0x90, 1, 2, 3, 4, 5, 6, 0xc3]);
        image[0x180..0x188].copy_from_slice(&[8, 7, 6, 5, 4, 3, 2, 1]);
        let text = LoadSegment {
            file_offset: 0x100, file_size: 8,
            virtual_address: 0x401100, memory_size: 0x1000,
            page_start: 0x401000, page_end: 0x403000,
            writable: false, executable: true,
        };
        let data = LoadSegment {
            file_offset: 0x180, file_size: 8,
            virtual_address: 0x403180, memory_size: 0x600,
            page_start: 0x403000, page_end: 0x404000,
            writable: true, executable: false,
        };
        (image, text, data)
    }

    #[test]
    fn post_copy_elf_byte_audit_checks_code_bss_data_and_stack() {
        let (image, text, data) = samples();
        let mut code = [0xa5; PAGE_SIZE];
        let mut bss = [0x5a; PAGE_SIZE];
        let mut rw = [0xc3; PAGE_SIZE];
        let requests = [
            (&text, 0x401000), (&text, 0x402000), (&data, 0x403000),
        ];
        let built = materialize_batch(
            &image, requests, [&mut code, &mut bss, &mut rw],
        ).unwrap();
        assert_eq!(
            audit_materialized_batch(&image, requests, [&code, &bss, &rw]),
            Ok(built),
        );
        assert_eq!(audit_zeroed_stack(&[0u8; PAGE_SIZE]), Ok(()));

        let old = code[0x100];
        code[0x100] ^= 1;
        assert_eq!(
            audit_materialized_batch(&image, requests, [&code, &bss, &rw]),
            Err(PageAuditError::ContentMismatch {
                index: 0, offset: 0x100,
            }),
        );
        code[0x100] = old;
        bss[17] = 0x5a;
        assert_eq!(
            audit_materialized_batch(&image, requests, [&code, &bss, &rw]),
            Err(PageAuditError::ContentMismatch {
                index: 1, offset: 17,
            }),
        );
        bss[17] = 0;
        rw[0x180] ^= 1;
        assert_eq!(
            audit_materialized_batch(&image, requests, [&code, &bss, &rw]),
            Err(PageAuditError::ContentMismatch {
                index: 2, offset: 0x180,
            }),
        );
        rw[0x180] ^= 1;
        let mut stack = [0u8; PAGE_SIZE];
        stack[PAGE_SIZE - 1] = 0xff;
        assert_eq!(audit_zeroed_stack(&stack), Err(PAGE_SIZE - 1));
        assert_eq!(
            audit_materialized_batch(&image, requests, [&code, &bss, &rw]),
            Ok(built),
        );
    }

    #[test]
    fn changed_elf_bytes_and_late_bad_layout_reject_without_any_writes() {
        let (image, text, data) = samples();
        let mut code = [0u8; PAGE_SIZE];
        let mut bss = [0u8; PAGE_SIZE];
        let mut rw = [0u8; PAGE_SIZE];
        let requests = [
            (&text, 0x401000), (&text, 0x402000), (&data, 0x403000),
        ];
        materialize_batch(&image, requests, [&mut code, &mut bss, &mut rw])
            .unwrap();
        let mut changed_source = image;
        changed_source[0x100] ^= 1;
        assert_eq!(
            audit_materialized_batch(
                &changed_source, requests, [&code, &bss, &rw],
            ),
            Err(PageAuditError::ContentMismatch {
                index: 0, offset: 0x100,
            }),
        );
        let mut invalid = data;
        invalid.executable = true; // late W+X, no bytes inspected/written
        assert_eq!(
            audit_materialized_batch(
                &image,
                [(&text, 0x401000), (&text, 0x402000),
                    (&invalid, 0x403000)],
                [&code, &bss, &rw],
            ),
            Err(PageAuditError::InvalidRequest(
                MaterializeError::InvalidPermissions,
            )),
        );
        assert_eq!(
            audit_materialized_batch(
                &image,
                [(&text, 0x401000), (&text, 0x402000),
                    (&data, 0x401000)],
                [&code, &bss, &rw],
            ),
            Err(PageAuditError::InvalidRequest(
                MaterializeError::DuplicateVirtualPage,
            )),
        );
        assert_eq!(
            audit_materialized_batch(&image, requests, [&code, &bss, &rw]),
            Ok([
                PageContents { copied: 8, zeroed: PAGE_SIZE-8,
                    writable: false, executable: true },
                PageContents { copied: 0, zeroed: PAGE_SIZE,
                    writable: false, executable: true },
                PageContents { copied: 8, zeroed: PAGE_SIZE-8,
                    writable: true, executable: false },
            ]),
        );
        assert_eq!(audit_materialized_batch(&image, [], []), Ok([]));
    }

    #[test]
    fn two_text_pages_and_data_materialize_with_exact_zero_fill() {
        let (image, text, data) = samples();
        let mut a = [0xa5; PAGE_SIZE];
        let mut b = [0xa5; PAGE_SIZE];
        let mut c = [0xa5; PAGE_SIZE];
        let summary = materialize_batch(
            &image, [(&text, 0x401000), (&text, 0x402000), (&data, 0x403000)],
            [&mut a, &mut b, &mut c],
        ).unwrap();
        assert_eq!(summary[0], PageContents {
            copied: 8, zeroed: PAGE_SIZE - 8, writable: false, executable: true,
        });
        assert_eq!(summary[1].copied, 0);
        assert_eq!(summary[2], PageContents {
            copied: 8, zeroed: PAGE_SIZE - 8, writable: true, executable: false,
        });
        assert!(a[..0x100].iter().all(|byte| *byte == 0));
        assert_eq!(&a[0x100..0x108], &image[0x100..0x108]);
        assert!(a[0x108..].iter().all(|byte| *byte == 0));
        assert!(b.iter().all(|byte| *byte == 0));
        assert!(c[..0x180].iter().all(|byte| *byte == 0));
        assert_eq!(&c[0x180..0x188], &image[0x180..0x188]);
        assert!(c[0x188..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn late_wx_invalid_file_and_duplicate_pages_leave_all_buffers_unchanged() {
        let (image, text, data) = samples();
        let mut a = [0xa5; PAGE_SIZE];
        let mut b = [0x5a; PAGE_SIZE];
        let mut c = [0x3c; PAGE_SIZE];
        let mut wx = data;
        wx.executable = true;
        assert_eq!(materialize_batch(
            &image, [(&text, 0x401000), (&text, 0x402000), (&wx, 0x403000)],
            [&mut a, &mut b, &mut c],
        ), Err(MaterializeError::InvalidPermissions));
        assert_eq!(materialize_batch(
            &image, [(&text, 0x401000), (&text, 0x402000), (&data, 0x401000)],
            [&mut a, &mut b, &mut c],
        ), Err(MaterializeError::DuplicateVirtualPage));
        let mut out_of_file = data;
        out_of_file.file_offset = 0x1180; // preserve VA/file page offset
        assert_eq!(materialize_batch(
            &image, [(&text, 0x401000), (&text, 0x402000),
                     (&out_of_file, 0x403000)],
            [&mut a, &mut b, &mut c],
        ), Err(MaterializeError::InvalidFile));
        assert!(a.iter().all(|x| *x == 0xa5));
        assert!(b.iter().all(|x| *x == 0x5a));
        assert!(c.iter().all(|x| *x == 0x3c));
    }

    #[test]
    fn empty_batch_is_noop_and_single_page_still_refuses_mutation() {
        let (image, text, data) = samples();
        assert_eq!(materialize_batch(&image, [], []), Ok([]));
        let mut untouched = [0xbe; PAGE_SIZE];
        assert_eq!(materialize(
            &image, &data, 0x401000, &mut untouched,
        ), Err(MaterializeError::InvalidPage));
        assert!(untouched.iter().all(|x| *x == 0xbe));
        assert_eq!(materialize(&image, &text, 0x402000, &mut untouched),
            Ok(PageContents {
                copied: 0, zeroed: PAGE_SIZE,
                writable: false, executable: true,
            }));
        assert!(untouched.iter().all(|x| *x == 0));
    }
}
