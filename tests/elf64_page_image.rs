//! Host contract for exact WolfOS no_std ELF64 admission + page copying.
#[path = "../kernel/src/elf64_preflight.rs"]
mod elf64_preflight;
#[path = "../kernel/src/elf64_page_image.rs"]
mod elf64_page_image;

use elf64_preflight::{preflight, LoadSegment};
use elf64_page_image::{materialize, MaterializeError, PAGE_SIZE};

fn put16(b: &mut [u8], at: usize, n: u16) {
    b[at..at+2].copy_from_slice(&n.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, n: u32) {
    b[at..at+4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, n: u64) {
    b[at..at+8].copy_from_slice(&n.to_le_bytes());
}
fn fixture() -> Vec<u8> {
    let mut b = vec![0u8; 0x300];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4..7].copy_from_slice(&[2, 1, 1]);
    put16(&mut b, 16, 2);
    put16(&mut b, 18, 62);
    put32(&mut b, 20, 1);
    put64(&mut b, 24, 0x401ff0);
    put64(&mut b, 32, 64);
    put16(&mut b, 52, 64);
    put16(&mut b, 54, 56);
    put16(&mut b, 56, 1);
    put32(&mut b, 64, 1);
    put32(&mut b, 68, 5);
    put64(&mut b, 72, 0x1f0);
    put64(&mut b, 80, 0x401ff0);
    put64(&mut b, 96, 20);
    put64(&mut b, 104, 0x1000);
    put64(&mut b, 112, 0x1000);
    for n in 0..20usize { b[0x1f0+n] = (n + 1) as u8; }
    b
}

#[test]
fn copies_unaligned_cross_page_file_bytes_and_zeroes_every_other_byte() {
    let bytes = fixture();
    let plan = preflight(&bytes).unwrap();
    assert_eq!(plan.len, 1);
    let segment = plan.segments[0].unwrap();
    assert_eq!((segment.page_start, segment.page_end), (0x401000, 0x403000));

    let mut first = [0xeeu8; PAGE_SIZE];
    let a = materialize(&bytes, &segment, 0x401000, &mut first).unwrap();
    assert_eq!((a.copied, a.zeroed), (16, PAGE_SIZE - 16));
    assert!(first[..PAGE_SIZE - 16].iter().all(|b| *b == 0));
    let expected: Vec<u8> = (1..=16).collect();
    assert_eq!(&first[PAGE_SIZE - 16..], &expected[..]);

    let mut second = [0xeeu8; PAGE_SIZE];
    let b = materialize(&bytes, &segment, 0x402000, &mut second).unwrap();
    assert_eq!((b.copied, b.zeroed), (4, PAGE_SIZE - 4));
    assert_eq!(&second[..4], &[17, 18, 19, 20]);
    assert!(second[4..].iter().all(|b| *b == 0));
    assert!(a.executable && !a.writable && b.executable && !b.writable);
}

#[test]
fn initializes_pure_bss_page_as_zero_without_reading_file() {
    let segment = LoadSegment {
        file_offset: 0, file_size: 0, virtual_address: 0x601000,
        memory_size: 4096, page_start: 0x601000, page_end: 0x602000,
        writable: true, executable: false,
    };
    let mut page = [0xffu8; PAGE_SIZE];
    let result = materialize(&[], &segment, 0x601000, &mut page).unwrap();
    assert_eq!(result.copied, 0);
    assert_eq!(result.zeroed, PAGE_SIZE);
    assert!(result.writable && !result.executable);
    assert!(page.iter().all(|b| *b == 0));
}

#[test]
fn invalid_page_alignment_and_range_preserve_destination_contents() {
    let bytes = fixture();
    let seg = preflight(&bytes).unwrap().segments[0].unwrap();
    let mut page = [0xa5u8; PAGE_SIZE];
    for wrong in [0x401001, 0x400000, 0x403000, u64::MAX] {
        assert_eq!(
            materialize(&bytes, &seg, wrong, &mut page),
            Err(MaterializeError::InvalidPage)
        );
        assert!(page.iter().all(|b| *b == 0xa5));
    }
}

#[test]
fn forged_wx_untrusted_file_or_bad_plan_fail_before_zeroing() {
    let bytes = fixture();
    let mut segment = preflight(&bytes).unwrap().segments[0].unwrap();
    let mut page = [0x5au8; PAGE_SIZE];
    segment.writable = true;
    assert_eq!(
        materialize(&bytes, &segment, 0x401000, &mut page),
        Err(MaterializeError::InvalidPermissions)
    );
    segment.writable = false;
    assert_eq!(
        materialize(&bytes[..0x200], &segment, 0x401000, &mut page),
        Err(MaterializeError::InvalidFile)
    );
    segment.page_end += 4096;
    assert_eq!(
        materialize(&bytes, &segment, 0x401000, &mut page),
        Err(MaterializeError::InvalidSegment)
    );
    segment.page_end -= 4096;
    segment.file_offset += 1;
    assert_eq!(
        materialize(&bytes, &segment, 0x401000, &mut page),
        Err(MaterializeError::InvalidSegment)
    );
    assert!(page.iter().all(|b| *b == 0x5a));
}

#[test]
fn refuse_non_user_page_and_wraparound() {
    let mut seg = LoadSegment {
        file_offset: 0, file_size: 0, virtual_address: 0,
        memory_size: 0x1000, page_start: 0, page_end: 0x1000,
        writable: false, executable: false,
    };
    let mut page = [0x33u8; PAGE_SIZE];
    assert_eq!(
        materialize(&[], &seg, 0, &mut page),
        Err(MaterializeError::InvalidSegment)
    );
    seg.virtual_address = u64::MAX - 0xfff;
    seg.page_start = u64::MAX & !0xfff;
    seg.page_end = u64::MAX;
    assert_eq!(
        materialize(&[], &seg, seg.page_start, &mut page),
        Err(MaterializeError::InvalidSegment)
    );
    assert!(page.iter().all(|b| *b == 0x33));
}
