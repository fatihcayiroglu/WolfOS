//! Isolated QEMU-boot proof that the real kernel invokes the pure ELF64
//! preflight on an embedded inert fixture. No user program is executed,
//! no CR3 change or user page installed, no Ring 3 transition occurs.

use crate::{
    elf64_preflight::{preflight, ElfError, PAGE_BYTES},
    elf64_page_image::{materialize, PageContents, PAGE_SIZE},
    pmm, serial,
};
use x86_64::VirtAddr;

fn put16(b: &mut [u8], at: usize, value: u16) {
    b[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(b: &mut [u8], at: usize, value: u64) {
    b[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn verify(hhdm_offset: u64) -> bool {
    let mut image = [0u8; 512];
    image[..4].copy_from_slice(b"\x7fELF");
    image[4..7].copy_from_slice(&[2, 1, 1]);
    put16(&mut image, 16, 2);
    put16(&mut image, 18, 62);
    put32(&mut image, 20, 1);
    put64(&mut image, 24, 0x401100);
    put64(&mut image, 32, 64);
    put16(&mut image, 52, 64);
    put16(&mut image, 54, 56);
    put16(&mut image, 56, 1);
    put32(&mut image, 64, 1);
    put32(&mut image, 68, 5); // readable + executable, not writable
    put64(&mut image, 72, 0x100);
    put64(&mut image, 80, 0x401100);
    put64(&mut image, 96, 8);
    put64(&mut image, 104, 0x900);
    put64(&mut image, 112, PAGE_BYTES);
    image[0x100] = 0xc3;

    let Ok(plan) = preflight(&image) else {
        serial::write_line("WOLFOS_ELF64_PREFLIGHT_ERROR valid_fixture");
        return false;
    };
    if plan.entry != 0x401100 || plan.len != 1 {
        serial::write_line("WOLFOS_ELF64_PREFLIGHT_ERROR invalid_plan");
        return false;
    }
    let Some(load) = plan.segments[0] else {
        serial::write_line("WOLFOS_ELF64_PREFLIGHT_ERROR missing_segment");
        return false;
    };
    if load.page_start != 0x401000 || load.page_end != 0x402000
        || !load.executable || load.writable || load.file_size != 8
        || load.memory_size != 0x900
    {
        serial::write_line("WOLFOS_ELF64_PREFLIGHT_ERROR wrong_permissions_or_bounds");
        return false;
    }

    // Fail-closed negative checks on the EXACT kernel code path.
    put32(&mut image, 68, 7);
    let wx_rejected = preflight(&image) == Err(ElfError::InvalidPermissions);
    put32(&mut image, 68, 5);
    let truncated_rejected = preflight(&image[..65]) == Err(ElfError::ProgramTable);
    put64(&mut image, 24, 0xffff_ffff_8000_0000);
    let kernel_entry_rejected = preflight(&image) == Err(ElfError::InvalidRange);
    if !wx_rejected || !truncated_rejected || !kernel_entry_rejected {
        serial::write_line("WOLFOS_ELF64_PREFLIGHT_ERROR fail_open");
        return false;
    }
    // The kernel itself exercises one real WolfOS-PMM-owned physical frame.
    // HHDM maps it in supervisor space ONLY; it is never installed as a
    // user PTE. This proves exact file bytes + BSS zero-fill and ownership
    // release, not Ring 3 or address-space isolation.
    let before = pmm::statistics().allocated_frames;
    let Some(frame) = pmm::allocate_frame() else {
        serial::write_line("WOLFOS_ELF64_PAGE_ERROR no_free_frame");
        return false;
    };
    let Some(address) = hhdm_offset.checked_add(frame)
        .and_then(|addr| VirtAddr::try_new(addr).ok())
    else {
        let _ = pmm::free_frame(frame);
        serial::write_line("WOLFOS_ELF64_PAGE_ERROR invalid_hhdm");
        return false;
    };
    // SAFETY: frame is exclusively allocated by WolfOS PMM, 4-KiB aligned,
    // fully mapped by Limine's HHDM. BSP owns it until free_frame() below.
    let page = unsafe { &mut *address.as_mut_ptr::<[u8; PAGE_SIZE]>() };
    let populated = materialize(&image, &load, load.page_start, page);
    let correct = populated == Ok(PageContents {
        copied: 8, zeroed: PAGE_SIZE - 8,
        writable: false, executable: true,
    }) && page[..0x100].iter().all(|b| *b == 0)
        && page[0x100] == 0xc3
        && page[0x101..].iter().all(|b| *b == 0);
    let released = pmm::free_frame(frame).is_ok();
    let after = pmm::statistics().allocated_frames;
    if !correct || !released || after != before {
        serial::write_line("WOLFOS_ELF64_PAGE_ERROR copy_or_release");
        return false;
    }
    serial::write_line(
        "WOLFOS_ELF64_PAGE_OK copied=8 zeroed=4088 frame_owned=1 released=1 ring3=0"
    );
    serial::write_line(
        "WOLFOS_ELF64_PREFLIGHT_OK entry=0x401100 loads=1 pages=1 wx_rejected=1 truncated_rejected=1 kernel_entry_rejected=1 executed=0 ring3=0"
    );
    true
}
