//! WolfOS P1: safely exercise x86-64 4-KiB page mapping.
//!
//! This is NOT a new address space or general VMM yet. We modify the active
//! Limine page tables at one deliberately unused lower-half kernel-test slot.
//! The bootloader's HHDM remains required to access page tables and RAM.
//! One boot CPU only, with maskable interrupts disabled.

use core::arch::asm;

use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags,
    PhysFrame, Size4KiB, Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use crate::{pmm, serial};

/// Canonical lower-half virtual address deliberately outside Limine mappings.
/// Do not expose this slot to userspace or general kernel applications.
pub const TEST_VIRTUAL_ADDRESS: u64 = 0x0000_4000_0000_0000;
const MAGIC: u64 = 0x574f_4c46_4f53_5031; // "WOLFOSP1"

struct TableFrameAllocator {
    allocated: usize,
}

// SAFETY: only allocates distinct 4-KiB-aligned MEMMAP_USABLE physical frames
// from WolfOS PMM, which permanently owns allocated frames until freed.
unsafe impl FrameAllocator<Size4KiB> for TableFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let physical = pmm::allocate_frame()?;
        self.allocated += 1;
        Some(PhysFrame::containing_address(PhysAddr::new(physical)))
    }
}

fn hhdm_virtual(hhdm_offset: u64, physical: u64) -> Option<VirtAddr> {
    let address = hhdm_offset.checked_add(physical)?;
    VirtAddr::try_new(address).ok()
}

pub fn mapping_roundtrip(hhdm_offset: u64) -> bool {
    let (pml4_frame, _) = Cr3::read();
    let Some(pml4_virt) = hhdm_virtual(hhdm_offset, pml4_frame.start_address().as_u64()) else {
        serial::write_line("WOLFOS_PAGING_ERROR invalid HHDM pointer");
        return false;
    };

    // SAFETY: Limine's HHDM maps the active CR3 PML4; this is early,
    // single-core serialized initialization with external IRQs masked.
    // The offset mapper is dropped before boot continues.
    let pml4 = unsafe { &mut *(pml4_virt.as_mut_ptr::<PageTable>()) };
    // SAFETY: HHDM maps all physical frames supplied by Limine and PMM,
    // and all required page-table pages for this mapping.
    let mut mapper = unsafe { OffsetPageTable::new(pml4, VirtAddr::new(hhdm_offset)) };

    let target = VirtAddr::new(TEST_VIRTUAL_ADDRESS);
    let page = Page::<Size4KiB>::containing_address(target);
    if mapper.translate_addr(target).is_some() {
        serial::write_line("WOLFOS_PAGING_ERROR test address already mapped");
        return false;
    }

    let before = pmm::statistics();
    let Some(data_phys) = pmm::allocate_frame() else {
        serial::write_line("WOLFOS_PAGING_ERROR no free frame");
        return false;
    };
    let data_frame = PhysFrame::containing_address(PhysAddr::new(data_phys));
    let mut tables = TableFrameAllocator { allocated: 0 };
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    // SAFETY: page was verified unmapped. The data frame belongs to PMM and
    // is not used in another virtual mapping managed by WolfOS. We allocate
    // fresh page-table frames as needed; they remain owned by active CR3.
    let mapped = unsafe { mapper.map_to(page, data_frame, flags, &mut tables) };
    let Ok(flush) = mapped else {
        serial::write_line("WOLFOS_PAGING_ERROR map_to failed");
        return false; // fatal to test: boot caller halts; no reuse of frames
    };
    flush.flush();

    if mapper.translate_addr(target).map(|p| p.as_u64()) != Some(data_phys) {
        serial::write_line("WOLFOS_PAGING_ERROR translation mismatch");
        return false;
    }

    // SAFETY: mapping is present and writable; exactly one u64 fits in page.
    unsafe {
        let pointer = target.as_mut_ptr::<u64>();
        pointer.write_volatile(MAGIC);
        if pointer.read_volatile() != MAGIC {
            serial::write_line("WOLFOS_PAGING_ERROR read/write mismatch");
            return false;
        }
    }
    serial::write_fmt(format_args!(
        "WOLFOS_PAGING_MAP_OK va={:#x} phys={:#x} table_frames={}\n",
        TEST_VIRTUAL_ADDRESS, data_phys, tables.allocated
    ));

    let Ok((unmapped, flush)) = mapper.unmap(page) else {
        serial::write_line("WOLFOS_PAGING_ERROR unmap failed");
        return false;
    };
    flush.flush(); // invalidates TLB entry for the virtual page

    if unmapped.start_address().as_u64() != data_phys
        || mapper.translate_addr(target).is_some()
    {
        serial::write_line("WOLFOS_PAGING_ERROR stale mapping after unmap");
        return false;
    }

    // Safe to return only the data frame: intermediate page-table frames
    // remain in the active address space. Reclamation comes in a later PR.
    if pmm::free_frame(data_phys).is_err() {
        serial::write_line("WOLFOS_PAGING_ERROR frame release failed");
        return false;
    }
    let after = pmm::statistics();
    if after.allocated_frames != before.allocated_frames + tables.allocated {
        serial::write_line("WOLFOS_PAGING_ERROR frame ownership mismatch");
        return false;
    }
    serial::write_line("WOLFOS_PAGING_UNMAP_OK");
    true
}

#[cfg(feature = "paging-fault-smoke")]
pub fn trigger_unmapped_read() -> ! {
    serial::write_line("WOLFOS_PAGING_FAULT_TEST_BEGIN");
    // SAFETY: privileged QEMU-only negative test. Use assembly instead of an
    // invalid Rust pointer read (which could cause undefined behavior).
    // Target was unmapped and TLB flushed by mapping_roundtrip().
    unsafe {
        asm!(
            "mov rax, qword ptr [rax]",
            inout("rax") TEST_VIRTUAL_ADDRESS => _,
            options(nostack, readonly, preserves_flags)
        );
    }
    serial::write_line("WOLFOS_PAGING_FAULT_TEST_FAILED no fault");
    crate::halt_forever()
}
