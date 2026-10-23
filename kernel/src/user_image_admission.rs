//! Fail-closed, allocation-free admission of a *disconnected* ELF shadow image.
//!
//! Combines three previously independent proofs: exact ELF-to-PTE binding,
//! every file/BSS byte in each staged backing page, and a zeroed NX stack.
//! The caller must derive each byte slice from the stated PMM frame through
//! its trusted HHDM mapping, hold exclusive ownership, and keep ELF bytes
//! immutable while this audit runs. Rust references alone cannot prove a
//! supplied physical address matches an arbitrary borrowed slice.
//! No CR3 switch, process publication, or CPL3 execution occurs here.

use crate::elf64_page_image::{
    audit_materialized_batch, audit_zeroed_stack, PageAuditError, PAGE_SIZE,
};
use crate::elf64_preflight::ImagePlan;
use crate::user_vm_layout::ENTRY_COUNT;
use crate::user_vm_multi::{self, ElfBindingError, UserPage, TABLE_FRAMES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Mapping(ElfBindingError),
    BackingCount,
    BackingMismatch,
    HhdmMismatch,
    FileBytes(PageAuditError),
    StackBytes(usize),
}

/// A caller-owned, HHDM-derived immutable view of one staged PMM frame.
#[derive(Clone, Copy)]
pub struct BackingPage<'a> {
    pub virtual_address: u64,
    pub physical_frame: u64,
    pub bytes: &'a [u8; PAGE_SIZE],
}

/// Check the complete four-level shadow PTE layout, every ELF-backed page
/// (including full BSS leaves), and the distinct, entirely zeroed user stack.
/// Missing/extra/duplicate/wrong-frame backing entries are rejected even when
/// individual page contents are valid. Never mutates any supplied memory.
pub fn audit_staged_image(
    image: &[u8],
    stack_virtual: u64,
    tables: [u64; TABLE_FRAMES],
    mapped: &[UserPage],
    pml4: &[u64; ENTRY_COUNT],
    pdpt: &[u64; ENTRY_COUNT],
    pd: &[u64; ENTRY_COUNT],
    pt: &[u64; ENTRY_COUNT],
    file_backings: &[BackingPage<'_>],
    stack: BackingPage<'_>,
) -> Result<ImagePlan, AdmissionError> {
    let plan = user_vm_multi::audit_elf_bindings(
        image, stack_virtual, pml4, pdpt, pd, pt, tables, mapped,
    ).map_err(AdmissionError::Mapping)?;

    if file_backings.len().checked_add(1) != Some(mapped.len()) {
        return Err(AdmissionError::BackingCount);
    }
    let Some(stack_leaf) = mapped.iter()
        .find(|page| page.virtual_address == stack_virtual)
    else { return Err(AdmissionError::BackingMismatch) };
    if stack.virtual_address != stack_virtual
        || stack.physical_frame != stack_leaf.physical_frame
    {
        return Err(AdmissionError::BackingMismatch);
    }

    for (i, backing) in file_backings.iter().enumerate() {
        if backing.virtual_address == stack_virtual
            || core::ptr::eq(backing.bytes, stack.bytes)
            || file_backings[..i].iter().any(|earlier|
                earlier.virtual_address == backing.virtual_address
                    || core::ptr::eq(earlier.bytes, backing.bytes))
        {
            return Err(AdmissionError::BackingMismatch);
        }
        let Some(leaf) = mapped.iter()
            .find(|page| page.virtual_address == backing.virtual_address)
        else { return Err(AdmissionError::BackingMismatch) };
        if leaf.physical_frame != backing.physical_frame {
            return Err(AdmissionError::BackingMismatch);
        }
        let Some(segment) = plan.segments[..plan.len].iter().flatten()
            .find(|seg| backing.virtual_address >= seg.page_start
                && backing.virtual_address < seg.page_end)
        else { return Err(AdmissionError::BackingMismatch) };

        audit_materialized_batch(
            image, [(segment, backing.virtual_address)], [backing.bytes],
        ).map_err(AdmissionError::FileBytes)?;
    }
    audit_zeroed_stack(stack.bytes).map_err(AdmissionError::StackBytes)?;
    Ok(plan)
}

/// A kernel-side provenance check for the physical-to-virtual byte view.
/// The caller still owns/pins the PMM frames: this validates the actual
/// reference pointer address is EXACTLY HHDM + its asserted physical frame.
/// It does not independently inspect page ownership in PMM metadata.
fn matches_hhdm(hhdm: u64, frame: u64, pointer: u64) -> bool {
    const HIGH_HALF: u64 = 0xffff_8000_0000_0000;
    hhdm >= HIGH_HALF && hhdm & 4095 == 0
        && frame != 0 && frame & 4095 == 0 && frame < (1 << 52)
        && hhdm.checked_add(frame) == Some(pointer)
}

pub fn audit_hhdm_backings(
    hhdm: u64,
    files: &[BackingPage<'_>],
    stack: BackingPage<'_>,
) -> Result<(), AdmissionError> {
    if files.iter().chain(core::iter::once(&stack)).any(|backing|
        !matches_hhdm(hhdm, backing.physical_frame, backing.bytes.as_ptr() as u64)
    ) {
        return Err(AdmissionError::HhdmMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provenance_rejects_wrong_frame_high_half_and_overflow() {
        let base = 0xffff_8000_0000_0000;
        assert!(matches_hhdm(base, 0x4000, base + 0x4000));
        assert!(!matches_hhdm(base, 0x4000, base + 0x5000));
        assert!(!matches_hhdm(0, 0x4000, 0x4000));
        assert!(!matches_hhdm(base + 1, 0x4000, base + 0x4001));
        assert!(!matches_hhdm(u64::MAX & !4095, 0x4000, 0x3000));
        assert!(!matches_hhdm(base, 0, base));
        assert!(!matches_hhdm(base, 0x4001, base + 0x4001));
    }
}
