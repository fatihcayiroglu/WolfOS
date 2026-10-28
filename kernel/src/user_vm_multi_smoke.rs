//! Additional P2 QEMU acceptance: four heterogeneous user pages in the
//! SAME disconnected PML4/PDPT/PD/PT hierarchy, backed by eight distinct
//! PMM frames. Two ELF text/BSS pages, one ELF data page and one stack page.
//! Real byte copy / BSS zeroing occurs through supervisor HHDM only.
//! We never write CR3, enter CPL3 or execute any ELF file.

use crate::{
    elf64_preflight::preflight,
    elf64_page_image::{materialize_batch, audit_materialized_batch, audit_zeroed_stack, PageAuditError, PAGE_SIZE},
    kernel_half_shadow, pmm, serial, user_image_admission::{self, BackingPage},
    pmm_frame_batch::{FrameBatch, FrameSource, AcquireError, ReleaseReport},
    user_vm_layout::ENTRY_COUNT,
    user_vm_multi::{self, UserPage},
    user_vm_two_pt,
    user_elf_launch_layout::{plan_static_image, plan_two_pt_image},
};
use x86_64::{registers::control::Cr3, VirtAddr};

const FRAME_TOTAL: usize = 8;
const TABLES: usize = 4;
const TEXT: u64 = 0x401000;
const TEXT_BSS: u64 = 0x402000;
const DATA: u64 = 0x403000;
const STACK: u64 = 0x404000;

struct RealPmm {
    remaining: usize,
}

impl FrameSource for RealPmm {
    fn allocate(&mut self) -> Option<u64> {
        if self.remaining == 0 { return None; }
        let frame = pmm::allocate_frame()?;
        self.remaining -= 1;
        Some(frame)
    }

    fn release(&mut self, frame: u64) -> bool {
        pmm::free_frame(frame).is_ok()
    }
}


fn put16(b: &mut [u8], pos: usize, val: u16) {
    b[pos..pos + 2].copy_from_slice(&val.to_le_bytes());
}
fn put32(b: &mut [u8], pos: usize, val: u32) {
    b[pos..pos + 4].copy_from_slice(&val.to_le_bytes());
}
fn put64(b: &mut [u8], pos: usize, val: u64) {
    b[pos..pos + 8].copy_from_slice(&val.to_le_bytes());
}

fn fixture() -> [u8; 512] {
    let mut b = [0u8; 512];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4..7].copy_from_slice(&[2, 1, 1]);
    put16(&mut b, 16, 2); // ET_EXEC
    put16(&mut b, 18, 62); // EM_X86_64
    put32(&mut b, 20, 1);
    put64(&mut b, 24, 0x401100); // executable file bytes
    put64(&mut b, 32, 64); // program header table
    put16(&mut b, 52, 64);
    put16(&mut b, 54, 56);
    put16(&mut b, 56, 2);

    put32(&mut b, 64, 1); // PT_LOAD text
    put32(&mut b, 68, 5); // R + X
    put64(&mut b, 72, 0x100);
    put64(&mut b, 80, 0x401100);
    put64(&mut b, 96, 8);
    put64(&mut b, 104, 0x1000); // spans TWO pages, mostly BSS
    put64(&mut b, 112, 0x1000);

    put32(&mut b, 120, 1); // PT_LOAD data
    put32(&mut b, 124, 6); // R + W
    put64(&mut b, 128, 0x180);
    put64(&mut b, 136, 0x403180);
    put64(&mut b, 152, 8);
    put64(&mut b, 160, 0x600);
    put64(&mut b, 168, 0x1000);
    b[0x100] = 0xc3;
    b[0x180..0x188].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    b
}

fn prove(hhdm: u64, frames: &[u64; FRAME_TOTAL]) -> bool {
    let file = fixture();
    let Ok(plan) = preflight(&file) else { return false; };
    if plan.len != 2 || plan.entry != 0x401100 { return false; }
    let Some(text) = plan.segments[0] else { return false; };
    let Some(data) = plan.segments[1] else { return false; };
    if text.page_start != TEXT || text.page_end != DATA
        || data.page_start != DATA || data.page_end != STACK
        || text.writable || !text.executable || !data.writable || data.executable
    { return false; }

    let mut pointers = [core::ptr::null_mut::<u8>(); FRAME_TOTAL];
    for (i, physical) in frames.iter().copied().enumerate() {
        let Some(vaddr) = hhdm.checked_add(physical)
            .and_then(|value| VirtAddr::try_new(value).ok())
        else { return false; };
        pointers[i] = vaddr.as_mut_ptr::<u8>();
    }
    let pages = [
        UserPage { virtual_address: TEXT, physical_frame: frames[4],
            writable: false, executable: true },
        UserPage { virtual_address: TEXT_BSS, physical_frame: frames[5],
            writable: false, executable: true },
        UserPage { virtual_address: DATA, physical_frame: frames[6],
            writable: true, executable: false },
        UserPage { virtual_address: STACK, physical_frame: frames[7],
            writable: true, executable: false },
    ];
    // Authenticate the *exact* ELF PT_LOAD RX/BSS/RW pages and the
    // proposed RW+NX user stack against every eventual shadow-root PTE
    // BEFORE zeroing frame buffers or writing a table entry.
    if user_vm_multi::validate_elf_bindings(
        &file, STACK, [frames[0], frames[1], frames[2], frames[3]], &pages,
    ) != Ok(plan) { return false; }
    let mut bad = pages;
    bad[1].writable = true; // RX/BSS cannot silently become RWX.
    if user_vm_multi::validate_elf_bindings(
        &file, STACK, [frames[0], frames[1], frames[2], frames[3]], &bad,
    ).is_ok() { return false; }
    bad = pages;
    bad[2].virtual_address = TEXT_BSS; // duplicate RX virtual leaf.
    if user_vm_multi::validate_elf_bindings(
        &file, STACK, [frames[0], frames[1], frames[2], frames[3]], &bad,
    ).is_ok() { return false; }
    // All rejected PTE proposals leave the already allocated PMM frame
    // counts and all candidate page-table/data buffers untouched.

    // SAFETY: eight separately owned and HHDM-mapped PMM physical frames.
    // These pointers are disjoint, never exposed to another CPU and stay
    // owned until this synchronous proof finishes and PMM frees them.
    unsafe {
        for ptr in pointers { core::ptr::write_bytes(ptr, 0xa5, PAGE_SIZE); }
        // Page-table creation demands four pristine, disjoint tables.
        for ptr in &pointers[..TABLES] {
            core::ptr::write_bytes(*ptr, 0, PAGE_SIZE);
        }
        let root = &mut *pointers[0].cast::<[u64; ENTRY_COUNT]>();
        let pdpt = &mut *pointers[1].cast::<[u64; ENTRY_COUNT]>();
        let pd = &mut *pointers[2].cast::<[u64; ENTRY_COUNT]>();
        let pt = &mut *pointers[3].cast::<[u64; ENTRY_COUNT]>();
        if user_vm_multi::populate(root, pdpt, pd, pt,
            [frames[0], frames[1], frames[2], frames[3]], &pages).is_err()
        { return false; }
        // Audit the physical shadow PTE bytes against fresh ELF byte
        // preflight, including the actual RX, RW+NX and stack flags.
        // This is still a disconnected root; hardware CR3 is unchanged.
        if user_vm_multi::audit_elf_bindings(
            &file, STACK, root, pdpt, pd, pt,
            [frames[0], frames[1], frames[2], frames[3]], &pages,
        ).is_err() || root[256..].iter().any(|p| *p != 0)
        { return false; }

        let first = &mut *pointers[4].cast::<[u8; PAGE_SIZE]>();
        let second = &mut *pointers[5].cast::<[u8; PAGE_SIZE]>();
        let third = &mut *pointers[6].cast::<[u8; PAGE_SIZE]>();
        let fourth = &mut *pointers[7].cast::<[u8; PAGE_SIZE]>();
        // Validate all three PT_LOAD pages before changing ANY HHDM
        // buffer. The separate stack page stays zero-only and unexecutable.
        if materialize_batch(
            &file,
            [(&text, TEXT), (&text, TEXT_BSS), (&data, DATA)],
            [first, second, third],
        ).is_err() { return false; }
        fourth.fill(0); // new zeroed stack, with no ELF file backing.

        // Observe the real four PMM data-frame buffers before any
        // hardware CR3 load. All file bytes, zeroed BSS/tails and stack
        // contents must match the validated ELF and zero-stack contract.
        let loads = [(&text, TEXT), (&text, TEXT_BSS), (&data, DATA)];
        if audit_materialized_batch(
            &file, loads, [&*first, &*second, &*third],
        ).is_err() || audit_zeroed_stack(fourth).is_err() {
            return false;
        }
        let original_text = first[0x100];
        first[0x100] ^= 1;
        let text_rejected = matches!(
            audit_materialized_batch(
                &file, loads, [&*first, &*second, &*third],
            ),
            Err(PageAuditError::ContentMismatch {
                index: 0, offset: 0x100,
            }),
        );
        first[0x100] = original_text;
        second[23] = 0xa5;
        let bss_rejected = matches!(
            audit_materialized_batch(
                &file, loads, [&*first, &*second, &*third],
            ),
            Err(PageAuditError::ContentMismatch {
                index: 1, offset: 23,
            }),
        );
        second[23] = 0;
        third[0x180] ^= 1;
        let data_rejected = matches!(
            audit_materialized_batch(
                &file, loads, [&*first, &*second, &*third],
            ),
            Err(PageAuditError::ContentMismatch {
                index: 2, offset: 0x180,
            }),
        );
        third[0x180] ^= 1;
        fourth[11] = 0x5a;
        let stack_rejected = audit_zeroed_stack(fourth) == Err(11);
        fourth[11] = 0;
        if !text_rejected || !bss_rejected
            || !data_rejected || !stack_rejected
            || audit_materialized_batch(
                &file, loads, [&*first, &*second, &*third],
            ).is_err()
            || audit_zeroed_stack(fourth).is_err()
        {
            return false;
        }


        // Complete pre-handoff audit: actual shadow PTE byte layout,
        // ALL PT_LOAD page coverage, exact PMM bytes, and zeroed user stack.
        // Still disconnected, with no CR3 write or IRET execution.
        if user_vm_multi::audit_ready_elf_image(
            &file, STACK,
            [frames[0], frames[1], frames[2], frames[3]],
            &pages, root, pdpt, pd, pt,
            loads, [&*first, &*second, &*third], fourth,
        ) != Ok(plan) { return false; }

        // Stronger physical provenance: each byte borrow must point to its
        // OWN HHDM-mapped PMM frame, not a swapped caller-owned buffer.
        // The independent ready_image_gate above already verified the ELF
        // plan and exact PTE flags; this gate binds frame identity to bytes.
        let file_backings = [
            BackingPage { virtual_address: TEXT,
                physical_frame: frames[4], bytes: &*first },
            BackingPage { virtual_address: TEXT_BSS,
                physical_frame: frames[5], bytes: &*second },
            BackingPage { virtual_address: DATA,
                physical_frame: frames[6], bytes: &*third },
        ];
        let stack_backing = BackingPage { virtual_address: STACK,
            physical_frame: frames[7], bytes: &*fourth };
        if user_image_admission::audit_hhdm_backings(
            hhdm, &file_backings, stack_backing,
        ).is_err() || user_image_admission::audit_staged_image(
            &file, STACK, [frames[0], frames[1], frames[2], frames[3]],
            &pages, root, pdpt, pd, pt,
            &file_backings, stack_backing,
        ) != Ok(plan) { return false; }

        // Snapshot the actual live Limine PML4 via HHDM WITHOUT modifying it.
        // The new root's four page tables are private PMM frames, while the
        // kernel upper half intentionally shares the live boot paging trees.
        // No CR3 switch, so boot code continues using the original mappings.
        let active_pml4_phys = Cr3::read().0.start_address().as_u64();
        let Some(active_pml4_ptr) = hhdm.checked_add(active_pml4_phys)
            .and_then(|value| VirtAddr::try_new(value).ok())
        else { return false; };
        // SAFETY: the Limine HHDM maps active CR3's PML4. Only BSP executes
        // this test with maskable IRQs off and before any AP starts; the
        // source is read-only, private target PML4 is a distinct PMM frame.
        let active = &*active_pml4_ptr.as_ptr::<[u64; ENTRY_COUNT]>();
        let old_user_entry = root[0];
        let copied = kernel_half_shadow::graft_kernel_half(
            active, root, 0, old_user_entry, frames,
        );
        let audited = kernel_half_shadow::audit_kernel_half(
            active, root, 0, old_user_entry, frames,
        );
        let kernel_va = crate::kmain as usize as u64;
        let kernel_idx = ((kernel_va >> 39) & 511) as usize;
        let hhdm_idx = ((hhdm >> 39) & 511) as usize;
        if !matches!(copied, Ok(n) if n >= 1)
            || copied != audited
            || kernel_idx < 256 || hhdm_idx < 256
            || active[kernel_idx] & 1 == 0
            || active[hhdm_idx] & 1 == 0
            || root[kernel_idx] != (active[kernel_idx] & !kernel_half_shadow::PTE_USER)
            || root[hhdm_idx] != (active[hhdm_idx] & !kernel_half_shadow::PTE_USER)
            || root[kernel_idx] & kernel_half_shadow::PTE_USER != 0
            || root[hhdm_idx] & kernel_half_shadow::PTE_USER != 0
        {
            serial::write_fmt(format_args!(
                "WOLFOS_USER_GRAFT_DIAG copied={copied:?} audit={audited:?} kernel_idx={} kernel_entry={:#x} hhdm_idx={} hhdm_entry={:#x} user_entry={:#x}\n",
                kernel_idx, active[kernel_idx], hhdm_idx, active[hhdm_idx], old_user_entry,
            ));
            return false;
        }

        first[0x100] == 0xc3
            && first.iter().enumerate().all(|(i, b)| *b == if i == 0x100 { 0xc3 } else { 0 })
            && second.iter().all(|b| *b == 0)
            && third[..0x180].iter().all(|b| *b == 0)
            && third[0x180..0x188] == [1, 2, 3, 4, 5, 6, 7, 8]
            && third[0x188..].iter().all(|b| *b == 0)
            && fourth.iter().all(|b| *b == 0)
    }
}

/// Real-PMM-backed SECOND disconnected proof. The SAME eight exclusively
/// owned frames are reused only after the preceding one-PT audit returned.
/// Here frames[0..5] are five table frames; frames[5..8] are RX/RW/stack.
/// The new high-half graft never activates CR3 or runs any user bytes; no disk I/O.
fn prove_two_pt(hhdm: u64, frames: &[u64; FRAME_TOTAL]) -> bool {
    let mut file = fixture();
    // Independently derive two LOAD pages straddling exactly 0x600000.
    put64(&mut file, 24, 0x5ff100);
    put64(&mut file, 80, 0x5ff100);
    put64(&mut file, 104, 0xf00);
    put64(&mut file, 136, 0x600180);
    put64(&mut file, 160, 0xe80);
    if plan_static_image(&file).is_ok() { return false; }
    let Ok(layout) = plan_two_pt_image(&file) else { return false };
    if layout.len != 3 || layout.stack_page != 0x601000 {
        return false;
    }
    let Some(text) = layout.image.segments[0] else { return false };
    let Some(data) = layout.image.segments[1] else { return false };
    let pages = [
        UserPage { virtual_address: 0x5ff000, physical_frame: frames[5],
            writable: false, executable: true },
        UserPage { virtual_address: 0x600000, physical_frame: frames[6],
            writable: true, executable: false },
        UserPage { virtual_address: 0x601000, physical_frame: frames[7],
            writable: true, executable: false },
    ];
    let table_frames: [u64; user_vm_two_pt::TABLE_FRAMES] =
        [frames[0], frames[1], frames[2], frames[3], frames[4]];
    if user_vm_two_pt::validate_elf_bindings(&file, table_frames, &pages)
        != Ok(layout)
    {
        return false;
    }
    let mut pointers = [core::ptr::null_mut::<u8>(); FRAME_TOTAL];
    for (i, physical) in frames.iter().copied().enumerate() {
        let Some(vaddr) = hhdm.checked_add(physical)
            .and_then(|value| VirtAddr::try_new(value).ok())
        else { return false; };
        pointers[i] = vaddr.as_mut_ptr::<u8>();
    }
    // SAFETY: every PMM frame remains pinned, disjoint, kernel-HHDM mapped,
    // and not reachable from an active CR3. No other CPU has these pointers.
    unsafe {
        for ptr in pointers { core::ptr::write_bytes(ptr, 0, PAGE_SIZE); }
        let root = &mut *pointers[0].cast::<[u64; ENTRY_COUNT]>();
        let pdpt = &mut *pointers[1].cast::<[u64; ENTRY_COUNT]>();
        let pd = &mut *pointers[2].cast::<[u64; ENTRY_COUNT]>();
        let pt0 = &mut *pointers[3].cast::<[u64; ENTRY_COUNT]>();
        let pt1 = &mut *pointers[4].cast::<[u64; ENTRY_COUNT]>();
        if user_vm_two_pt::populate(
            root, pdpt, pd, pt0, pt1, table_frames, &pages,
        ).is_err() { return false; }
        if user_vm_two_pt::audit_elf_bindings(
            &file, root, pdpt, pd, pt0, pt1, table_frames, &pages,
        ) != Ok(layout)
            || root[256..].iter().any(|entry| *entry != 0)
        {
            return false;
        }
        let text_page = &mut *pointers[5].cast::<[u8; PAGE_SIZE]>();
        let data_page = &mut *pointers[6].cast::<[u8; PAGE_SIZE]>();
        let stack_page = &mut *pointers[7].cast::<[u8; PAGE_SIZE]>();
        let requests = [(&text, 0x5ff000), (&data, 0x600000)];
        if materialize_batch(&file, requests, [&mut *text_page, &mut *data_page]).is_err()
            || audit_materialized_batch(
                &file, requests, [&*text_page, &*data_page],
            ).is_err()
            || audit_zeroed_stack(stack_page).is_err()
        {
            return false;
        }
        let original = data_page[0x180];
        data_page[0x180] ^= 1;
        let tamper_rejected = matches!(
            audit_materialized_batch(&file, requests, [&*text_page, &*data_page]),
            Err(PageAuditError::ContentMismatch { index: 1, offset: 0x180 }),
        );
        data_page[0x180] = original;
        let original_pte = pt1[0];
        pt1[0] &= !crate::user_vm_layout::NX; // data may never become executable
        let pte_rejected = user_vm_two_pt::audit(
            root, pdpt, pd, pt0, pt1, table_frames, &pages,
        ).is_err();
        pt1[0] = original_pte;

        // Deliberately corrupt staged RW ELF data and require the full
        // two-PT admission gate to reject the bytes, then restore them
        // BEFORE constructing the long-lived immutable frame borrows.
        data_page[0x180] ^= 1;
        let admission_tamper_denied = {
            let corrupt_files = [
                BackingPage { virtual_address: 0x5ff000,
                    physical_frame: frames[5], bytes: &*text_page },
                BackingPage { virtual_address: 0x600000,
                    physical_frame: frames[6], bytes: &*data_page },
            ];
            let corrupt_stack = BackingPage { virtual_address: 0x601000,
                physical_frame: frames[7], bytes: &*stack_page };
            matches!(
                user_image_admission::audit_two_pt_staged_image(
                    &file, table_frames, &pages,
                    root, pdpt, pd, pt0, pt1,
                    &corrupt_files, corrupt_stack,
                ),
                Err(user_image_admission::TwoPtAdmissionError::FileBytes(
                    PageAuditError::ContentMismatch { index: 0, offset: 0x180 },
                )),
            )
        };
        data_page[0x180] ^= 1;

        let file_backings = [
            BackingPage { virtual_address: 0x5ff000,
                physical_frame: frames[5], bytes: &*text_page },
            BackingPage { virtual_address: 0x600000,
                physical_frame: frames[6], bytes: &*data_page },
        ];
        let stack_backing = BackingPage {
            virtual_address: 0x601000,
            physical_frame: frames[7], bytes: &*stack_page,
        };
        // The all-in-one two-PT admission must bind the same authentic ELF,
        // all five actual shadow tables and every individual PMM backing.
        let ready = user_image_admission::audit_two_pt_staged_image(
            &file, table_frames, &pages,
            root, pdpt, pd, pt0, pt1,
            &file_backings, stack_backing,
        ) == Ok(layout)
            && user_image_admission::audit_hhdm_backings(
                hhdm, &file_backings, stack_backing,
            ).is_ok();

        if !ready || !admission_tamper_denied
            || user_image_admission::audit_two_pt_staged_image(
                &file, table_frames, &pages,
                root, pdpt, pd, pt0, pt1,
                &file_backings, stack_backing,
            ) != Ok(layout)
        {
            return false;
        }

        // The shadow hierarchy is still disconnected. Inherit a verified
        // supervisor-only high-half from the original *active* Limine root;
        // no CR3 switch, TSS edit, IRET or user execution is performed.
        let active_pml4_phys = Cr3::read().0.start_address().as_u64();
        let Some(active_pml4_ptr) = hhdm.checked_add(active_pml4_phys)
            .and_then(|value| VirtAddr::try_new(value).ok())
        else { return false };
        let active = &*active_pml4_ptr.as_ptr::<[u64; ENTRY_COUNT]>();
        let user_root_entry = root[0];
        let copied = kernel_half_shadow::graft_kernel_half(
            active, root, 0, user_root_entry, frames,
        );
        let audited = kernel_half_shadow::audit_kernel_half(
            active, root, 0, user_root_entry, frames,
        );
        let kernel_idx = ((crate::kmain as usize as u64 >> 39) & 511) as usize;
        let hhdm_idx = ((hhdm >> 39) & 511) as usize;
        if !matches!(copied, Ok(n) if n >= 1)
            || copied != audited || kernel_idx < 256 || hhdm_idx < 256
            || active[kernel_idx] & 1 == 0 || active[hhdm_idx] & 1 == 0
            || root[kernel_idx] != (active[kernel_idx] & !kernel_half_shadow::PTE_USER)
            || root[hhdm_idx] != (active[hhdm_idx] & !kernel_half_shadow::PTE_USER)
            || root[kernel_idx] & kernel_half_shadow::PTE_USER != 0
            || root[hhdm_idx] & kernel_half_shadow::PTE_USER != 0
        {
            return false;
        }
        let trusted_hhdm_entry = root[hhdm_idx];
        root[hhdm_idx] |= kernel_half_shadow::PTE_USER;
        let escalation_denied = matches!(
            kernel_half_shadow::audit_kernel_half(
                active, root, 0, user_root_entry, frames,
            ),
            Err(kernel_half_shadow::GraftError::UserAccessibleKernel),
        );
        root[hhdm_idx] = trusted_hhdm_entry;
        let repaired = kernel_half_shadow::audit_kernel_half(
            active, root, 0, user_root_entry, frames,
        ) == copied;

        tamper_rejected && pte_rejected && admission_tamper_denied
            && ready && escalation_denied && repaired
            && audit_materialized_batch(
                &file, requests, [&*text_page, &*data_page],
            ).is_ok()
            && audit_zeroed_stack(stack_page).is_ok()
            && text_page[0x100] == 0xc3
            && data_page[0x180..0x188] == [1, 2, 3, 4, 5, 6, 7, 8]
    }
}

/// A THIRD, independent real-PMM proof: the identical two-PT ELF is
/// relocated into an actually vacant nonzero user PML4 slot, just as the
/// existing live Ring3 launcher selects its address-space slot. It is still
/// a disconnected shadow: no new CR3/IRET path is executed here.
fn prove_relocated_two_pt(hhdm: u64, frames: &[u64; FRAME_TOTAL]) -> bool {
    let mut file = fixture();
    put64(&mut file, 24, 0x5ff100);
    put64(&mut file, 80, 0x5ff100);
    put64(&mut file, 104, 0xf00);
    put64(&mut file, 136, 0x600180);
    put64(&mut file, 160, 0xe80);

    let active_physical = Cr3::read().0.start_address().as_u64();
    let Some(active_ptr) = hhdm.checked_add(active_physical)
        .and_then(|value| VirtAddr::try_new(value).ok())
    else { return false };
    // SAFETY: IF=0, BSP-only, active Limine root is HHDM mapped. The
    // borrowed live PML4 is never modified by this proof.
    let active = unsafe { &*active_ptr.as_ptr::<[u64; ENTRY_COUNT]>() };
    let Some(slot) = (1..256).find(|s| active[*s] == 0)
    else { return false };
    let base = (slot as u64) << 39;
    let pages = [
        UserPage { virtual_address: base + 0x5ff000,
            physical_frame: frames[5], writable: false, executable: true },
        UserPage { virtual_address: base + 0x600000,
            physical_frame: frames[6], writable: true, executable: false },
        UserPage { virtual_address: base + 0x601000,
            physical_frame: frames[7], writable: true, executable: false },
    ];
    let table_frames = [frames[0], frames[1], frames[2], frames[3], frames[4]];
    let Ok(layout) = user_vm_two_pt::validate_relocated_elf_bindings(
        &file, slot, table_frames, &pages,
    ) else { return false };
    if layout.stack_page != base + 0x601000
        || layout.entry != base + 0x5ff100
        || layout.source.len != 3
    { return false }

    let mut pointers = [core::ptr::null_mut::<u8>(); FRAME_TOTAL];
    for (i, physical) in frames.iter().copied().enumerate() {
        let Some(vaddr) = hhdm.checked_add(physical)
            .and_then(|value| VirtAddr::try_new(value).ok())
        else { return false };
        pointers[i] = vaddr.as_mut_ptr::<u8>();
    }
    // SAFETY: all eight PMM frames remain exclusively owned by this
    // synchronous, IF=0 BSP smoke. None belongs to the live CR3 root.
    unsafe {
        for ptr in pointers { core::ptr::write_bytes(ptr, 0, PAGE_SIZE); }
        let root = &mut *pointers[0].cast::<[u64; ENTRY_COUNT]>();
        let pdpt = &mut *pointers[1].cast::<[u64; ENTRY_COUNT]>();
        let pd = &mut *pointers[2].cast::<[u64; ENTRY_COUNT]>();
        let pt0 = &mut *pointers[3].cast::<[u64; ENTRY_COUNT]>();
        let pt1 = &mut *pointers[4].cast::<[u64; ENTRY_COUNT]>();
        if user_vm_two_pt::populate(
            root, pdpt, pd, pt0, pt1, table_frames, &pages,
        ).is_err() || user_vm_two_pt::audit_relocated_elf_bindings(
            &file, slot, root, pdpt, pd, pt0, pt1, table_frames, &pages,
        ) != Ok(layout)
        { return false }

        let text_page = &mut *pointers[5].cast::<[u8; PAGE_SIZE]>();
        let data_page = &mut *pointers[6].cast::<[u8; PAGE_SIZE]>();
        let stack_page = &mut *pointers[7].cast::<[u8; PAGE_SIZE]>();
        let Some(text) = layout.source.image.segments[0] else { return false };
        let Some(data) = layout.source.image.segments[1] else { return false };
        let requests = [(&text, 0x5ff000), (&data, 0x600000)];
        // NOTE: ELF byte offsets are derived from SOURCE virtual addresses.
        // Only PTE lookup, RIP and RSP use the base-relocated address.
        if materialize_batch(
            &file, requests, [&mut *text_page, &mut *data_page],
        ).is_err() || audit_zeroed_stack(stack_page).is_err()
        { return false }

        data_page[0x180] ^= 1;
        let rejected = {
            let files = [
                BackingPage { virtual_address: pages[0].virtual_address,
                    physical_frame: frames[5], bytes: &*text_page },
                BackingPage { virtual_address: pages[1].virtual_address,
                    physical_frame: frames[6], bytes: &*data_page },
            ];
            let stack = BackingPage { virtual_address: pages[2].virtual_address,
                physical_frame: frames[7], bytes: &*stack_page };
            matches!(
                user_image_admission::audit_relocated_two_pt_staged_image(
                    &file, slot, table_frames, &pages,
                    root, pdpt, pd, pt0, pt1, &files, stack,
                ),
                Err(user_image_admission::TwoPtAdmissionError::FileBytes(
                    PageAuditError::ContentMismatch { index: 0, offset: 0x180 },
                )),
            )
        };
        data_page[0x180] ^= 1;
        let files = [
            BackingPage { virtual_address: pages[0].virtual_address,
                physical_frame: frames[5], bytes: &*text_page },
            BackingPage { virtual_address: pages[1].virtual_address,
                physical_frame: frames[6], bytes: &*data_page },
        ];
        let stack = BackingPage { virtual_address: pages[2].virtual_address,
            physical_frame: frames[7], bytes: &*stack_page };
        let admitted = user_image_admission::audit_relocated_two_pt_staged_image(
            &file, slot, table_frames, &pages,
            root, pdpt, pd, pt0, pt1, &files, stack,
        ) == Ok(layout)
            && user_image_admission::audit_hhdm_backings(
                hhdm, &files, stack,
            ).is_ok();
        if !admitted || !rejected || root[0] != 0
            || root[slot] & (kernel_half_shadow::PTE_USER | 1)
                != (kernel_half_shadow::PTE_USER | 1)
        { return false }

        let user_entry = root[slot];
        let copied = kernel_half_shadow::graft_kernel_half(
            active, root, slot, user_entry, frames,
        );
        let kernel_idx = ((crate::kmain as usize as u64 >> 39) & 511) as usize;
        let hhdm_idx = ((hhdm >> 39) & 511) as usize;
        matches!(copied, Ok(n) if n > 0)
            && kernel_half_shadow::audit_kernel_half(
                active, root, slot, user_entry, frames,
            ) == copied
            && kernel_idx >= 256 && hhdm_idx >= 256
            && root[kernel_idx] == (active[kernel_idx] & !kernel_half_shadow::PTE_USER)
            && root[hhdm_idx] == (active[hhdm_idx] & !kernel_half_shadow::PTE_USER)
            && root[kernel_idx] & kernel_half_shadow::PTE_USER == 0
            && root[hhdm_idx] & kernel_half_shadow::PTE_USER == 0
            && text_page[0x100] == 0xc3
            && data_page[0x180..0x188] == [1, 2, 3, 4, 5, 6, 7, 8]
            && audit_zeroed_stack(stack_page).is_ok()
    }
}

pub fn verify(hhdm: u64) -> bool {
    let before = pmm::statistics().allocated_frames;
    let (cr3, _) = Cr3::read();
    let cr3_before = cr3.start_address().as_u64();

    // Real PMM fault injection: the fourth requested frame is unavailable.
    // All three already-owned frames MUST be returned before the caller can
    // proceed, and the PMM live-allocation counter must be unchanged.
    let mut limited = RealPmm { remaining: 3 };
    let rollback = matches!(
        FrameBatch::<_, FRAME_TOTAL>::acquire(&mut limited),
        Err(AcquireError::Exhausted {
            acquired: 3,
            rollback: ReleaseReport { released: 3, failed: 0 },
        })
    ) && pmm::statistics().allocated_frames == before;
    if !rollback {
        serial::write_line("WOLFOS_USER_MULTI_ERROR injected_rollback=0");
        return false;
    }

    // Stage every real PMM frame under a single non-cloneable owner.
    // Even an early return triggers cleanup; explicit close reports errors.
    let mut source = RealPmm { remaining: FRAME_TOTAL };
    let batch = match FrameBatch::<_, FRAME_TOTAL>::acquire(&mut source) {
        Ok(batch) => batch,
        Err(error) => {
            serial::write_fmt(format_args!(
                "WOLFOS_USER_MULTI_ERROR frame_batch_acquire={error:?}\n",
            ));
            return false;
        }
    };
    let frames = *batch.frames();
    let exclusive = frames.iter().enumerate().all(|(i, frame)|
        *frame != 0 && *frame % 4096 == 0 && !frames[..i].contains(frame)
    );
    let verified = exclusive && prove(hhdm, &frames)
        && prove_two_pt(hhdm, &frames)
        && prove_relocated_two_pt(hhdm, &frames);
    let cleanup = batch.close();
    let freed = cleanup.released;
    let (now, _) = Cr3::read();
    let cr3_unchanged = now.start_address().as_u64() == cr3_before;
    let no_leak = pmm::statistics().allocated_frames == before;
    if !verified || freed != FRAME_TOTAL || cleanup.failed != 0
        || !cr3_unchanged || !no_leak
    {
        serial::write_fmt(format_args!(
            "WOLFOS_USER_MULTI_ERROR allocated={} verified={} freed={} release_failed={} cr3={} accounting={}\n",
            FRAME_TOTAL, verified, freed, cleanup.failed, cr3_unchanged, no_leak,
        ));
        return false;
    }
    serial::write_line("WOLFOS_USER_RELOCATED_TWO_PT_OK vacant_slot=1 relocated_elf=1 relocated_pte=1 byte_source_unshifted=1 staged_admission=1 tamper_denied=1 kernel_supervisor=1 cr3_unchanged=1 freed=8 ring3=0");
    serial::write_line("WOLFOS_USER_TWO_PT_OK frames=8 tables=5 pt_regions=2 load_pages=2 stack_rw_nx=1 elf_bound=1 bss_zero=1 hhdm_provenance=1 tamper_denied=1 pte_denied=1 staged_admission=1 admission_tamper_denied=1 kernel_supervisor=1 high_half_copied=1 kernel_anchor=1 hhdm_anchor=1 high_half_escalation_denied=1 cr3_unchanged=1 freed=8 ring3=0");
    serial::write_line(
        "WOLFOS_USER_MULTI_OK roots=1 pages=4 rx=2 rw_nx=2 elf_segments=2 bss_zero=1 atomic_page_copy=1 elf_pte_contract=1 byte_audit=1 tamper_rejected=4 stack_zero=1 ready_image_gate=1 hhdm_backing=1 staged_admission=1 frame_batch=1 injected_rollback=3 kernel_supervisor=1 high_half_copied=1 kernel_anchor=1 hhdm_anchor=1 freed=8 cr3_unchanged=1 ring3=0"
    );
    true
}
