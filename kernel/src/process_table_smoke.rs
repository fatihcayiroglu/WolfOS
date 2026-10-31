//! Real QEMU PMM proof: four disjoint 7-frame tentative process leases,
//! three simultaneously READY in one no_std table, fourth refused at
//! capacity; safe PID-scoped rollback and reuse without any frame leak.
//! This deliberately does not activate any private CR3 or execute Ring3.
use x86_64::registers::control::Cr3;
use crate::{
    pmm, serial,
    process_table::{ProcessTable, TableError, GuardedBatchError},
    user_context_bank::{UserContextBank, KernelStack, KSTACK_BYTES, ContextError, ElfAdmissionError},
    user_syscall_abi::UserSyscallFrame,
};

const GROUPS: usize = 4;
const FRAMES: usize = 7;
const RESIDENT: usize = 3;

fn fail(msg: &str) -> ! {
    serial::write_fmt(format_args!("WOLFOS_PROCESS_TABLE_ERROR {msg}\n"));
    crate::halt_forever()
}

/// PMM leases are physically allocated, not synthetic addresses. On partial
/// allocation failure, every already-issued frame is returned to the PMM.
fn allocate_groups() -> Option<[[u64; FRAMES]; GROUPS]> {
    let mut groups = [[0u64; FRAMES]; GROUPS];
    for group in 0..GROUPS {
        for at in 0..FRAMES {
            let Some(frame) = pmm::allocate_frame() else {
                for owned in groups.iter().flatten().copied().filter(|f| *f != 0) {
                    let _ = pmm::free_frame(owned);
                }
                return None;
            };
            if frame == 0 || frame & 4095 != 0
                || groups.iter().flatten().any(|known| *known == frame)
            {
                let _ = pmm::free_frame(frame);
                for owned in groups.iter().flatten().copied().filter(|f| *f != 0) {
                    let _ = pmm::free_frame(owned);
                }
                return None;
            }
            groups[group][at] = frame;
        }
    }
    Some(groups)
}

// These guarded-stack addresses are ONLY synthetic RSP0 *metadata* for
// bootstrap validation. No physical stack mapping, TSS switch or user IRET
// occurs in this separate PMM ownership smoke.
fn context_stack(slot: usize) -> KernelStack {
    let bottom = 0xffff_8000_0b00_0000 + slot as u64 * 0x10000;
    KernelStack { bottom, top: bottom + KSTACK_BYTES }
}

fn bootstrap_frame(slot: usize) -> UserSyscallFrame {
    let mut frame = UserSyscallFrame::default();
    frame.hardware.rip = 0x401100 + slot as u64 * 0x1000;
    frame.hardware.rsp = 0x405000;
    frame.hardware.cs = 0x2b;
    frame.hardware.ss = 0x23;
    frame.hardware.rflags = 0x2;
    frame.registers.rax = slot as u64 + 1;
    frame
}

/// Bounded kernel-resident ET_EXEC file bytes. These bytes are parsed
/// in QEMU but NOT mapped or executed as user instructions in this flavor.
fn elf_bytes(slot: usize) -> [u8; 512] {
    let mut bytes = [0u8; 512];
    let entry = 0x401100u64 + slot as u64 * 0x1000;
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4..7].copy_from_slice(&[2, 1, 1]);
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // AMD64
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[24..32].copy_from_slice(&entry.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    bytes[68..72].copy_from_slice(&5u32.to_le_bytes()); // R|X
    bytes[72..80].copy_from_slice(&0x100u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&entry.to_le_bytes());
    bytes[96..104].copy_from_slice(&8u64.to_le_bytes());
    bytes[104..112].copy_from_slice(&0x900u64.to_le_bytes());
    bytes[112..120].copy_from_slice(&4096u64.to_le_bytes());
    bytes[0x100] = 0x90;
    bytes
}

pub fn verify() {
    let (active, _) = Cr3::read();
    let boot_cr3 = active.start_address().as_u64();
    if boot_cr3 == 0 { fail("invalid_boot_cr3") }
    let baseline = pmm::statistics().allocated_frames;
    let Some(groups) = allocate_groups() else { fail("alloc_28_real_frames") };
    if groups.iter().any(|g| g[0] == boot_cr3)
        || pmm::statistics().allocated_frames != baseline + GROUPS * FRAMES
    { fail("allocated_frames_or_boot_root") }

    let mut table = ProcessTable::<RESIDENT, FRAMES>::new();
    let mut contexts = UserContextBank::<RESIDENT>::new();
    let images = [elf_bytes(0), elf_bytes(1), elf_bytes(2)];
    // A late W+X ELF cannot publish any earlier PID/context, despite
    // already-owned REAL PMM candidate leases still held by the caller.
    let mut invalid_elf = images[2];
    invalid_elf[68..72].copy_from_slice(&7u32.to_le_bytes());
    if !matches!(contexts.admit_elf_batch(&mut table, [
        (&images[0][..], groups[0], context_stack(0), bootstrap_frame(0)),
        (&images[1][..], groups[1], context_stack(1), bootstrap_frame(1)),
        (&invalid_elf[..], groups[2], context_stack(2), bootstrap_frame(2)),
    ]), Err(ElfAdmissionError::Image { index: 2, .. }))
        || table.occupied() != 0 || contexts.count() != 0
        || pmm::statistics().allocated_frames != baseline + GROUPS * FRAMES
    { fail("late_invalid_elf_rollback_real_pmm") }

    // Test a physical alias BETWEEN proposed real-PMM process leases.
    // Both new PIDs and bootstrap CPU context frames must stay invisible.
    let mut in_batch_alias = groups[1];
    in_batch_alias[6] = groups[0][3];
    if contexts.admit_bootstrap_batch(&mut table, [
        (groups[0], context_stack(0), bootstrap_frame(0)),
        (in_batch_alias, context_stack(1), bootstrap_frame(1)),
    ]) != Err(GuardedBatchError::Table(TableError::PhysicalAlias))
        || table.occupied() != 0 || contexts.count() != 0
        || table.snapshot(1).is_some()
    { fail("joint_batch_cross_lease_alias_or_partial_pid") }

    // The third proposed process has an invalid bootstrap RFLAGS mask.
    // PMM frames remain physically allocated by the caller but neither
    // registry may publish ANY tentative PID or saved context.
    let mut invalid = bootstrap_frame(2);
    invalid.hardware.rflags = 0x202;
    if contexts.admit_bootstrap_batch(&mut table, [
        (groups[0], context_stack(0), bootstrap_frame(0)),
        (groups[1], context_stack(1), bootstrap_frame(1)),
        (groups[2], context_stack(2), invalid),
    ]) != Err(GuardedBatchError::Validate(ContextError::BadFlags))
        || table.occupied() != 0 || contexts.count() != 0
        || table.snapshot(1).is_some()
        || pmm::statistics().allocated_frames != baseline + GROUPS * FRAMES
    { fail("joint_batch_bootstrap_validation_or_pmm_accounting") }

    // Admit three REAL independent PMM leases and guarded *metadata*
    // contexts atomically; no bootstrap IRET or frame mapping is performed.
    let residents = core::array::from_fn(|i|
        (&images[i][..], groups[i], context_stack(i), bootstrap_frame(i))
    );
    if contexts.admit_elf_batch(&mut table, residents) != Ok([1, 2, 3])
        || contexts.count() != RESIDENT
        || (1..=3).any(|pid| contexts.snapshot(pid).is_none())
    { fail("three_resident_joint_batch_admissions") }
    if table.occupied() != RESIDENT || table.running() != 0
        || table.reserve(groups[3][0], groups[3]) != Err(TableError::Full)
    { fail("resident_capacity") }
    serial::write_line(
        "WOLFOS_PROCESS_TABLE_RESIDENT_OK ready=3 pids=1,2,3 real_pmm_frames=28 aliases=0 running=0"
    );

    serial::write_line(
        "WOLFOS_PROCESS_TABLE_BOOTSTRAP_OK pids=3 context_frames=3 private_lease_roots=3 atomic_rollback=1 stack_mapped=0 cpl3_executed=0"
    );
    serial::write_line(
        "WOLFOS_PROCESS_TABLE_ELF_PREFLIGHT_OK images=3 file_backed_entries=3 wx_denied=1 late_rollback=1 real_pmm=28 user_mapping=0"
    );

    // The actual hardware boot CR3 cannot be reclaimed as a PID root.
    if table.cancel_ready(2, groups[1][0]).is_ok()
        || table.occupied() != RESIDENT
        || table.cancel_ready(2, boot_cr3) != Ok(groups[1])
    { fail("cancel_ready_cr3_guard") }
    if contexts.retire(&table, 2).is_err()
        || contexts.snapshot(2).is_some()
        || contexts.count() != RESIDENT - 1
    { fail("cancelled_context_retirement") }
    for frame in groups[1].iter().copied() {
        if pmm::free_frame(frame).is_err() { fail("cancelled_frame_free") }
    }
    if pmm::statistics().allocated_frames != baseline + 3 * FRAMES {
        fail("cancelled_frame_count")
    }

    // Only one table slot remains. A TWO-owner batch must fail as a
    // whole, even though its first new member passes all PMM checks.
    // Real physical pages are held by the caller and never freed by policy.
    if table.reserve_batch([
        (groups[3][0], groups[3]),
        (groups[3][0], groups[3]),
    ]) != Err(TableError::Full)
        || table.occupied() != RESIDENT - 1
        || table.snapshot(4).is_some()
    { fail("batch_partial_publish_or_pid_burn") }

    // Claiming an existing PID's PMM leaf as a new CR3 root is forbidden.
    let mut alias = groups[3];
    alias[0] = groups[0][1];
    if table.reserve(alias[0], alias) != Err(TableError::PhysicalAlias) {
        fail("cross_pid_alias_accepted")
    }
    if table.reserve(groups[3][0], groups[3]) != Ok(4)
        || table.occupied() != RESIDENT
        || table.snapshot(2).is_some()
        || table.snapshot(4).is_none()
    { fail("slot_reuse_or_stale_pid") }
    // The retired PID2's RSP0 metadata may be reused only after its bank
    // entry is removed. PID4 gets an independent new CR3/PMM lease.
    if contexts.prepare_bootstrap(
        &table, 4, groups[3][0], context_stack(1), bootstrap_frame(3),
    ).is_err() || contexts.snapshot(4).is_none()
        || contexts.snapshot(2).is_some() || contexts.count() != RESIDENT
    { fail("safe_context_slot_stack_reuse") }
    serial::write_line(
        "WOLFOS_PROCESS_TABLE_REUSE_OK last_pid=4 stale_pid_denied=1 foreign_cr3_denied=1"
    );
    serial::write_line(
        "WOLFOS_PROCESS_TABLE_CONTEXT_REUSE_OK live_contexts=3 retired_pid2=1 fresh_pid4=1 rsp0_reused_safely=1"
    );

    for (pid, i) in [(1, 0), (3, 2), (4, 3)] {
        let Ok(reclaimed) = table.cancel_ready(pid, boot_cr3) else {
            fail("ready_release_authority")
        };
        if reclaimed != groups[i] { fail("wrong_owner_frames") }
        if contexts.retire(&table, pid).is_err() {
            fail("context_retire_after_exact_lease_transfer")
        }
        for frame in reclaimed {
            if pmm::free_frame(frame).is_err() { fail("double_free_or_invalid_pmm") }
        }
    }
    if table.occupied() != 0 || table.running() != 0
        || contexts.count() != 0
        || pmm::statistics().allocated_frames != baseline
    { fail("pmm_count_or_live_pid_leak") }
    serial::write_line(
        "WOLFOS_PROCESS_TABLE_CLEANUP_OK issued_pids=4 frames_freed=28 pmm_no_leak=1 boot_cr3_preserved=1 cpl3_executed=0"
    );
}


/// The two PMM data pages are owned by different READY registry PIDs.
/// They are intentionally *not* mapped to CPL3 or attached to VirtIO GPU.
/// Read actual HHDM physical RAM pixels and prove cross-process z-order plus
/// fail-before-write denial after PID1 is revoked. The whole operation is
/// BSP-only with IRQs off, no AP CPU, and both PMM leases still held.
#[cfg(feature = "qemu-surface-reap-pmm-smoke")]
fn verify_owned_pmm_pixels(
    hhdm: u64,
    frames: &[u64; 4],
    processes: &ProcessTable<2, 2>,
    surfaces: &crate::virtio_gpu_desktop_wire::surface_ledger::SurfaceLedger<2>,
    a: crate::virtio_gpu_desktop_wire::surface_pixels::Identity,
    b: crate::virtio_gpu_desktop_wire::surface_pixels::Identity,
    expect_live: bool,
) {
    use crate::virtio_gpu_desktop_wire::{
        damage::Rect,
        surface_ledger::Error as LedgerError,
        surface_pixels::{CompositionReport, Error as PixelError, Identity, SurfacePixels},
        surface_process_bridge::{compose_registered, Error as BridgeError},
    };
    if x86_64::instructions::interrupts::are_enabled() {
        fail("surface_pixels_irqs_enabled")
    }
    let Some(a_address)=hhdm.checked_add(frames[1])
        .and_then(|x|x86_64::VirtAddr::try_new(x).ok()) else {
        fail("surface_pixels_a_hhdm")
    };
    let Some(b_address)=hhdm.checked_add(frames[3])
        .and_then(|x|x86_64::VirtAddr::try_new(x).ok()) else {
        fail("surface_pixels_b_hhdm")
    };
    if a_address==b_address || a_address.as_u64() & 4095 != 0
        || b_address.as_u64() & 4095 != 0
    { fail("surface_pixels_alias_or_alignment") }

    // Initial writes touch only the data frame (second page) of each
    // independently-owned two-page ProcessTable lease. The first frame
    // of each lease is the registry's CR3-root *metadata* frame, untouched.
    // These PMM data pages remain leased until BOTH source slices expire.
    if expect_live {
        for i in 0..4usize {
            // SAFETY: frames[1]/frames[3] are distinct, exclusively allocated
            // real PMM pages, mapped as kernel RAM through boot HHDM, not user
            // or MMIO. BSP-only under IRQ-disabled test. No reader is live.
            unsafe {
                a_address.as_mut_ptr::<u32>().add(i).write_volatile(0x00d7_2200);
                b_address.as_mut_ptr::<u32>().add(i).write_volatile(0x0007_27e1);
            }
        }
    }
    // SAFETY: both spans are aligned 4-word prefixes within separate 4 KiB
    // owned PMM pages, after initial writes and before any PMM free/unmap.
    let a_data=unsafe{core::slice::from_raw_parts(a_address.as_ptr::<u32>(),4)};
    let b_data=unsafe{core::slice::from_raw_parts(b_address.as_ptr::<u32>(),4)};
    if a_data != [0x00d7_2200;4] || b_data != [0x0007_27e1;4] {
        fail("surface_pixels_real_physical_contents")
    }
    let Ok(r_a)=Rect::checked(1,1,2,2) else {fail("surface_rect_a")};
    let Ok(r_b)=Rect::checked(2,1,2,2) else {fail("surface_rect_b")};
    let Ok(view)=Rect::checked(0,0,8,8) else {fail("surface_view")};
    let Ok(first)=SurfacePixels::new(a,r_a,2,a_data) else {fail("surface_a_ref")};
    let Ok(second)=SurfacePixels::new(b,r_b,2,b_data) else {fail("surface_b_ref")};
    let background=[0x0033_3355;64];
    let mut output=[0x00ce_efed;64];

    let rendered=compose_registered(
        processes,surfaces,&mut output,&background,view,8,view,
        first,second,b
    );
    if expect_live {
        if rendered!=Ok(CompositionReport{
            background:58,first:2,second:4,
        }) {
            fail("surface_live_compose_report")
        }
        for y in 0..8usize {
            for x in 0..8usize {
                let expected=if (2..4).contains(&x) && (1..3).contains(&y) {
                    0x0007_27e1
                } else if (1..3).contains(&x) && (1..3).contains(&y) {
                    0x00d7_2200
                } else {
                    0x0033_3355
                };
                if output[y*8+x]!=expected {
                    fail("surface_live_compose_real_pmm_pixel")
                }
            }
        }
    } else if rendered!=Err(BridgeError::Ledger(LedgerError::NotLive))
        || output!=[0x00ce_efed;64]
    {
        fail("surface_closed_owner_touched_pixels")
    }
    // Even if the owner is still READY, a forged process generation must
    // fail BEFORE changing a destination pixel.
    output.fill(0x00ce_efed);
    let forged=Identity{process_generation:a.pid+1,..a};
    let Ok(forged_first)=SurfacePixels::new(forged,r_a,2,a_data) else {
        fail("surface_forged_fixture")
    };
    if compose_registered(processes,surfaces,&mut output,&background,
        view,8,view,forged_first,second,b)
        !=Err(BridgeError::InvalidProcessIdentity)
        || output!=[0x00ce_efed;64]
    { fail("surface_forged_process_generation_mutated_pixels") }

    if expect_live {
        let invalid_top=Identity{slot:999,..b};
        if compose_registered(processes,surfaces,&mut output,&background,
            view,8,view,first,second,invalid_top)
            !=Err(BridgeError::Ledger(LedgerError::Pixel(PixelError::InvalidTop)))
            || output!=[0x00ce_efed;64]
        { fail("surface_invalid_z_order_mutated_pixels") }
    }
    // Never retain any borrowed PMM pixel slice after this function exits.
}

/// Real QEMU PMM integration for the *software-only* surface retirement gate.
/// These four physical pages are exclusively owned by two READY PID leases;
/// they are NOT user-mapped pixels and never submitted to VirtIO-GPU.
/// GPU transfer/flush acknowledgements below are SYNTHETIC policy exercises
/// after verifying that the guarded cancel refuses to return the PMM lease.
/// No real DMA or CPL3 claim is made by this separate feature.
#[cfg(feature = "qemu-surface-reap-pmm-smoke")]
pub fn verify_surface_reap_pmm(hhdm: u64) {
    use crate::virtio_gpu_desktop_wire::surface_ledger::{
        SurfaceLedger, Error as GpuError, State as SurfaceState,
    };
    use crate::virtio_gpu_desktop_wire::surface_process_bridge::{
        open_registered, cancel_ready_counted_guarded, Error as BridgeError,
    };

    let (actual, _) = Cr3::read();
    let supervisor_cr3 = actual.start_address().as_u64();
    if supervisor_cr3 == 0 { fail("surface_supervisor_cr3") }
    let baseline = pmm::statistics().allocated_frames;

    // Allocate real owned physical pages; reject aliases to boot CR3.
    let mut frames=[0u64;4];
    for index in 0..frames.len() {
        let Some(frame)=pmm::allocate_frame() else {
            fail("surface_pmm_allocate")
        };
        if frame == 0 || frame & 4095 != 0 || frame == supervisor_cr3
            || frames[..index].contains(&frame) {
            fail("surface_pmm_unique_frame")
        }
        frames[index]=frame;
    }
    if pmm::statistics().allocated_frames != baseline+4 {
        fail("surface_pmm_initial_count")
    }
    let mut processes=ProcessTable::<2,2>::new();
    let mut surfaces=SurfaceLedger::<2>::new();
    let Ok(pid1)=processes.reserve(frames[0],[frames[0],frames[1]]) else {
        fail("surface_process_admit_one")
    };
    let Ok(pid2)=processes.reserve(frames[2],[frames[2],frames[3]]) else {
        fail("surface_process_admit_two")
    };
    let Ok(a)=open_registered(&processes,&mut surfaces,pid1) else {
        fail("surface_open_owner_one")
    };
    let Ok(b)=open_registered(&processes,&mut surfaces,pid2) else {
        fail("surface_open_owner_two")
    };
    verify_owned_pmm_pixels(hhdm,&frames,&processes,&surfaces,a,b,true);
    if surfaces.begin_submit(a,100,101).is_err() {
        fail("surface_submit_software_contract")
    }

    // A policy ledger awaiting genuine device replies must deny a frame
    // lease. This fixture uses explicit synthetic completions afterwards to
    // test only the ordering logic, not any hardware evidence.
    if cancel_ready_counted_guarded(&mut processes,&mut surfaces,pid1,supervisor_cr3)
        != Err(BridgeError::OutstandingSurfaces)
        || surfaces.state(a)!=Ok(SurfaceState::ClosingSubmitted)
        || surfaces.state(b)!=Ok(SurfaceState::Live)
        || processes.snapshot(pid1).is_none()
        || pmm::statistics().allocated_frames!=baseline+4
    { fail("surface_early_pmm_release_refusal") }

    // CPU-side pixels remain present in actual PMM pages, but a closing
    // owner cannot present even a single pixel after revocation.
    verify_owned_pmm_pixels(hhdm,&frames,&processes,&surfaces,a,b,false);

    if surfaces.ack_flush(a,101)!=Err(GpuError::FlushBeforeTransfer)
        || surfaces.ack_transfer(a,100).is_err()
    { fail("surface_transfer_order") }
    if cancel_ready_counted_guarded(&mut processes,&mut surfaces,pid1,supervisor_cr3)
        != Err(BridgeError::OutstandingSurfaces)
        || surfaces.state(a)!=Ok(SurfaceState::ClosingTransferred)
    { fail("surface_half_ack_must_keep_pmm") }

    if surfaces.ack_flush(a,101).is_err()
        || surfaces.release(a)!=Ok(a)
    { fail("surface_synthetic_completion_and_release") }
    let Ok(lease1)=cancel_ready_counted_guarded(
        &mut processes,&mut surfaces,pid1,supervisor_cr3
    ) else { fail("surface_cancel_one_after_drain") };
    if lease1.as_slice()!=&frames[0..2]
        || processes.snapshot(pid1).is_some()
        || surfaces.require_live(a)!=Err(GpuError::StaleHandle)
        || pmm::statistics().allocated_frames!=baseline+4
    { fail("surface_first_lease_authority") }

    // Real PMM pages must be freed EXACTLY once, and second PID still owns
    // its pages. This proves a real physical accounting boundary only.
    for &frame in lease1.as_slice() {
        if pmm::free_frame(frame).is_err() { fail("surface_free_one") }
    }
    if pmm::statistics().allocated_frames!=baseline+2
        || processes.snapshot(pid2).is_none()
        || surfaces.state(b)!=Ok(SurfaceState::Live)
    { fail("surface_other_pid_isolation") }

    // PID2 never sent GPU work and must not require a fabricated fence.
    if cancel_ready_counted_guarded(&mut processes,&mut surfaces,pid2,supervisor_cr3)
        != Err(BridgeError::OutstandingSurfaces)
        || surfaces.state(b)!=Ok(SurfaceState::Closing)
        || surfaces.release(b)!=Ok(b)
    { fail("surface_no_gpu_cleanup") }
    let Ok(lease2)=cancel_ready_counted_guarded(
        &mut processes,&mut surfaces,pid2,supervisor_cr3
    ) else { fail("surface_cancel_two_after_drain") };
    if lease2.as_slice()!=&frames[2..4] {
        fail("surface_second_lease_authority")
    }
    for &frame in lease2.as_slice() {
        if pmm::free_frame(frame).is_err() { fail("surface_free_two") }
    }
    if processes.occupied()!=0 || surfaces.owner_remaining(pid1,pid1)!=0
        || surfaces.owner_remaining(pid2,pid2)!=0
        || pmm::statistics().allocated_frames!=baseline
    { fail("surface_cleanup_pmm_leak") }

    serial::write_line(
        "WOLFOS_SURFACE_REAP_PMM_OK pids=2 real_pmm_pages=4 early_release_denied=1 half_ack_denied=1 cross_pid_isolated=1 synthetic_gpu_acks=1 owner_pixel_composition=1 stale_owner_pixels_denied=1 pmm_no_leak=1 cpl3_executed=0 real_gpu_dma=0"
    );
}
