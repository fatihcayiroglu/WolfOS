//! Real QEMU PMM proof: four disjoint 7-frame tentative process leases,
//! three simultaneously READY in one no_std table, fourth refused at
//! capacity; safe PID-scoped rollback and reuse without any frame leak.
//! This deliberately does not activate any private CR3 or execute Ring3.
use x86_64::registers::control::Cr3;
use crate::{
    pmm, serial,
    process_table::{ProcessTable, TableError},
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
    for at in 0..RESIDENT {
        if table.reserve(groups[at][0], groups[at]) != Ok(at as u64 + 1) {
            fail("three_resident_admissions")
        }
    }
    if table.occupied() != RESIDENT || table.running() != 0
        || table.reserve(groups[3][0], groups[3]) != Err(TableError::Full)
    { fail("resident_capacity") }
    serial::write_line(
        "WOLFOS_PROCESS_TABLE_RESIDENT_OK ready=3 pids=1,2,3 real_pmm_frames=28 aliases=0 running=0"
    );

    // The actual hardware boot CR3 cannot be reclaimed as a PID root.
    if table.cancel_ready(2, groups[1][0]).is_ok()
        || table.occupied() != RESIDENT
        || table.cancel_ready(2, boot_cr3) != Ok(groups[1])
    { fail("cancel_ready_cr3_guard") }
    for frame in groups[1].iter().copied() {
        if pmm::free_frame(frame).is_err() { fail("cancelled_frame_free") }
    }
    if pmm::statistics().allocated_frames != baseline + 3 * FRAMES {
        fail("cancelled_frame_count")
    }

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
    serial::write_line(
        "WOLFOS_PROCESS_TABLE_REUSE_OK last_pid=4 stale_pid_denied=1 foreign_cr3_denied=1"
    );

    for (pid, i) in [(1, 0), (3, 2), (4, 3)] {
        let Ok(reclaimed) = table.cancel_ready(pid, boot_cr3) else {
            fail("ready_release_authority")
        };
        if reclaimed != groups[i] { fail("wrong_owner_frames") }
        for frame in reclaimed {
            if pmm::free_frame(frame).is_err() { fail("double_free_or_invalid_pmm") }
        }
    }
    if table.occupied() != 0 || table.running() != 0
        || pmm::statistics().allocated_frames != baseline
    { fail("pmm_count_or_live_pid_leak") }
    serial::write_line(
        "WOLFOS_PROCESS_TABLE_CLEANUP_OK issued_pids=4 frames_freed=28 pmm_no_leak=1 boot_cr3_preserved=1 cpl3_executed=0"
    );
}
