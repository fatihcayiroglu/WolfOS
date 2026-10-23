//! BSP-only CR3 observation proof before WolfOS starts secondary CPUs.
//! A private PMM PML4 borrows the unchanged boot kernel mappings. Only this
//! root frame is owned here; shared lower-level tables are never released.
//! No user program or multicore address-space shootdown is exercised.

use crate::{
    address_space_retirement::{Error, Phase, RetirementGate},
    pmm, serial,
};
use x86_64::{
    PhysAddr, VirtAddr,
    registers::control::{Cr3, Cr4, Cr4Flags},
    structures::paging::PhysFrame,
};

fn observed_root() -> u64 {
    Cr3::read().0.start_address().as_u64()
}

fn exercise(private: u64, supervisor: u64, retire_before_load: bool) -> bool {
    let generation = if retire_before_load { 2 } else { 1 };
    let Ok(mut gate) = RetirementGate::<1>::new(generation, private, supervisor) else {
        return false;
    };
    if gate.publish().is_err() {
        return false;
    }
    let Ok(ticket) = gate.reserve_cpu(0) else {
        return false;
    };
    if retire_before_load && gate.begin_retirement().is_err() {
        return false;
    }
    let Ok(frame) = PhysFrame::from_start_address(PhysAddr::new(private)) else {
        return false;
    };
    let (original, flags) = Cr3::read();
    if original.start_address().as_u64() != supervisor {
        return false;
    }

    // SAFETY: BSP IF=0, before boot_aps; only this CPU can load the private
    // root. Its entire PML4 was copied from the current root, preserving
    // code, boot stack and HHDM mappings. PCID is independently disabled.
    // The PMM root stays allocated throughout both loads and all checks.
    unsafe {
        Cr3::write(frame, flags);
    }
    // No early return between the private load and the unconditional restore.
    let active = observed_root();
    let mut ok = active == private;
    if retire_before_load {
        ok &= gate.confirm_active(ticket, active) == Err(Error::WrongPhase);
    } else {
        ok &= gate.confirm_active(ticket, active).is_ok();
        ok &= gate.begin_retirement().is_ok();
    }
    let before = gate.snapshot();
    ok &= gate.reserve_cpu(0) == Err(Error::WrongPhase);
    ok &= gate.acknowledge_quiescent(ticket, observed_root()) == Err(Error::WrongCr3);
    ok &= gate.finish_retirement() == Err(Error::OutstandingCpus);
    ok &= gate.snapshot() == before;
    ok &= if retire_before_load {
        before.reserved == 1
    } else {
        before.active == 1
    };
    // SAFETY: restore the authenticated original root and its flags while
    // both PML4 frames and every borrowed child table are still resident.
    unsafe {
        Cr3::write(original, flags);
    }
    let restored = observed_root();
    ok &= restored == supervisor;
    ok &= gate.acknowledge_quiescent(ticket, restored).is_ok();
    ok &= gate.acknowledge_quiescent(ticket, restored) == Err(Error::StaleTicket);
    ok &= gate.finish_retirement().is_ok();
    ok &= gate.snapshot().phase == Phase::Retired;
    ok
}

pub fn verify(hhdm: u64) -> bool {
    if x86_64::instructions::interrupts::are_enabled() || Cr4::read().contains(Cr4Flags::PCID) {
        return false;
    }
    let before = pmm::statistics().allocated_frames;
    let supervisor = observed_root();
    let Some(private) = pmm::allocate_frame() else {
        return false;
    };
    // A PMM ownership violation must fail closed without freeing active CR3.
    if private == supervisor {
        return false;
    }
    let addresses = hhdm
        .checked_add(supervisor)
        .and_then(|old| hhdm.checked_add(private).map(|new| (old, new)));
    let pointers = addresses.and_then(|(old, new)| {
        Some((
            VirtAddr::try_new(old).ok()?.as_ptr::<u64>(),
            VirtAddr::try_new(new).ok()?.as_mut_ptr::<u64>(),
        ))
    });
    let verified = if let Some((old, new)) = pointers {
        // SAFETY: aligned HHDM views of distinct resident physical PML4
        // frames. No lower-level table ownership is transferred or changed.
        unsafe {
            for index in 0..512 {
                new.add(index)
                    .write_volatile(old.add(index).read_volatile());
            }
        }
        exercise(private, supervisor, false) && exercise(private, supervisor, true)
    } else {
        false
    };

    // The gate itself NEVER frees frames. This isolated test independently
    // verifies restored CR3, IF=0, PCID=0 and sole-BSP root access first.
    if observed_root() != supervisor {
        return false;
    }
    let resident = pmm::statistics().allocated_frames == before + 1;
    let freed = pmm::free_frame(private).is_ok();
    let no_leak = pmm::statistics().allocated_frames == before;
    if !verified || !resident || !freed || !no_leak {
        serial::write_line("WOLFOS_ADDRESS_SPACE_RETIRE_ERROR");
        return false;
    }
    serial::write_line(
        "WOLFOS_ADDRESS_SPACE_RETIRE_OK bsp_only=1 private_cr3_loads=2 late_load_rejected=1 active_rejected=1 reentry_rejected=1 stale_ack_rejected=1 supervisor_restored=1 frames_freed=1 pmm_no_leak=1 ring3=0",
    );
    true
}
