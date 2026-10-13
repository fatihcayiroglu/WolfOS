//! First real multi-processor Rust execution test.
//!
//! Limine parks secondary processors until the BSP atomically provides an
//! entrypoint. Each AP executes Rust on a bootloader-provided stack, publishes
//! its unique handshake, then parks forever with external IRQs disabled.
//!
//! This is NOT a working SMP scheduler. APs do not use the BSP's GDT/TSS,
//! serial output, dynamic allocator or fault handlers; no shared page-table
//! modification occurs after releasing APs. Per-core descriptors and stacks
//! are required before accepting real kernel work on the APs.

use core::sync::atomic::{AtomicU64, Ordering};

use limine::mp::{MpInfo, MpRespData};

use crate::serial;

pub const MAX_BOOT_CPUS: usize = 256;
const ACK_MAGIC: u64 = 0x574F_4C46_4150_0000;
const WAIT_ROUNDS: usize = 100_000_000;

// The BSP is the sole writer of the boot sequence. Each AP only writes the
// slot assigned to it via Limine extra_argument, then never writes again.
static AP_ACK: [AtomicU64; MAX_BOOT_CPUS] =
    [const { AtomicU64::new(0) }; MAX_BOOT_CPUS];

fn expected_ack(info: &MpInfo) -> u64 {
    ACK_MAGIC ^ ((info.processor_id as u64) << 32) ^ info.lapic_id as u64
}

/// # Safety
/// The bootloader must supply an independent valid stack and correct
/// long-mode execution context as described in the Limine MP protocol.
/// The AP remains isolated: no allocator, serial port, mutable kernel
/// globals, or interrupt handling is used.
unsafe extern "C" fn secondary_entry(info: &MpInfo) -> ! {
    x86_64::instructions::interrupts::disable();

    let index = info.extra_argument() as usize;
    if index >= MAX_BOOT_CPUS || index == 0 {
        crate::halt_forever();
    }

    AP_ACK[index].store(expected_ack(info), Ordering::Release);
    crate::halt_forever();
}

/// Starts every non-BSP processor with Limine and verifies that real Rust
/// code executes on all of them. The BSP remains the only active worker.
pub fn boot_aps(mp: &MpRespData) -> bool {
    let cpus = mp.cpus();
    if cpus.is_empty() || cpus.len() > MAX_BOOT_CPUS {
        serial::write_fmt(format_args!(
            "WOLFOS_SMP_ERROR invalid_cpu_count={}\n", cpus.len()
        ));
        return false;
    }

    let mut bsp_count = 0usize;
    let mut ap_count = 0usize;

    // Validate identity and exact BSP membership before releasing APs.
    for (i, cpu) in cpus.iter().enumerate() {
        if cpu.lapic_id == mp.bsp_lapic_id {
            bsp_count += 1;
        }
        for other in cpus[..i].iter() {
            if other.lapic_id == cpu.lapic_id {
                serial::write_line("WOLFOS_SMP_ERROR duplicate_lapic_id");
                return false;
            }
        }
    }
    if bsp_count != 1 {
        serial::write_line("WOLFOS_SMP_ERROR bsp_not_unique");
        return false;
    }

    for (index, cpu) in cpus.iter().enumerate() {
        if cpu.lapic_id == mp.bsp_lapic_id {
            continue;
        }
        // Bootstrap slots can be zero, so shift by one and keep the last
        // slot free. Enforce this limit before starting any APs.
        let slot = index + 1;
        if slot >= MAX_BOOT_CPUS {
            serial::write_line("WOLFOS_SMP_ERROR too_many_aps");
            return false;
        }
        // Limine's bootstrap publishes the AP entrypoint with a Release
        // atomic store. The secondary CPU then executes secondary_entry.
        cpu.bootstrap(secondary_entry, slot as u64);
        ap_count += 1;
    }

    // QEMU acceptance requires that APs run Rust, not just show up in MADT.
    for _ in 0..WAIT_ROUNDS {
        let all_acked = cpus.iter().enumerate().all(|(index, cpu)| {
            cpu.lapic_id == mp.bsp_lapic_id
                || AP_ACK[index + 1].load(Ordering::Acquire) == expected_ack(cpu)
        });
        if all_acked {
            serial::write_fmt(format_args!(
                "WOLFOS_SMP_APS_OK total={} bsp_lapic={} ap_acks={}\n",
                cpus.len(), mp.bsp_lapic_id, ap_count
            ));
            return true;
        }
        core::hint::spin_loop();
    }
    serial::write_fmt(format_args!(
        "WOLFOS_SMP_ERROR ap_ack_timeout expected={}\n", ap_count
    ));
    false
}
