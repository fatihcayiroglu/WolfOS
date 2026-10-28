//! Read-only discovery of legacy PCI configuration space on x86-64.
//! PCI configuration mechanism #1 (0xCF8/0xCFC) gives 256-byte headers.
//!
//! Not a PCIe ECAM driver or driver installer. Only early-boot (BSP) access
//! with interrupts disabled is supported; CF8/CFC are shared I/O ports.
//! We never write to device configuration registers.

use core::arch::asm;
use crate::{display_driver_policy::DisplayIdentity, serial};

const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;
const MAX_LOGGED: usize = 20;

#[derive(Clone, Copy, Debug)]
pub struct PciSummary {
    pub devices: usize,
    pub displays: usize,
    pub networks: usize,
    pub storage: usize,
}

/// Read an aligned u32 from a function's first 256 PCI config bytes.
/// SAFETY: Only for the boot processor with interrupts disabled. It writes
/// the *address selection port*, not any PCI device configuration register.
fn read_u32(bus: u8, slot: u8, function: u8, offset: u8) -> u32 {
    let address = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((function as u32) << 8)
        | (u32::from(offset) & 0xfc);
    let response: u32;
    unsafe {
        asm!("out dx, eax",
            in("dx") CONFIG_ADDRESS, in("eax") address,
            options(nomem, nostack, preserves_flags));
        asm!("in eax, dx",
            in("dx") CONFIG_DATA, out("eax") response,
            options(nomem, nostack, preserves_flags));
    }
    response
}

fn probe(bus: u8, slot: u8, function: u8) -> Option<(u16, u16)> {
    let ids = read_u32(bus, slot, function, 0);
    let vendor = ids as u16;
    if vendor == 0xffff { return None; }
    Some((vendor, (ids >> 16) as u16))
}

fn record(
    summary: &mut PciSummary,
    bus: u8,
    slot: u8,
    function: u8,
    vendor: u16,
    device: u16,
) {
    let revision_and_class = read_u32(bus, slot, function, 0x08);
    let class = (revision_and_class >> 24) as u8;
    let subclass = (revision_and_class >> 16) as u8;
    let prog_if = (revision_and_class >> 8) as u8;

    if summary.devices < MAX_LOGGED {
        serial::write_fmt(format_args!(
            "WOLFOS_PCI_DEVICE {:02x}:{:02x}.{} vendor={:04x} device={:04x} class={:02x}:{:02x}:{:02x}\n",
            bus, slot, function, vendor, device, class, subclass, prog_if
        ));
    }
    summary.devices += 1;
    match class {
        0x01 => summary.storage += 1,
        0x02 => summary.networks += 1,
        0x03 => {
            summary.displays += 1;
            serial::write_fmt(format_args!(
                "WOLFOS_GPU_DETECTED vendor={:04x} device={:04x} bus={:02x} slot={:02x}\n",
                vendor, device, bus, slot
            ));
            // Identification is NOT permission to bind any accelerated
            // driver. This stage neither configures BARs nor touches DMA.
            if let Some(identity) = DisplayIdentity::from_pci(vendor, device, class) {
                serial::write_fmt(format_args!(
                    "WOLFOS_GPU_DRIVER_POLICY vendor={:04x} device={:04x} family={} native=none cfg_write=0\n",
                    vendor, device, identity.family.label(),
                ));
            }
        }
        _ => {}
    }
}

/// Scan 256 buses, 32 slots, and function 1..7 only for multifunction devices.
/// Legacy access is deliberately serialized by the single-CPU startup phase.
pub fn discover() -> PciSummary {
    let mut summary = PciSummary {
        devices: 0, displays: 0, networks: 0, storage: 0,
    };
    for bus in 0u16..=255 {
        for slot in 0u8..32 {
            let b = bus as u8;
            let Some((vendor, device)) = probe(b, slot, 0) else { continue; };
            record(&mut summary, b, slot, 0, vendor, device);
            let header = (read_u32(b, slot, 0, 0x0c) >> 16) as u8;
            if header & 0x80 == 0 { continue; }
            for function in 1u8..8 {
                if let Some((vendor, device)) = probe(b, slot, function) {
                    record(&mut summary, b, slot, function, vendor, device);
                }
            }
        }
    }
    serial::write_fmt(format_args!(
        "WOLFOS_PCI_OK devices={} displays={} networks={} storage={}\n",
        summary.devices, summary.displays, summary.networks, summary.storage
    ));
    summary
}
