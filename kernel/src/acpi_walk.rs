//! Read-only firmware ACPI table traversal at kernel boot.
//! Limine's HHDM provides the physical-to-virtual mapping. Firmware regions
//! must be backed by mapped ACPI RAM and cannot be freed by WolfOS PMM.
//! No ACPI AML execution, device writes or interrupt configuration.

use core::ptr;
use limine::memmap::{Entry, MEMMAP_ACPI_RECLAIMABLE, MEMMAP_ACPI_NVS, MEMMAP_MAPPED_RESERVED};
use x86_64::VirtAddr;

use crate::acpi_layout::RsdpInfo;
use crate::acpi_tables::{parse_madt, parse_sdt, sdt_length, RootTable, Sdt, SDT_HEADER_LEN};
use crate::serial;

const MAX_ROOT_ENTRIES: usize = 256;

fn allowed_firmware_region(physical: u64, length: usize, memmap: &[&Entry]) -> bool {
    let Some(end) = physical.checked_add(length as u64) else { return false; };
    memmap.iter().copied().any(|entry| {
        let allowed = entry.type_ == MEMMAP_ACPI_RECLAIMABLE
            || entry.type_ == MEMMAP_ACPI_NVS
            || entry.type_ == MEMMAP_MAPPED_RESERVED;
        let Some(region_end) = entry.base.checked_add(entry.length) else {
            return false;
        };
        allowed && entry.base <= physical && end <= region_end
    })
}

/// # Safety
/// Caller must provide valid Limine HHDM and reserve ACPI table memory
/// throughout the parse. Returns a view only over validated mapped RAM.
unsafe fn load_sdt<'a>(physical: u64, hhdm: u64, memmap: &[&Entry]) -> Result<Sdt<'a>, &'static str> {
    if physical == 0 || !allowed_firmware_region(physical, SDT_HEADER_LEN, memmap) {
        return Err("header not in mapped ACPI firmware RAM");
    }
    let Some(address) = hhdm.checked_add(physical) else {
        return Err("HHDM overflow");
    };
    let Ok(virtual_address) = VirtAddr::try_new(address) else {
        return Err("noncanonical HHDM address");
    };
    let source = virtual_address.as_ptr::<u8>();
    let mut header = [0u8; SDT_HEADER_LEN];
    for (i, byte) in header.iter_mut().enumerate() {
        // SAFETY: validated mapped firmware range covers the SDT header.
        *byte = unsafe { ptr::read_volatile(source.add(i)) };
    }
    let length = sdt_length(&header).map_err(|_| "SDT header length invalid")?;
    if !allowed_firmware_region(physical, length, memmap) {
        return Err("SDT spans outside mapped ACPI region");
    }
    // SAFETY: the full contiguous mapped region was verified, firmware
    // storage remains reserved, and we only ever read from these slices.
    let data = unsafe { core::slice::from_raw_parts(source, length) };
    parse_sdt(data).map_err(|_| "SDT checksum or structure invalid")
}

pub fn discover(info: RsdpInfo, hhdm: u64, memmap: &[&Entry]) -> bool {
    let (root_phys, want_xsdt) = match info.xsdt_physical {
        Some(xsdt) if xsdt != 0 => (xsdt, true),
        _ => (info.rsdt_physical as u64, false),
    };

    // SAFETY: HHDM and memory-map entries come from the verified Limine
    // handoff; only firmware-owned memory ranges can be dereferenced.
    let root_sdt = match unsafe { load_sdt(root_phys, hhdm, memmap) } {
        Ok(sdt) => sdt,
        Err(message) => {
            serial::write_fmt(format_args!("WOLFOS_ACPI_ROOT_ERROR {message}\n"));
            return false;
        }
    };
    if (want_xsdt && root_sdt.signature != *b"XSDT")
        || (!want_xsdt && root_sdt.signature != *b"RSDT")
    {
        serial::write_line("WOLFOS_ACPI_ROOT_ERROR root signature mismatch");
        return false;
    }
    let root = match RootTable::parse(&root_sdt) {
        Ok(root) if root.len() <= MAX_ROOT_ENTRIES => root,
        _ => {
            serial::write_line("WOLFOS_ACPI_ROOT_ERROR invalid/oversized root directory");
            return false;
        }
    };

    serial::write_fmt(format_args!(
        "WOLFOS_ACPI_ROOT_OK kind={} entries={}\n",
        if want_xsdt { "XSDT" } else { "RSDT" }, root.len()
    ));

    let mut found_madt = false;
    for index in 0..root.len() {
        let Some(phys) = root.physical_at(index) else {
            serial::write_line("WOLFOS_ACPI_ROOT_ERROR invalid root pointer");
            return false;
        };
        // SAFETY: we validate memory-map region, bounds, mapped virtual
        // address, checksum and exact table length before examining data.
        let table = match unsafe { load_sdt(phys, hhdm, memmap) } {
            Ok(table) => table,
            Err(message) => {
                serial::write_fmt(format_args!("WOLFOS_ACPI_TABLE_ERROR index={index} {message}\n"));
                return false;
            }
        };
        if table.signature != *b"APIC" { continue; }
        if found_madt {
            serial::write_line("WOLFOS_ACPI_MADT_ERROR duplicate MADT");
            return false;
        }
        found_madt = true;
        let summary = match parse_madt(&table) {
            Ok(summary) => summary,
            Err(error) => {
                serial::write_fmt(format_args!("WOLFOS_ACPI_MADT_ERROR {error:?}\n"));
                return false;
            }
        };
        let enabled = summary.enabled_lapic + summary.enabled_x2apic;
        serial::write_fmt(format_args!(
            "WOLFOS_ACPI_MADT_OK enabled_cpus={} lapic={} x2apic={} ioapic={} online_capable={} entries={} lapic_phys={:#x}\n",
            enabled, summary.enabled_lapic, summary.enabled_x2apic,
            summary.io_apics, summary.online_capable,
            summary.entries, summary.local_apic_phys
        ));
        if enabled == 0 {
            serial::write_line("WOLFOS_ACPI_MADT_ERROR no enabled processors");
            return false;
        }
    }
    if !found_madt {
        serial::write_line("WOLFOS_ACPI_MADT_ERROR no APIC table");
    }
    found_madt
}
