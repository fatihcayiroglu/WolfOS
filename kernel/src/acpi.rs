//! Read-only ACPI firmware discovery using Limine's RSDP virtual pointer.
//! Limine base revision 0 guarantees this is a virtual address on x86-64.
//! Firmware memory is read but never modified. Tables not yet enumerated.

use crate::acpi_layout::{parse_rsdp, MAX_RSDP_SIZE, MIN_RSDP_SIZE, ACPI_V2_RSDP_SIZE};
use crate::serial;

pub fn report_rsdp(rsdp_address: *mut ()) -> bool {
    if rsdp_address.is_null() {
        serial::write_line("WOLFOS_ACPI_ERROR null RSDP");
        return false;
    }
    let ptr = rsdp_address.cast::<u8>();
    let mut bytes = [0_u8; MAX_RSDP_SIZE];

    // SAFETY: Limine promises the RSDP virtual pointer maps valid firmware
    // memory for the RSDP size on base revision 0. The first 20 bytes
    // always exist when RSDP is present. Never write firmware memory.
    for (i, dst) in bytes[..MIN_RSDP_SIZE].iter_mut().enumerate() {
        *dst = unsafe { ptr.add(i).read_volatile() };
    }

    let mut length = MIN_RSDP_SIZE;
    if bytes[15] >= 2 {
        // SAFETY: ACPI revision >= 2 RSDP has at least 36 mapped bytes.
        for (i, dst) in bytes[MIN_RSDP_SIZE..ACPI_V2_RSDP_SIZE].iter_mut().enumerate() {
            *dst = unsafe { ptr.add(MIN_RSDP_SIZE + i).read_volatile() };
        }
        length = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
        if !(ACPI_V2_RSDP_SIZE..=MAX_RSDP_SIZE).contains(&length) {
            serial::write_line("WOLFOS_ACPI_ERROR invalid extended length");
            return false;
        }
        // SAFETY: Firmware provides the indicated contiguous RSDP length.
        for (i, dst) in bytes[ACPI_V2_RSDP_SIZE..length].iter_mut().enumerate() {
            *dst = unsafe { ptr.add(ACPI_V2_RSDP_SIZE + i).read_volatile() };
        }
    }
    match parse_rsdp(&bytes[..length]) {
        Ok(info) => {
            let oem = core::str::from_utf8(&info.oem_id).unwrap_or("??????");
            serial::write_fmt(format_args!(
                "WOLFOS_ACPI_RSDP_OK revision={} oem={} rsdt={:#x} xsdt={:#x} length={}\n",
                info.revision, oem, info.rsdt_physical,
                info.xsdt_physical.unwrap_or(0), info.length
            ));
            true
        }
        Err(err) => {
            serial::write_fmt(format_args!("WOLFOS_ACPI_ERROR {err:?}\n"));
            false
        }
    }
}
