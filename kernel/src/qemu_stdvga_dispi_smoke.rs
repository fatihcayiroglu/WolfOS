//! QEMU standard-VGA Bochs VBE *read-only* capability observation.
//! Only the port INDEX selector (0x1ce) is written and restored.
//! No mode/data-register writes, PCI config writes, BAR mapping or DMA.
//! Feature-gated; BSP-only before other CPUs launch and with IRQs masked.

use core::arch::asm;
use crate::{qemu_dispi_contract::DispiObservation, serial};

const SELECTOR: u16 = 0x01ce;
const DATA: u16 = 0x01cf;

#[inline]
fn read_word(port: u16) -> u16 {
    let value: u16;
    // SAFETY: feature runs only on an isolated QEMU stdvga device
    // recognized at PCI 1234:1111, before AP startup. x86 I/O read only.
    unsafe {
        asm!("in ax, dx", in("dx") port, out("ax") value,
             options(nomem, nostack, preserves_flags));
    }
    value
}

#[inline]
fn select(index: u16) {
    // SAFETY: this writes ONLY the Bochs VBE index/selector port, never
    // the data port or a device configuration register. Selector restored.
    unsafe {
        asm!("out dx, ax", in("dx") SELECTOR, in("ax") index,
             options(nomem, nostack, preserves_flags));
    }
}

#[inline]
fn register(index: u16) -> u16 {
    select(index);
    read_word(DATA)
}

/// True guest I/O exercise: exactly one verified QEMU stdvga PCI device.
/// Caller must invoke before SMP boot and with interrupts disabled.
pub(crate) fn prove(stdvga_devices: usize) -> bool {
    if stdvga_devices != 1 {
        serial::write_line("WOLFOS_QEMU_DISPI_PROBE_FAIL stage=pci");
        return false;
    }
    let original = read_word(SELECTOR);
    let id = register(0);
    let xres = register(1);
    let yres = register(2);
    let bpp = register(3);
    let enable = register(4);
    let vram64k = register(10);
    select(original);
    let sample = DispiObservation {
        selector_before: original,
        selector_after: read_word(SELECTOR),
        id, xres, yres, bpp, enable, vram64k,
    };
    if !sample.valid() {
        serial::write_fmt(format_args!(
            "WOLFOS_QEMU_DISPI_PROBE_FAIL stage=observation id={:04x} xres={} yres={} bpp={} enable={} vram64k={} index_before={} index_after={}\n",
            id, xres, yres, bpp, enable, vram64k,
            original, sample.selector_after,
        ));
        return false;
    }
    serial::write_fmt(format_args!(
        "WOLFOS_QEMU_DISPI_PROBE_OK pci=1234:1111 id={:04x} xres={} yres={} bpp={} enabled={} vram64k={} selector_restored=1 mode_writes=0 native_accel=0\n",
        id, xres, yres, bpp, enable, vram64k,
    ));
    true
}
