//! QEMU PCI stdvga *test-only* controlled register write and rollback.
//! Only DISPI ENABLE (index 4) data receives two writes, and INDEX port
//! is restored; mode registers and one painted pixel must survive.
//! NEVER enabled in production boot or on vendor GPUs.

use core::arch::asm;
use crate::{
    qemu_dispi_contract::DispiObservation,
    qemu_vbe_transaction_contract as policy,
    serial,
};

const INDEX_PORT: u16 = 0x01ce;
const DATA_PORT: u16 = 0x01cf;

#[inline]
fn read_word(port: u16) -> u16 {
    let value: u16;
    // SAFETY: This feature is isolated to BSP QEMU -vga std, pre-SMP,
    // with interrupts disabled and exact PCI 1234:1111 proof.
    unsafe {
        asm!("in ax, dx", in("dx") port, out("ax") value,
            options(nomem, nostack, preserves_flags));
    }
    value
}

#[inline]
fn select(index: u16) {
    unsafe {
        asm!("out dx, ax", in("dx") INDEX_PORT, in("ax") index,
            options(nomem, nostack, preserves_flags));
    }
}

#[inline]
fn register(index: u16) -> u16 {
    select(index);
    read_word(DATA_PORT)
}

#[inline]
fn write_enable(value: u16) {
    // SAFETY: Exactly one gated QEMU virtual VGA ENABLE register is written.
    // Temporary bit is NOCLEARMEM; VBE stays enabled throughout.
    unsafe {
        asm!("out dx, ax", in("dx") DATA_PORT, in("ax") value,
            options(nomem, nostack, preserves_flags));
    }
}

/// Caller guarantees a validated mapped 32bpp Limine framebuffer pixel.
/// No real-device driver installs, no DMA, no mode geometry writes.
pub(crate) fn prove(observed: DispiObservation, pixel: *mut u32) -> bool {
    if !policy::may_attempt(observed) {
        serial::write_line("WOLFOS_QEMU_VBE_ENABLE_TX_FAIL stage=preflight");
        return false;
    }
    let selector = read_word(INDEX_PORT);
    if selector != observed.selector_before {
        serial::write_line("WOLFOS_QEMU_VBE_ENABLE_TX_FAIL stage=selector_before");
        return false;
    }
    select(policy::ENABLE_INDEX);
    let original_enable = read_word(DATA_PORT);
    if original_enable != policy::INITIAL_ENABLE {
        select(selector);
        serial::write_line("WOLFOS_QEMU_VBE_ENABLE_TX_FAIL stage=enable_before");
        return false;
    }

    // SAFETY: First checked 32-bit address in Limine's mapped framebuffer.
    // Save and restore the exact prior bytes, only in QEMU-only test flavor.
    let old_pixel = unsafe { pixel.read_volatile() };
    let witness = old_pixel ^ 0x00a5_5ac3;
    unsafe { pixel.write_volatile(witness); }

    // Bounded *reversible* VBE control-bit transaction; no resolution change.
    // Always issue the restoring second write even if first readback differs.
    write_enable(policy::TRANSIENT_ENABLE);
    let transient = read_word(DATA_PORT);
    write_enable(policy::INITIAL_ENABLE);
    let restored = read_word(DATA_PORT);

    let id = register(0);
    let xres = register(1);
    let yres = register(2);
    let bpp = register(3);
    let enable = register(4);
    let vram64k = register(10);
    select(selector);
    let after = DispiObservation {
        selector_before: selector,
        selector_after: read_word(INDEX_PORT),
        id, xres, yres, bpp, enable, vram64k,
    };
    let pixels_ok = unsafe { pixel.read_volatile() == witness };
    unsafe { pixel.write_volatile(old_pixel); }

    if !policy::restored_exactly(observed, transient, restored, after, pixels_ok) {
        serial::write_fmt(format_args!(
            "WOLFOS_QEMU_VBE_ENABLE_TX_FAIL stage=rollback transient={:04x} restored={:04x} enable={:04x} selector={:04x} pixel_ok={}\n",
            transient, restored, after.enable, after.selector_after, u8::from(pixels_ok),
        ));
        return false;
    }
    serial::write_line(
        "WOLFOS_QEMU_VBE_ENABLE_TX_OK pci=1234:1111 initial=0041 temporary=00c1 restored=0041 writes=2 selector_restored=1 geometry_preserved=1 pixel_preserved=1 native_accel=0"
    );
    true
}
