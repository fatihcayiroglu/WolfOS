//! QEMU-only transient *real* VBE mode change with unconditional rollback.
//! This is NOT a production GPU driver. Only exact PCI 1234:1111 / vga std,
//! single-vCPU opt-in test ISO, with the Limine framebuffer validated first.
//! On any post-write mismatch we restore the display mode and fail closed.

use core::arch::asm;
use crate::{
    qemu_dispi_contract::DispiObservation,
    qemu_vbe_full_state_contract::FullVbeState,
    qemu_vbe_mode_rollback_contract as policy,
    serial,
};

const INDEX: u16 = 0x01ce;
const DATA: u16 = 0x01cf;

#[inline]
fn read_word(port: u16) -> u16 {
    let value: u16;
    // SAFETY: Only the separately enabled QEMU stdvga BSP smoke target,
    // before SMP/interrupt enabling and after device/VRAM attestation.
    unsafe {
        asm!("in ax, dx", in("dx") port, out("ax") value,
            options(nomem, nostack, preserves_flags));
    }
    value
}
#[inline]
fn select(index: u16) {
    // SAFETY: Index-port selection on the gated QEMU Bochs VBE device.
    unsafe {
        asm!("out dx, ax", in("dx") INDEX, in("ax") index,
            options(nomem, nostack, preserves_flags));
    }
}
#[inline]
fn register(index: u16) -> u16 {
    select(index);
    read_word(DATA)
}
#[inline]
fn write(index: u16, value: u16) {
    select(index);
    // SAFETY: Exactly one of 11 documented, bounded QEMU VBE data writes,
    // all within the feature-isolated mode transaction and its rollback.
    unsafe {
        asm!("out dx, ax", in("dx") DATA, in("ax") value,
            options(nomem, nostack, preserves_flags));
    }
}
fn observe(selector: u16) -> DispiObservation {
    let id = register(0);
    let xres = register(1);
    let yres = register(2);
    let bpp = register(3);
    let enable = register(4);
    let vram64k = register(10);
    select(selector);
    DispiObservation {
        selector_before: selector,
        selector_after: read_word(INDEX),
        id, xres, yres, bpp, enable, vram64k,
    }
}
fn full(selector: u16) -> FullVbeState {
    let bank = register(5);
    let virtual_width = register(6);
    let virtual_height = register(7);
    let x_offset = register(8);
    let y_offset = register(9);
    select(selector);
    FullVbeState {
        selector_before: selector,
        selector_after: read_word(INDEX),
        bank, virtual_width, virtual_height, x_offset, y_offset,
    }
}

/// Caller has already verified the exact stdvga PCI ID, current VBE mode,
/// Limine RGB layout and full virtual-plane geometry. Pixel points to a
/// mapped, writable, volatile 32-bit framebuffer word.
/// The eleven data writes are: disable, new x/y/bpp, enable; then
/// disable, old x/y/bpp, enable-NOCLEAR, restore original ENABLE.
/// After the first write there is no early return before rollback.
pub(crate) fn prove(
    original: DispiObservation,
    before: FullVbeState,
    pixel: *mut u32,
) -> bool {
    if !policy::may_attempt(original, before) {
        serial::write_line("WOLFOS_QEMU_VBE_MODE_ROLLBACK_FAIL stage=preflight");
        return false;
    }
    let selector = read_word(INDEX);
    if selector != original.selector_before {
        serial::write_line("WOLFOS_QEMU_VBE_MODE_ROLLBACK_FAIL stage=selector_before");
        return false;
    }
    let original_enable = register(4);
    select(selector);
    if original_enable != policy::RESTORE_ENABLE {
        serial::write_line("WOLFOS_QEMU_VBE_MODE_ROLLBACK_FAIL stage=enable_before");
        return false;
    }

    // SAFETY: exact mapped 32bpp Limine framebuffer first pixel; restore
    // original 32-bit word whether verification succeeds or fails.
    let old_pixel = unsafe { pixel.read_volatile() };
    let witness = old_pixel ^ 0x005a_b6c3;
    unsafe { pixel.write_volatile(witness); }

    // Live switch to a smaller virtual QEMU display without clearing VRAM.
    write(4, 0x0000);                 // 1: disable VBE to permit geometry writes
    write(1, policy::TARGET_WIDTH);   // 2: new visible width
    write(2, policy::TARGET_HEIGHT);  // 3: new visible height
    write(3, policy::DEPTH);          // 4: packed 32bpp
    write(4, policy::TEMP_ENABLE);    // 5: enable LFB + NOCLEARMEM
    let temporary = observe(selector);
    let temporary_full = full(selector);

    // ALWAYS restore the original visible geometry, even on invalid
    // intermediate observations. NOCLEARMEM avoids destroying the witness.
    write(4, 0x0000);                 // 6: disable VBE again
    write(1, original.xres);         // 7: old width
    write(2, original.yres);         // 8: old height
    write(3, original.bpp);          // 9: old bpp
    write(4, policy::TEMP_ENABLE);    // 10: enable without clearing VRAM
    write(4, original.enable);       // 11: exact original ENABLE flags
    select(selector);
    let restored = observe(selector);
    let after = full(selector);
    let pixel_preserved = unsafe { pixel.read_volatile() == witness };
    unsafe { pixel.write_volatile(old_pixel); }
    let switched_ok = policy::switched_as_expected(original, temporary, temporary_full);
    let rollback_ok = policy::rollback_exact(original, before, restored, after, pixel_preserved);

    if !switched_ok || !rollback_ok {
        serial::write_fmt(format_args!(
            "WOLFOS_QEMU_VBE_MODE_ROLLBACK_FAIL stage=verified switched={} rollback={} temp={}x{} depth={} enable={:04x} temp_virt={}x{} restored={}x{} depth={} enable={:04x} restored_virt={}x{} selector={} pixel={}\n",
            u8::from(switched_ok), u8::from(rollback_ok),
            temporary.xres, temporary.yres, temporary.bpp, temporary.enable,
            temporary_full.virtual_width, temporary_full.virtual_height,
            restored.xres, restored.yres, restored.bpp, restored.enable,
            after.virtual_width, after.virtual_height,
            restored.selector_after, u8::from(pixel_preserved),
        ));
        return false;
    }

    serial::write_line(
        "WOLFOS_QEMU_VBE_MODE_ROLLBACK_OK from=1280x800 to=1024x768 restored=1280x800 writes=11 temporary_enable=00c1 restored_enable=0041 selector_restored=1 full_state_restored=1 pixel_preserved=1 native_accel=0"
    );
    true
}
