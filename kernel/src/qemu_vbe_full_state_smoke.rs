//! QEMU stdvga full restore-snapshot readback. No data-register writes.
//! Read extra Bochs VBE indexes 5..9 before/after the isolated control-bit
//! transaction. Reject any untracked virtual plane or panning change.

use core::arch::asm;
use crate::{
    qemu_dispi_contract::DispiObservation,
    qemu_vbe_full_state_contract::FullVbeState,
    serial,
};

const INDEX: u16 = 0x01ce;
const DATA: u16 = 0x01cf;

#[inline]
fn read_word(port: u16) -> u16 {
    let value: u16;
    // SAFETY: QEMU-only BSP with interrupts disabled; this reads a register.
    unsafe {
        asm!("in ax, dx", in("dx") port, out("ax") value,
            options(nomem, nostack, preserves_flags));
    }
    value
}

#[inline]
fn select(index: u16) {
    // SAFETY: writes only the index/selector port and restores it after reads.
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

fn sample() -> FullVbeState {
    let selector_before = read_word(INDEX);
    let bank = register(5);
    let virtual_width = register(6);
    let virtual_height = register(7);
    let x_offset = register(8);
    let y_offset = register(9);
    select(selector_before);
    FullVbeState {
        selector_before,
        selector_after: read_word(INDEX),
        bank, virtual_width, virtual_height, x_offset, y_offset,
    }
}

pub(crate) fn capture(device: DispiObservation) -> Option<FullVbeState> {
    let state = sample();
    if !state.safe_for_future_restore(device) {
        serial::write_fmt(format_args!(
            "WOLFOS_QEMU_VBE_FULL_FAIL stage=before bank={} virtw={} virth={} xoff={} yoff={} selector_before={} selector_after={}\n",
            state.bank, state.virtual_width, state.virtual_height,
            state.x_offset, state.y_offset, state.selector_before, state.selector_after,
        ));
        return None;
    }
    serial::write_fmt(format_args!(
        "WOLFOS_QEMU_VBE_FULL_BEFORE bank={} virtw={} virth={} xoff={} yoff={} selector_restored=1 data_writes=0\n",
        state.bank, state.virtual_width, state.virtual_height, state.x_offset, state.y_offset,
    ));
    Some(state)
}

pub(crate) fn verify_after(before: FullVbeState, device: DispiObservation) -> bool {
    let state = sample();
    if !before.unchanged(state, device) {
        serial::write_fmt(format_args!(
            "WOLFOS_QEMU_VBE_FULL_FAIL stage=after bank={} virtw={} virth={} xoff={} yoff={} selector_before={} selector_after={}\n",
            state.bank, state.virtual_width, state.virtual_height,
            state.x_offset, state.y_offset, state.selector_before, state.selector_after,
        ));
        return false;
    }
    serial::write_fmt(format_args!(
        "WOLFOS_QEMU_VBE_FULL_AFTER bank={} virtw={} virth={} xoff={} yoff={} selector_restored=1 data_writes=0\n",
        state.bank, state.virtual_width, state.virtual_height, state.x_offset, state.y_offset,
    ));
    serial::write_line(
        "WOLFOS_QEMU_VBE_FULL_STATE_OK snapshots_equal=1 bank_zero=1 pan_zero=1 virtual_plane_bounded=1 tx_writes=2 native_accel=0"
    );
    true
}
