//! Pure policy for QEMU-only reversible 1280x800 -> 1024x768 -> 1280x800
//! Bochs VBE mode transition. Do not permit mode writes on physical GPUs.

use crate::{
    qemu_dispi_contract::DispiObservation,
    qemu_vbe_full_state_contract::FullVbeState,
    qemu_vbe_transaction_contract,
};

pub const TARGET_WIDTH: u16 = 1024;
pub const TARGET_HEIGHT: u16 = 768;
pub const DEPTH: u16 = 32;
pub const TEMP_ENABLE: u16 = 0x00c1;
pub const RESTORE_ENABLE: u16 = 0x0041;

pub fn may_attempt(original: DispiObservation, full: FullVbeState) -> bool {
    qemu_vbe_transaction_contract::may_attempt(original)
        && original.xres == 1280
        && original.yres == 800
        && full.safe_for_future_restore(original)
        && full.virtual_width == original.xres
}

pub fn switched_as_expected(
    original: DispiObservation,
    temporary: DispiObservation,
    full: FullVbeState,
) -> bool {
    if !qemu_vbe_transaction_contract::may_attempt(original)
        || original.xres != 1280 || original.yres != 800
    {
        return false;
    }
    if temporary.selector_before != original.selector_before
        || temporary.selector_after != original.selector_before
        || temporary.id != original.id || temporary.vram64k != original.vram64k
        || temporary.xres != TARGET_WIDTH || temporary.yres != TARGET_HEIGHT
        || temporary.bpp != DEPTH || temporary.enable != TEMP_ENABLE
        || !temporary.valid()
    {
        return false;
    }
    if full.bank != 0 || full.x_offset != 0 || full.y_offset != 0
        || full.selector_before != original.selector_before
        || full.selector_after != original.selector_before
        || full.virtual_width < TARGET_WIDTH
        || full.virtual_height < TARGET_HEIGHT
    {
        return false;
    }
    u64::from(full.virtual_width) * u64::from(full.virtual_height) * 4
        <= u64::from(original.vram64k) * 65536
}

pub fn rollback_exact(
    original: DispiObservation, before: FullVbeState,
    restored: DispiObservation, after: FullVbeState, pixel_ok: bool,
) -> bool {
    may_attempt(original, before)
        && restored == original
        && after == before
        && pixel_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    const ORIG: DispiObservation = DispiObservation {
        selector_before: 10, selector_after: 10,
        id: 0xb0c5, xres: 1280, yres: 800, bpp: 32, enable: 0x41, vram64k: 256,
    };
    const BEFORE: FullVbeState = FullVbeState {
        selector_before: 10, selector_after: 10, bank: 0,
        virtual_width: 1280, virtual_height: 3276, x_offset: 0, y_offset: 0,
    };
    const TEMP: DispiObservation = DispiObservation {
        xres: TARGET_WIDTH, yres: TARGET_HEIGHT, enable: TEMP_ENABLE, ..ORIG
    };
    const TEMP_FULL: FullVbeState = FullVbeState {
        virtual_width: TARGET_WIDTH, virtual_height: 4096, ..BEFORE
    };
    #[test]
    fn genuine_qemu_1280_to_1024_preflight() { assert!(may_attempt(ORIG, BEFORE)); }
    #[test]
    fn refuse_other_initial_resolution() {
        assert!(!may_attempt(DispiObservation { xres: 1024, ..ORIG }, BEFORE));
        assert!(!may_attempt(DispiObservation { yres: 768, ..ORIG }, BEFORE));
    }
    #[test]
    fn refuse_malformed_original_virtual_state() {
        assert!(!may_attempt(ORIG, FullVbeState { bank: 1, ..BEFORE }));
        assert!(!may_attempt(ORIG, FullVbeState { x_offset: 8, ..BEFORE }));
    }
    #[test]
    fn forbid_virtual_stride_tampering() {
        assert!(!may_attempt(ORIG, FullVbeState { virtual_width: 1296, ..BEFORE }));
    }
    #[test]
    fn new_mode_and_virtual_state_match() {
        assert!(switched_as_expected(ORIG, TEMP, TEMP_FULL));
    }
    #[test]
    fn deny_wrong_temporary_control_flags() {
        assert!(!switched_as_expected(ORIG, DispiObservation { enable: 0x41, ..TEMP }, TEMP_FULL));
        assert!(!switched_as_expected(ORIG, DispiObservation { enable: 0, ..TEMP }, TEMP_FULL));
    }
    #[test]
    fn deny_wrong_temporary_geometry() {
        assert!(!switched_as_expected(ORIG, DispiObservation { xres: 1000, ..TEMP }, TEMP_FULL));
        assert!(!switched_as_expected(ORIG, DispiObservation { bpp: 24, ..TEMP }, TEMP_FULL));
    }
    #[test]
    fn deny_temporary_pan_or_bank() {
        assert!(!switched_as_expected(ORIG, TEMP, FullVbeState { bank: 1, ..TEMP_FULL }));
        assert!(!switched_as_expected(ORIG, TEMP, FullVbeState { y_offset: 1, ..TEMP_FULL }));
    }
    #[test]
    fn deny_temporary_plane_exceeding_vram() {
        assert!(!switched_as_expected(ORIG, TEMP, FullVbeState { virtual_height: 5000, ..TEMP_FULL }));
    }
    #[test]
    fn deny_temporary_selector_or_vram_drift() {
        assert!(!switched_as_expected(ORIG, DispiObservation { selector_after: 0, ..TEMP }, TEMP_FULL));
        assert!(!switched_as_expected(ORIG, DispiObservation { vram64k: 1, ..TEMP }, TEMP_FULL));
    }
    #[test]
    fn rollback_exact_original_and_pixel() {
        assert!(rollback_exact(ORIG, BEFORE, ORIG, BEFORE, true));
    }
    #[test]
    fn no_pixel_means_no_success() {
        assert!(!rollback_exact(ORIG, BEFORE, ORIG, BEFORE, false));
    }
    #[test]
    fn rollback_must_restore_mode_and_full_plane() {
        assert!(!rollback_exact(ORIG, BEFORE, TEMP, BEFORE, true));
        assert!(!rollback_exact(ORIG, BEFORE, ORIG,
            FullVbeState { virtual_width: 1288, ..BEFORE }, true));
    }
}
