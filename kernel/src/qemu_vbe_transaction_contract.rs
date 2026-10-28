//! Pure preflight and evidence contract for a *QEMU-only* idempotent
//! Bochs VBE ENABLE toggle: 0x0041 -> 0x00c1 -> 0x0041.
//! This is a virtual-device control write, not a vendor GPU driver.

use crate::qemu_dispi_contract::DispiObservation;

pub const ENABLE_INDEX: u16 = 4;
pub const INITIAL_ENABLE: u16 = 0x0041;
pub const TRANSIENT_ENABLE: u16 = 0x00c1;

pub fn may_attempt(observation: DispiObservation) -> bool {
    observation.valid()
        && observation.id == 0xb0c5
        && observation.enable == INITIAL_ENABLE
        && observation.bpp == 32
        && observation.xres > 0
        && observation.yres > 0
}

pub fn restored_exactly(
    original: DispiObservation, transient: u16, restored: u16,
    after: DispiObservation, pixel_preserved: bool,
) -> bool {
    may_attempt(original)
        && transient == TRANSIENT_ENABLE
        && restored == INITIAL_ENABLE
        && after == original
        && pixel_preserved
}

#[cfg(test)]
mod tests {
    use super::*;
    const VALID: DispiObservation = DispiObservation {
        selector_before: 0x000a, selector_after: 0x000a,
        id: 0xb0c5, xres: 1280, yres: 800, bpp: 32,
        enable: INITIAL_ENABLE, vram64k: 256,
    };
    #[test]
    fn exact_qemu_enabled_lfb_is_allowed() { assert!(may_attempt(VALID)); }
    #[test]
    fn disabled_or_unexpected_control_bits_refused() {
        for bits in [0, 1, 0x40, 0x81, 0xc1, 0x21, 0x141] {
            assert!(!may_attempt(DispiObservation { enable: bits, ..VALID }));
        }
    }
    #[test]
    fn only_known_virtual_device_revision_allowed() {
        for id in [0, 0xb0c0, 0xb0c3, 0xb0c4, 0xb0c6] {
            assert!(!may_attempt(DispiObservation { id, ..VALID }));
        }
    }
    #[test]
    fn only_packed_32_bit_is_used() {
        for bpp in [0, 8, 15, 16, 24] {
            assert!(!may_attempt(DispiObservation { bpp, ..VALID }));
        }
    }
    #[test]
    fn no_selector_restoration_means_no_writes() {
        assert!(!may_attempt(DispiObservation { selector_after: 2, ..VALID }));
    }
    #[test]
    fn malformed_zero_vram_means_no_writes() {
        assert!(!may_attempt(DispiObservation { vram64k: 0, ..VALID }));
    }
    #[test]
    fn successful_reversible_enable_bit_toggle() {
        assert!(restored_exactly(VALID, TRANSIENT_ENABLE, INITIAL_ENABLE, VALID, true));
    }
    #[test]
    fn wrong_transient_value_is_failure() {
        assert!(!restored_exactly(VALID, INITIAL_ENABLE, INITIAL_ENABLE, VALID, true));
    }
    #[test]
    fn no_final_restore_is_failure() {
        assert!(!restored_exactly(VALID, TRANSIENT_ENABLE, TRANSIENT_ENABLE, VALID, true));
    }
    #[test]
    fn changed_geometry_is_failure() {
        let changed = DispiObservation { xres: 1024, ..VALID };
        assert!(!restored_exactly(VALID, TRANSIENT_ENABLE, INITIAL_ENABLE, changed, true));
    }
    #[test]
    fn changed_vram_or_bpp_is_failure() {
        assert!(!restored_exactly(VALID, TRANSIENT_ENABLE, INITIAL_ENABLE,
            DispiObservation { vram64k: 255, ..VALID }, true));
        assert!(!restored_exactly(VALID, TRANSIENT_ENABLE, INITIAL_ENABLE,
            DispiObservation { bpp: 24, ..VALID }, true));
    }
    #[test]
    fn lost_framebuffer_sentinel_is_failure() {
        assert!(!restored_exactly(VALID, TRANSIENT_ENABLE, INITIAL_ENABLE, VALID, false));
    }
    #[test]
    fn selector_mismatch_after_transaction_is_failure() {
        assert!(!restored_exactly(VALID, TRANSIENT_ENABLE, INITIAL_ENABLE,
            DispiObservation { selector_after: 11, ..VALID }, true));
    }
}
