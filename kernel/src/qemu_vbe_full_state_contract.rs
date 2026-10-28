//! Pure read-only register invariants needed before any future VBE mode-set.
use crate::{
    qemu_dispi_contract::DispiObservation,
    qemu_vbe_transaction_contract,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FullVbeState {
    pub selector_before: u16,
    pub selector_after: u16,
    pub bank: u16,
    pub virtual_width: u16,
    pub virtual_height: u16,
    pub x_offset: u16,
    pub y_offset: u16,
}

impl FullVbeState {
    pub fn safe_for_future_restore(self, device: DispiObservation) -> bool {
        if !qemu_vbe_transaction_contract::may_attempt(device)
            || self.selector_before != self.selector_after
            || self.selector_before != device.selector_before
            || self.bank != 0 || self.x_offset != 0 || self.y_offset != 0
            || self.virtual_width < device.xres
            || self.virtual_height < device.yres
        {
            return false;
        }
        let Some(bytes_per_row) = u64::from(self.virtual_width).checked_mul(4) else {
            return false;
        };
        let Some(bytes) = bytes_per_row.checked_mul(u64::from(self.virtual_height)) else {
            return false;
        };
        bytes <= u64::from(device.vram64k) * 65536
    }

    pub fn unchanged(self, after: Self, device: DispiObservation) -> bool {
        self.safe_for_future_restore(device)
            && after.safe_for_future_restore(device)
            && self == after
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const OBS: DispiObservation = DispiObservation {
        selector_before: 10, selector_after: 10,
        id: 0xb0c5, xres: 1280, yres: 800, bpp: 32,
        enable: 0x41, vram64k: 256,
    };
    const GOOD: FullVbeState = FullVbeState {
        selector_before: 10, selector_after: 10,
        bank: 0, virtual_width: 1280, virtual_height: 3276,
        x_offset: 0, y_offset: 0,
    };
    #[test]
    fn valid_qemu_full_layout_is_safe() {
        assert!(GOOD.safe_for_future_restore(OBS));
        assert!(GOOD.unchanged(GOOD, OBS));
    }
    #[test]
    fn bank_must_be_zero_under_lfb() {
        assert!(!FullVbeState { bank: 1, ..GOOD }.safe_for_future_restore(OBS));
    }
    #[test]
    fn horizontal_pan_must_be_zero_for_firmware_framebuffer() {
        assert!(!FullVbeState { x_offset: 1, ..GOOD }.safe_for_future_restore(OBS));
    }
    #[test]
    fn vertical_pan_must_be_zero_for_firmware_framebuffer() {
        assert!(!FullVbeState { y_offset: 1, ..GOOD }.safe_for_future_restore(OBS));
    }
    #[test]
    fn virtual_width_must_cover_physical_width() {
        assert!(!FullVbeState { virtual_width: 1279, ..GOOD }.safe_for_future_restore(OBS));
    }
    #[test]
    fn virtual_height_must_cover_scanout_height() {
        assert!(!FullVbeState { virtual_height: 799, ..GOOD }.safe_for_future_restore(OBS));
    }
    #[test]
    fn virtual_plane_must_fit_available_vram() {
        assert!(!FullVbeState { virtual_width: 8192, ..GOOD }.safe_for_future_restore(OBS));
        assert!(!FullVbeState { virtual_height: 5000, ..GOOD }.safe_for_future_restore(OBS));
    }
    #[test]
    fn valid_framebuffer_with_virtual_plane_padding_is_ok() {
        assert!(FullVbeState { virtual_height: 3276, ..GOOD }.safe_for_future_restore(OBS));
    }
    #[test]
    fn selector_must_be_restored() {
        assert!(!FullVbeState { selector_after: 0, ..GOOD }.safe_for_future_restore(OBS));
        assert!(!FullVbeState { selector_before: 1, selector_after: 1, ..GOOD }
            .safe_for_future_restore(OBS));
    }
    #[test]
    fn no_transaction_state_leak_after_toggle() {
        for altered in [
            FullVbeState { bank: 2, ..GOOD },
            FullVbeState { virtual_width: 1288, ..GOOD },
            FullVbeState { virtual_height: 3275, ..GOOD },
            FullVbeState { x_offset: 1, ..GOOD },
            FullVbeState { y_offset: 1, ..GOOD },
        ] {
            assert!(!GOOD.unchanged(altered, OBS));
        }
    }
    #[test]
    fn unknown_or_disabled_device_rejected() {
        assert!(!GOOD.safe_for_future_restore(DispiObservation { enable: 0, ..OBS }));
        assert!(!GOOD.safe_for_future_restore(DispiObservation { id: 0xb0c4, ..OBS }));
    }
}
