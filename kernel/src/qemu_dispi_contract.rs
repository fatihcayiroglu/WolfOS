//! Pure bounds/audit contract for the QEMU standard-VGA Bochs VBE probe.
//! No guest port I/O lives here; host tests can check forged observations.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispiObservation {
    pub selector_before: u16,
    pub selector_after: u16,
    pub id: u16,
    pub xres: u16,
    pub yres: u16,
    pub bpp: u16,
    pub enable: u16,
    pub vram64k: u16,
}

impl DispiObservation {
    pub const fn valid(self) -> bool {
        // Hardware index selector must be restored even on success.
        if self.selector_before != self.selector_after
            || !(self.id >= 0xb0c0 && self.id <= 0xb0c5)
            || self.vram64k == 0
        { return false; }
        if self.enable & 1 != 0 {
            if self.xres == 0 || self.yres == 0
                || self.xres > 8192 || self.yres > 8192
            { return false; }
            let bytes_per_pixel = match self.bpp {
                4 | 8 => 1u64,
                15 | 16 => 2,
                24 => 3,
                32 => 4,
                _ => return false,
            };
            let needed = self.xres as u64 * self.yres as u64 * bytes_per_pixel;
            let available = self.vram64k as u64 * 65536;
            if needed > available { return false; }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: DispiObservation = DispiObservation {
        selector_before: 7, selector_after: 7,
        id: 0xb0c5, xres: 1024, yres: 768,
        bpp: 32, enable: 0x41, vram64k: 256,
    };

    #[test]
    fn realistic_std_vga_observation_is_accepted() {
        assert!(GOOD.valid());
    }

    #[test]
    fn all_supported_vbe_ids_are_accepted() {
        for id in 0xb0c0..=0xb0c5 {
            assert!(DispiObservation { id, ..GOOD }.valid());
        }
    }

    #[test]
    fn wrong_vbe_id_is_refused() {
        for id in [0, 0xffff, 0xb0bf, 0xb0c6, 0x1234] {
            assert!(!DispiObservation { id, ..GOOD }.valid());
        }
    }

    #[test]
    fn no_video_memory_is_refused() {
        assert!(!DispiObservation { vram64k: 0, ..GOOD }.valid());
    }

    #[test]
    fn selector_must_be_restored() {
        assert!(!DispiObservation { selector_after: 0, ..GOOD }.valid());
    }

    #[test]
    fn enabled_mode_requires_dimensions() {
        for (xres, yres) in [(0, 768), (1024, 0), (0, 0)] {
            assert!(!DispiObservation { xres, yres, ..GOOD }.valid());
        }
    }

    #[test]
    fn enabled_mode_dimensions_are_bounded() {
        assert!(!DispiObservation { xres: 8193, ..GOOD }.valid());
        assert!(!DispiObservation { yres: 8193, ..GOOD }.valid());
    }

    #[test]
    fn enabled_mode_bpp_is_supported() {
        for bpp in [4, 8, 15, 16, 24, 32] {
            assert!(DispiObservation { bpp, ..GOOD }.valid());
        }
        for bpp in [0, 1, 2, 12, 17, 30, 64, 65535] {
            assert!(!DispiObservation { bpp, ..GOOD }.valid());
        }
    }

    #[test]
    fn reject_mode_larger_than_reported_vram() {
        assert!(!DispiObservation { vram64k: 1, ..GOOD }.valid());
        assert!(!DispiObservation {
            xres: 8192, yres: 8192, ..GOOD
        }.valid());
    }

    #[test]
    fn disabled_vbe_may_have_zero_mode_registers() {
        assert!(DispiObservation {
            xres: 0, yres: 0, bpp: 0, enable: 0, ..GOOD
        }.valid());
    }

    #[test]
    fn zero_selector_is_valid_when_preserved() {
        assert!(DispiObservation {
            selector_before: 0, selector_after: 0, ..GOOD
        }.valid());
    }
}
