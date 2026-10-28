//! Allocation-free early display policy. PCI identity is NOT a loaded driver.
//!
//! Real vendor-specific kernel drivers, signed package validation, firmware,
//! BAR mapping, DMA, hotplug and accelerated graphics are NOT implemented.
//! Until then a validated bootloader-provided framebuffer is the only
//! permitted display backend. Never write to PCI device registers here.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayVendor {
    Nvidia,
    Amd,
    Intel,
    Qemu,
    Virtio,
    Other,
}

impl DisplayVendor {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Nvidia => "nvidia",
            Self::Amd => "amd",
            Self::Intel => "intel",
            Self::Qemu => "qemu",
            Self::Virtio => "virtio",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayIdentity {
    pub vendor_id: u16,
    pub device_id: u16,
    pub family: DisplayVendor,
}

impl DisplayIdentity {
    /// Read-only PCI display-class identity. Classification does not
    /// authorize loading firmware, mapping BARs or claiming support.
    pub const fn from_pci(vendor_id: u16, device_id: u16, class: u8) -> Option<Self> {
        if class != 0x03 || vendor_id == 0xffff || vendor_id == 0 {
            return None;
        }
        let family = match vendor_id {
            0x10de => DisplayVendor::Nvidia,
            0x1002 => DisplayVendor::Amd,
            0x8086 => DisplayVendor::Intel,
            0x1234 | 0x1b36 => DisplayVendor::Qemu,
            0x1af4 => DisplayVendor::Virtio,
            _ => DisplayVendor::Other,
        };
        Some(Self { vendor_id, device_id, family })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootDisplayBackend {
    /// Limine handed the kernel a framebuffer that has passed the kernel's
    /// RGB/stride/pointer checks. Does NOT imply native GPU acceleration.
    LimineFramebuffer,
    /// No verified framebuffer and no vetted native driver: fail closed.
    Unavailable,
}

impl BootDisplayBackend {
    pub const fn label(self) -> &'static str {
        match self {
            Self::LimineFramebuffer => "limine-framebuffer",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayDriverPlan {
    pub backend: BootDisplayBackend,
    pub native_acceleration: bool,
    pub native_driver_loaded: bool,
}

pub const fn early_boot_plan(validated_boot_framebuffer: bool) -> DisplayDriverPlan {
    DisplayDriverPlan {
        backend: if validated_boot_framebuffer {
            BootDisplayBackend::LimineFramebuffer
        } else {
            BootDisplayBackend::Unavailable
        },
        native_acceleration: false,
        native_driver_loaded: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vendor_ids_are_classified_only_as_identity() {
        for (vendor, expected) in [
            (0x10de, DisplayVendor::Nvidia),
            (0x1002, DisplayVendor::Amd),
            (0x8086, DisplayVendor::Intel),
            (0x1234, DisplayVendor::Qemu),
            (0x1b36, DisplayVendor::Qemu),
            (0x1af4, DisplayVendor::Virtio),
            (0x15ad, DisplayVendor::Other),
            (0x9999, DisplayVendor::Other),
        ] {
            let id = DisplayIdentity::from_pci(vendor, 0x1234, 0x03).unwrap();
            assert_eq!(id.family, expected);
            assert_eq!(id.vendor_id, vendor);
            assert_eq!(id.device_id, 0x1234);
        }
    }

    #[test]
    fn reject_non_display_pci_classes() {
        for class in [0x00, 0x01, 0x02, 0x04, 0x06, 0x0c, 0xff] {
            assert_eq!(DisplayIdentity::from_pci(0x10de, 0x1234, class), None);
        }
    }

    #[test]
    fn reject_absent_or_malformed_vendor() {
        for vendor in [0, 0xffff] {
            assert_eq!(DisplayIdentity::from_pci(vendor, 0x1, 0x03), None);
        }
    }

    #[test]
    fn accept_all_display_subtypes_without_pretending_driver_support() {
        for device in [0x0000, 0x1111, 0x1234, 0xffff] {
            assert!(DisplayIdentity::from_pci(0x10de, device, 0x03).is_some());
        }
    }

    #[test]
    fn unverified_framebuffer_never_enables_native_driver() {
        let decision = early_boot_plan(false);
        assert_eq!(decision.backend, BootDisplayBackend::Unavailable);
        assert_eq!(decision.backend.label(), "unavailable");
        assert!(!decision.native_acceleration);
        assert!(!decision.native_driver_loaded);
    }

    #[test]
    fn verified_firmware_fallback_does_not_claim_acceleration() {
        let decision = early_boot_plan(true);
        assert_eq!(decision.backend, BootDisplayBackend::LimineFramebuffer);
        assert_eq!(decision.backend.label(), "limine-framebuffer");
        assert!(!decision.native_acceleration);
        assert!(!decision.native_driver_loaded);
    }

    #[test]
    fn vendor_labels_are_stable_and_explicit() {
        assert_eq!(DisplayVendor::Nvidia.label(), "nvidia");
        assert_eq!(DisplayVendor::Amd.label(), "amd");
        assert_eq!(DisplayVendor::Intel.label(), "intel");
        assert_eq!(DisplayVendor::Qemu.label(), "qemu");
        assert_eq!(DisplayVendor::Virtio.label(), "virtio");
        assert_eq!(DisplayVendor::Other.label(), "other");
    }
}
