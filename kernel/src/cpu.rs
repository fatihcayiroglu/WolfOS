//! Read-only early x86-64 CPU identification.
//! This identifies the virtual/physical CPU; it does not install drivers.

use core::arch::x86_64::__cpuid;
use crate::serial;

#[derive(Clone, Copy)]
pub struct Identity {
    vendor: [u8; 12],
    pub family: Option<u32>,
    pub model: Option<u32>,
    pub sse2: bool,
    pub hypervisor: bool,
}

impl Identity {
    /// CPUID vendor bytes are not guaranteed to be printable display text.
    pub fn vendor_name(&self) -> &str {
        match core::str::from_utf8(&self.vendor) {
            Ok(name) if name.bytes().all(|byte| byte.is_ascii_graphic()) => name,
            _ => "unknown",
        }
    }
}

pub fn identify() -> Identity {
    // CPUID is mandatory on x86-64. Leaf 0 reports maximum basic leaf.
    let leaf0 = __cpuid(0);
    let mut vendor = [0_u8; 12];
    vendor[0..4].copy_from_slice(&leaf0.ebx.to_le_bytes());
    vendor[4..8].copy_from_slice(&leaf0.edx.to_le_bytes());
    vendor[8..12].copy_from_slice(&leaf0.ecx.to_le_bytes());

    if leaf0.eax < 1 {
        return Identity {
            vendor, family: None, model: None,
            sse2: false, hypervisor: false,
        };
    }

    let features = __cpuid(1);
    let base_family = (features.eax >> 8) & 0x0f;
    let base_model = (features.eax >> 4) & 0x0f;
    let extended_family = (features.eax >> 20) & 0xff;
    let extended_model = (features.eax >> 16) & 0x0f;
    let family = if base_family == 0x0f {
        base_family + extended_family
    } else {
        base_family
    };
    let model = if base_family == 0x06 || base_family == 0x0f {
        base_model | (extended_model << 4)
    } else {
        base_model
    };

    Identity {
        vendor,
        family: Some(family),
        model: Some(model),
        sse2: features.edx & (1 << 26) != 0,
        hypervisor: features.ecx & (1 << 31) != 0,
    }
}

pub fn log_identity() {
    let cpu = identify();
    let vendor = cpu.vendor_name();
    if let (Some(family), Some(model)) = (cpu.family, cpu.model) {
        serial::write_fmt(format_args!(
            "WOLFOS_CPU_OK vendor={} family={} model={} sse2={} hypervisor={}\n",
            vendor, family, model, cpu.sse2, cpu.hypervisor,
        ));
    } else {
        serial::write_fmt(format_args!(
            "WOLFOS_CPU_OK vendor={} feature_leaf=unavailable\n", vendor,
        ));
    }
}
