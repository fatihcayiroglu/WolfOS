//! Read-only early x86-64 CPU identification.
//! This identifies the virtual/physical CPU; it does not install drivers.

use core::arch::x86_64::__cpuid;

use crate::serial;

pub fn log_identity() {
    // CPUID is mandatory on x86-64. Leaf 0 reports maximum basic leaf.
    let identity = __cpuid(0);
    let mut vendor_bytes = [0_u8; 12];
    vendor_bytes[0..4].copy_from_slice(&identity.ebx.to_le_bytes());
    vendor_bytes[4..8].copy_from_slice(&identity.edx.to_le_bytes());
    vendor_bytes[8..12].copy_from_slice(&identity.ecx.to_le_bytes());
    let vendor = core::str::from_utf8(&vendor_bytes).unwrap_or("unknown");

    if identity.eax < 1 {
        serial::write_fmt(format_args!(
            "WOLFOS_CPU_OK vendor={} feature_leaf=unavailable\n",
            vendor
        ));
        return;
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
    let sse2 = (features.edx & (1 << 26)) != 0;
    let hypervisor = (features.ecx & (1 << 31)) != 0;

    serial::write_fmt(format_args!(
        "WOLFOS_CPU_OK vendor={} family={} model={} sse2={} hypervisor={}\n",
        vendor, family, model, sse2, hypervisor
    ));
}
