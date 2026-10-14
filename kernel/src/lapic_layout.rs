//! Pure x86 local-APIC IA32_APIC_BASE register validation.
//! No MSR access, no_std and independently host-testable.

pub const IA32_APIC_BASE_MSR: u32 = 0x1b;
pub const APIC_BASE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
pub const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
pub const APIC_X2APIC_ENABLE: u64 = 1 << 10;
pub const APIC_BSP_FLAG: u64 = 1 << 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApicBase {
    pub physical_address: u64,
    pub x2apic: bool,
    pub bsp: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApicBaseError {
    GlobalApicDisabled,
    InvalidBaseAddress,
}

/// Interpret the register without writing it. Reject disabled/zero bases.
/// No MMIO or timer access is implied by successfully parsing this value.
pub fn parse_apic_base(raw: u64) -> Result<ApicBase, ApicBaseError> {
    if raw & APIC_GLOBAL_ENABLE == 0 {
        return Err(ApicBaseError::GlobalApicDisabled);
    }
    let physical_address = raw & APIC_BASE_ADDRESS_MASK;
    if physical_address == 0 {
        return Err(ApicBaseError::InvalidBaseAddress);
    }
    Ok(ApicBase {
        physical_address,
        x2apic: raw & APIC_X2APIC_ENABLE != 0,
        bsp: raw & APIC_BSP_FLAG != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_xapic_bsp_and_ap() {
        let bsp = parse_apic_base(0xfee0_0000 | APIC_BSP_FLAG | APIC_GLOBAL_ENABLE).unwrap();
        assert_eq!(bsp.physical_address, 0xfee0_0000);
        assert!(bsp.bsp);
        assert!(!bsp.x2apic);
        let ap = parse_apic_base(0xfee0_0000 | APIC_GLOBAL_ENABLE).unwrap();
        assert!(!ap.bsp);
    }

    #[test]
    fn x2apic_and_wide_physical_base() {
        let base = 0x0000_1234_5678_9000;
        let info = parse_apic_base(base | APIC_GLOBAL_ENABLE | APIC_X2APIC_ENABLE).unwrap();
        assert_eq!(info.physical_address, base);
        assert!(info.x2apic);
    }

    #[test]
    fn rejects_disabled_and_zero_base() {
        assert_eq!(parse_apic_base(0xfee0_0000), Err(ApicBaseError::GlobalApicDisabled));
        assert_eq!(parse_apic_base(APIC_GLOBAL_ENABLE), Err(ApicBaseError::InvalidBaseAddress));
    }
}
