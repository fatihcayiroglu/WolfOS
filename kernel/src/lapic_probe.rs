//! Read-only, per-processor x86 local APIC identity/MSR discovery.
//!
//! A CPU samples its OWN IA32_APIC_BASE with RDMSR and its CPUID APIC ID.
//! Each Limine CPU index owns one independent atomic report. BSP observes
//! AP reports only after the AP_READY Release/Acquire synchronization.
//! Never write an MSR, APIC MMIO, send IPI, or enable maskable interrupts.

use core::arch::{asm, x86_64::{__cpuid, __cpuid_count}};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use limine::mp::MpInfo;

use crate::{lapic_layout, smp::MAX_BOOT_CPUS};

struct ProbeSlot {
    msr: AtomicU64,
    cpuid_apic_id: AtomicU32,
    sampled: AtomicBool,
    valid: AtomicBool,
}
impl ProbeSlot {
    const fn new() -> Self {
        Self {
            msr: AtomicU64::new(0),
            cpuid_apic_id: AtomicU32::new(0),
            sampled: AtomicBool::new(false),
            valid: AtomicBool::new(false),
        }
    }
}
static PROBES: [ProbeSlot; MAX_BOOT_CPUS] =
    [const { ProbeSlot::new() }; MAX_BOOT_CPUS];

pub struct Summary {
    pub cpus: usize,
    pub x2apic: usize,
    pub base: u64,
}

fn cpu_apic_id(max_basic_leaf: u32, leaf1_ebx: u32) -> u32 {
    if max_basic_leaf >= 0x0b {
        let topology = __cpuid_count(0x0b, 0);
        // Some virtual CPUs implement leaf 0xB but return an empty level.
        if topology.ebx != 0 && ((topology.ecx >> 8) & 0xff) != 0 {
            return topology.edx;
        }
    }
    (leaf1_ebx >> 24) & 0xff
}

/// Obtain a snapshot of the CURRENT CPU, without modifying any APIC state.
/// Do not execute RDMSR unless CPUID reports MSR and local APIC support.
fn read_snapshot() -> Option<(u32, u64)> {
    let max_basic = __cpuid(0).eax;
    if max_basic < 1 { return None; }
    let leaf1 = __cpuid(1);
    // CPUID.1:EDX MSR bit 5, APIC bit 9
    if leaf1.edx & ((1 << 5) | (1 << 9)) != ((1 << 5) | (1 << 9)) {
        return None;
    }
    let mut low: u32;
    let mut high: u32;
    // SAFETY: ring-0 x86-64 kernel and CPUID reports RDMSR available.
    // IA32_APIC_BASE is architecturally defined when CPUID.APIC=1.
    // This is READ-ONLY. No write to MMIO or model-specific registers.
    unsafe {
        asm!("rdmsr",
             in("ecx") lapic_layout::IA32_APIC_BASE_MSR,
             lateout("eax") low, lateout("edx") high,
             options(nomem, nostack, preserves_flags));
    }
    let msr = (u64::from(high) << 32) | u64::from(low);
    Some((cpu_apic_id(max_basic, leaf1.ebx), msr))
}

/// Called exactly once on the CPU owning a unique Limine directory slot.
/// Failed probes are published as invalid, so BSP can reject promptly.
pub fn capture(index: usize, expected_apic_id: u32, should_be_bsp: bool) -> bool {
    if index >= MAX_BOOT_CPUS { return false; }
    let slot = &PROBES[index];
    let mut valid = false;
    if let Some((id, raw)) = read_snapshot() {
        slot.cpuid_apic_id.store(id, Ordering::Relaxed);
        slot.msr.store(raw, Ordering::Relaxed);
        valid = matches!(
            lapic_layout::parse_apic_base(raw),
            Ok(base) if id == expected_apic_id && base.bsp == should_be_bsp
        );
    }
    slot.valid.store(valid, Ordering::Relaxed);
    // Publishing the boolean orders the preceding ID and MSR writes.
    slot.sampled.store(true, Ordering::Release);
    valid
}

/// BSP-only; each AP has already published AP_READY Release, observed with
/// Acquire. Verify all current-core register reports and the shared APIC base.
pub fn verify(cpus: &[&MpInfo], bsp_index: usize) -> Option<Summary> {
    if cpus.is_empty() || cpus.len() > MAX_BOOT_CPUS || bsp_index >= cpus.len() {
        return None;
    }
    let mut expected_base = None;
    let mut x2apic = 0;
    for (index, cpu) in cpus.iter().enumerate() {
        let slot = &PROBES[index];
        if !slot.sampled.load(Ordering::Acquire) ||
           !slot.valid.load(Ordering::Relaxed) ||
           slot.cpuid_apic_id.load(Ordering::Relaxed) != cpu.lapic_id
        {
            return None;
        }
        let base = lapic_layout::parse_apic_base(slot.msr.load(Ordering::Relaxed)).ok()?;
        if base.bsp != (index == bsp_index) { return None; }
        if let Some(physical) = expected_base {
            if base.physical_address != physical { return None; }
        } else {
            expected_base = Some(base.physical_address);
        }
        if base.x2apic { x2apic += 1; }
    }
    Some(Summary { cpus: cpus.len(), x2apic, base: expected_base? })
}


/// BSP-only identity snapshot used to map legacy xAPIC MMIO safely.
/// The x2APIC interface is MSR-only; do not attempt MMIO in that mode.
pub fn bsp_mmio_base(expected_apic_id: u32) -> Option<u64> {
    let (id, raw) = read_snapshot()?;
    let base = lapic_layout::parse_apic_base(raw).ok()?;
    if id != expected_apic_id || !base.bsp || base.x2apic {
        return None;
    }
    Some(base.physical_address)
}
