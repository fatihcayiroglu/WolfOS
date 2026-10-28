//! Read-only discovery of legacy PCI configuration space on x86-64.
//! PCI configuration mechanism #1 (0xCF8/0xCFC) gives 256-byte headers.
//!
//! Not a PCIe ECAM driver or driver installer. Only early-boot (BSP) access
//! with interrupts disabled is supported; CF8/CFC are shared I/O ports.
//! Device configuration stays read-only except the feature-gated, QEMU-only
//! BAR-size smoke, which disables decode, restores all BARs/command and checks
//! the restore before claiming success. Never use this on physical devices.

use core::arch::asm;
use crate::{display_driver_policy::DisplayIdentity, serial};
#[cfg(feature = "qemu-virtio-gpu-pci-smoke")]
use crate::virtio_gpu_pci_caps;
#[cfg(feature = "qemu-virtio-gpu-bars-smoke")]
use crate::virtio_gpu_pci_bars;


const CONFIG_ADDRESS: u16 = 0xCF8;
const CONFIG_DATA: u16 = 0xCFC;
const MAX_LOGGED: usize = 20;

#[derive(Clone, Copy, Debug)]
pub struct PciSummary {
    pub devices: usize,
    pub displays: usize,
    pub networks: usize,
    pub storage: usize,
    /// Read-only count of exact QEMU PCI Standard VGA 1234:1111 functions.
    pub qemu_stdvga: usize,
    #[cfg(feature = "qemu-virtio-gpu-pci-smoke")]
    pub virtio_gpu_caps_verified: usize,
    #[cfg(feature = "qemu-virtio-gpu-bar-size-smoke")]
    pub virtio_gpu_bar_size_verified: usize,
}

/// Read an aligned u32 from a function's first 256 PCI config bytes.
/// SAFETY: Only for the boot processor with interrupts disabled. It writes
/// the *address selection port*, not any PCI device configuration register.
fn read_u32(bus: u8, slot: u8, function: u8, offset: u8) -> u32 {
    let address = 0x8000_0000u32
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((function as u32) << 8)
        | (u32::from(offset) & 0xfc);
    let response: u32;
    unsafe {
        asm!("out dx, eax",
            in("dx") CONFIG_ADDRESS, in("eax") address,
            options(nomem, nostack, preserves_flags));
        asm!("in eax, dx",
            in("dx") CONFIG_DATA, out("eax") response,
            options(nomem, nostack, preserves_flags));
    }
    response
}

#[cfg(feature = "qemu-virtio-gpu-bar-size-smoke")]
fn config_select(bus: u8,slot: u8,function: u8,offset: u8) -> u32 {
    0x8000_0000u32
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((function as u32) << 8)
        | (u32::from(offset) & 0xfc)
}

#[cfg(feature = "qemu-virtio-gpu-bar-size-smoke")]
fn write_config_u32(bus:u8,slot:u8,function:u8,offset:u8,value:u32) {
    // Dedicated QEMU-only BAR-size test. Never exported to regular PCI
    // discovery or enabled for physical hardware.
    let address=config_select(bus,slot,function,offset);
    unsafe {
        asm!("out dx, eax",in("dx") CONFIG_ADDRESS,in("eax") address,
            options(nomem,nostack,preserves_flags));
        asm!("out dx, eax",in("dx") CONFIG_DATA,in("eax") value,
            options(nomem,nostack,preserves_flags));
    }
}

#[cfg(feature = "qemu-virtio-gpu-bar-size-smoke")]
fn write_command_u16(bus:u8,slot:u8,function:u8,value:u16) {
    // A 16-bit write to COMMAND only; the upper PCI STATUS half-word
    // includes W1C bits and MUST NEVER be written back from a u32 read.
    let address=config_select(bus,slot,function,0x04);
    unsafe {
        asm!("out dx, eax",in("dx") CONFIG_ADDRESS,in("eax") address,
            options(nomem,nostack,preserves_flags));
        asm!("out dx, ax",in("dx") CONFIG_DATA,in("ax") value,
            options(nomem,nostack,preserves_flags));
    }
}

#[cfg(feature = "qemu-virtio-gpu-bar-size-smoke")]
fn prove_qemu_common_bar_aperture(
    bus:u8,slot:u8,function:u8,bar:u8,
    bar_kind:virtio_gpu_pci_bars::BarKind,
    region_offset:u32,region_length:u32,
) -> bool {
    use crate::virtio_gpu_bar_size_contract::{BarKind, aperture_size, validate_window};

    let kind=match bar_kind {
        virtio_gpu_pci_bars::BarKind::Io=>BarKind::Io,
        virtio_gpu_pci_bars::BarKind::Memory32=>BarKind::Memory32,
        virtio_gpu_pci_bars::BarKind::Memory64=>BarKind::Memory64,
    };
    let wide=kind==BarKind::Memory64;
    if bar>=6 || (wide && bar==5) {
        serial::write_line("WOLFOS_VIRTIO_GPU_BAR_SIZE_FAIL bar_index");
        return false;
    }
    let low_reg=0x10u8+4*bar;
    let hi_reg=low_reg+4;
    let original_low=read_u32(bus,slot,function,low_reg);
    let original_high=if wide { read_u32(bus,slot,function,hi_reg) } else { 0 };
    let original_command=read_u32(bus,slot,function,0x04) as u16;
    let disabled_command=original_command & !0x0007u16;

    // Exactly one transaction with guaranteed program-flow rollback.
    // Keep decoder and bus-master disabled while all-ones BAR masks are
    // visible. No early return is permitted between BAR probe writes
    // and restoration; no heap, DMA or driver active.
    write_command_u16(bus,slot,function,disabled_command);
    let disabled_ok=(read_u32(bus,slot,function,0x04) as u16)==disabled_command;
    if !disabled_ok {
        write_command_u16(bus,slot,function,original_command);
        serial::write_line("WOLFOS_VIRTIO_GPU_BAR_SIZE_FAIL decode_not_disabled");
        return false;
    }

    write_config_u32(bus,slot,function,low_reg,u32::MAX);
    if wide { write_config_u32(bus,slot,function,hi_reg,u32::MAX); }
    let mask_low=read_u32(bus,slot,function,low_reg);
    let mask_high=if wide {read_u32(bus,slot,function,hi_reg)} else {0};
    if wide { write_config_u32(bus,slot,function,hi_reg,original_high); }
    write_config_u32(bus,slot,function,low_reg,original_low);
    write_command_u16(bus,slot,function,original_command);

    let restored=(read_u32(bus,slot,function,0x04) as u16)==original_command
        && read_u32(bus,slot,function,low_reg)==original_low
        && (!wide || read_u32(bus,slot,function,hi_reg)==original_high);
    if !restored {
        serial::write_line("WOLFOS_VIRTIO_GPU_BAR_SIZE_FAIL restore_mismatch");
        return false;
    }

    let base=match kind {
        BarKind::Io=>u64::from(original_low & !3),
        BarKind::Memory32=>u64::from(original_low & !15),
        BarKind::Memory64=>(u64::from(original_high)<<32)|u64::from(original_low & !15),
    };
    let Ok(bytes)=aperture_size(kind,mask_low,mask_high) else {
        serial::write_line("WOLFOS_VIRTIO_GPU_BAR_SIZE_FAIL invalid_mask");
        return false;
    };
    if validate_window(base,bytes,region_offset,region_length).is_err() {
        serial::write_line("WOLFOS_VIRTIO_GPU_BAR_SIZE_FAIL region_outside");
        return false;
    }
    let bar_writes=if wide {4}else{2};
    serial::write_fmt(format_args!(
        "WOLFOS_VIRTIO_GPU_BAR_SIZE_OK kind={} bytes={} common_offset={} common_length={} command_writes=2 bar_writes={} restored=1 decode_stopped=1 mmio=0 dma=0\n",
        kind.label(),bytes,region_offset,region_length,bar_writes,
    ));
    true
}

fn probe(bus: u8, slot: u8, function: u8) -> Option<(u16, u16)> {
    let ids = read_u32(bus, slot, function, 0);
    let vendor = ids as u16;
    if vendor == 0xffff { return None; }
    Some((vendor, (ids >> 16) as u16))
}

#[cfg(feature = "qemu-virtio-gpu-pci-smoke")]
fn inspect_qemu_virtio_gpu(bus: u8, slot: u8, function: u8) -> bool {
    // Exactly 64 read-only PCI configuration dwords. CF8 selector writes
    // are NOT writes to any PCI device configuration register.
    let mut cfg = [0u8; 256];
    for dword in 0..64usize {
        let offset = (dword * 4) as u8;
        cfg[dword*4..dword*4+4]
            .copy_from_slice(&read_u32(bus, slot, function, offset).to_le_bytes());
    }
    match virtio_gpu_pci_caps::inspect(&cfg) {
        Ok(caps) if caps.vendor_caps >= 4 => {
            serial::write_fmt(format_args!(
                "WOLFOS_VIRTIO_GPU_PCI_CAPS_OK vendor=1af4 device=1050 common={} notify={} isr={} device={} multiplier={} cap_reads=64 cfg_writes=0 dma=0 accel=0\n",
                caps.common_bar,caps.notify_bar,caps.isr_bar,caps.device_bar,
                caps.notify_multiplier
            ));
            #[cfg(feature = "qemu-virtio-gpu-bars-smoke")]
            {
                match virtio_gpu_pci_bars::inspect(&cfg, [
                    caps.common_bar, caps.notify_bar,
                    caps.isr_bar, caps.device_bar,
                ]) {
                    Ok(bars) => {
                        serial::write_fmt(format_args!(
                            "WOLFOS_VIRTIO_GPU_BARS_OK common={} notify={} isr={} device={} cfg_writes=0 bar_probe_writes=0 mmio=0\n",
                            bars.common.label(), bars.notify.label(),
                            bars.isr.label(), bars.device.label(),
                        ));
                        #[cfg(feature = "qemu-virtio-gpu-bar-size-smoke")]
                        if !prove_qemu_common_bar_aperture(
                            bus,slot,function,caps.common_bar,bars.common,
                            caps.common_offset,caps.common_length,
                        ) {
                            return false;
                        }
                    },
                    Err(error) => {
                        serial::write_fmt(format_args!(
                            "WOLFOS_VIRTIO_GPU_BARS_FAIL {error:?}\n"
                        ));
                        return false;
                    }
                }
            }
            true
        }
        Ok(_) => {
            serial::write_line("WOLFOS_VIRTIO_GPU_PCI_CAPS_FAIL insufficient_caps");
            false
        }
        Err(error) => {
            serial::write_fmt(format_args!(
                "WOLFOS_VIRTIO_GPU_PCI_CAPS_FAIL {error:?}\n"
            ));
            false
        }
    }
}

fn record(
    summary: &mut PciSummary,
    bus: u8,
    slot: u8,
    function: u8,
    vendor: u16,
    device: u16,
) {
    let revision_and_class = read_u32(bus, slot, function, 0x08);
    let class = (revision_and_class >> 24) as u8;
    let subclass = (revision_and_class >> 16) as u8;
    let prog_if = (revision_and_class >> 8) as u8;

    if summary.devices < MAX_LOGGED {
        serial::write_fmt(format_args!(
            "WOLFOS_PCI_DEVICE {:02x}:{:02x}.{} vendor={:04x} device={:04x} class={:02x}:{:02x}:{:02x}\n",
            bus, slot, function, vendor, device, class, subclass, prog_if
        ));
    }
    summary.devices += 1;
    match class {
        0x01 => summary.storage += 1,
        0x02 => summary.networks += 1,
        0x03 => {
            summary.displays += 1;
            if vendor == 0x1234 && device == 0x1111 {
                summary.qemu_stdvga += 1;
            }
            serial::write_fmt(format_args!(
                "WOLFOS_GPU_DETECTED vendor={:04x} device={:04x} bus={:02x} slot={:02x}\n",
                vendor, device, bus, slot
            ));
            // Identification is NOT permission to bind any accelerated
            // driver. This stage neither configures BARs nor touches DMA.
            if let Some(identity) = DisplayIdentity::from_pci(vendor, device, class) {
                serial::write_fmt(format_args!(
                    "WOLFOS_GPU_DRIVER_POLICY vendor={:04x} device={:04x} family={} native=none cfg_write=0\n",
                    vendor, device, identity.family.label(),
                ));
            }
            #[cfg(feature = "qemu-virtio-gpu-pci-smoke")]
            if vendor == virtio_gpu_pci_caps::VIRTIO_VENDOR
                && device == virtio_gpu_pci_caps::VIRTIO_GPU_DEVICE
                && subclass == 0x00
                && inspect_qemu_virtio_gpu(bus,slot,function)
            {
                summary.virtio_gpu_caps_verified += 1;
                #[cfg(feature = "qemu-virtio-gpu-bar-size-smoke")]
                { summary.virtio_gpu_bar_size_verified += 1; }
            }
        }
        _ => {}
    }
}

/// Scan 256 buses, 32 slots, and function 1..7 only for multifunction devices.
/// Legacy access is deliberately serialized by the single-CPU startup phase.
pub fn discover() -> PciSummary {
    let mut summary = PciSummary {
        devices: 0, displays: 0, networks: 0, storage: 0, qemu_stdvga: 0,
        #[cfg(feature = "qemu-virtio-gpu-pci-smoke")]
        virtio_gpu_caps_verified: 0,
        #[cfg(feature = "qemu-virtio-gpu-bar-size-smoke")]
        virtio_gpu_bar_size_verified: 0,
    };
    for bus in 0u16..=255 {
        for slot in 0u8..32 {
            let b = bus as u8;
            let Some((vendor, device)) = probe(b, slot, 0) else { continue; };
            record(&mut summary, b, slot, 0, vendor, device);
            let header = (read_u32(b, slot, 0, 0x0c) >> 16) as u8;
            if header & 0x80 == 0 { continue; }
            for function in 1u8..8 {
                if let Some((vendor, device)) = probe(b, slot, function) {
                    record(&mut summary, b, slot, function, vendor, device);
                }
            }
        }
    }
    serial::write_fmt(format_args!(
        "WOLFOS_PCI_OK devices={} displays={} networks={} storage={}\n",
        summary.devices, summary.displays, summary.networks, summary.storage
    ));
    summary
}
