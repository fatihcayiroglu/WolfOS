//! Read-only modern VirtIO-GPU PCI vendor capability-chain validator.
//! No BAR-size probing, MMIO map, DMA, device status write or virtqueue use.
//! The returned BAR offsets are untrusted until mapped and bounded by a
//! separate real PCI BAR/resource allocator. QEMU-only smoke exercises this.

pub const VIRTIO_VENDOR: u16 = 0x1af4;
pub const VIRTIO_GPU_DEVICE: u16 = 0x1050;
const PCI_BYTES: usize = 256;
const MAX_HOPS: usize = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityError {
    WrongIdentity,
    NoCapabilityList,
    BadPointer,
    CapabilityLoop,
    MalformedCapability,
    BadBar,
    InvalidRange,
    DuplicateType,
    IncompleteTypes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioGpuCapabilities {
    pub common_bar: u8,
    pub notify_bar: u8,
    pub isr_bar: u8,
    pub device_bar: u8,
    pub notify_multiplier: u32,
    pub vendor_caps: u8,
}

fn le16(cfg: &[u8;PCI_BYTES], i: usize) -> u16 {
    u16::from_le_bytes([cfg[i],cfg[i+1]])
}
fn le32(cfg: &[u8;PCI_BYTES], i: usize) -> u32 {
    u32::from_le_bytes([cfg[i],cfg[i+1],cfg[i+2],cfg[i+3]])
}

pub fn inspect(cfg: &[u8;PCI_BYTES]) -> Result<VirtioGpuCapabilities, CapabilityError> {
    if le16(cfg,0) != VIRTIO_VENDOR
        || le16(cfg,2) != VIRTIO_GPU_DEVICE
        || cfg[0x0b] != 0x03
    {
        return Err(CapabilityError::WrongIdentity);
    }
    // Status bit 4 is "Capabilities List", high 16 of config dword at 0x04.
    if le16(cfg,0x06) & 0x10 == 0 {
        return Err(CapabilityError::NoCapabilityList);
    }
    let mut pointer=usize::from(cfg[0x34]);
    if pointer==0 { return Err(CapabilityError::NoCapabilityList); }
    let mut seen=[false;PCI_BYTES];
    let mut occupied=[false;PCI_BYTES];
    let mut kinds: [Option<(u8,u32)>;4]=[None;4];
    let mut multiplier=0u32;
    let mut vendor_caps=0u8;
    let mut hops=0usize;

    while pointer != 0 {
        if pointer<0x40 || pointer>0xfc || pointer & 3 != 0 {
            return Err(CapabilityError::BadPointer);
        }
        if seen[pointer] { return Err(CapabilityError::CapabilityLoop); }
        seen[pointer]=true;
        hops+=1;
        if hops>MAX_HOPS { return Err(CapabilityError::CapabilityLoop); }
        let id=cfg[pointer];
        let next=usize::from(cfg[pointer+1]);
        if occupied[pointer] {
            return Err(CapabilityError::MalformedCapability);
        }
        if id==0x09 {
            if pointer>0xf0 { return Err(CapabilityError::MalformedCapability); }
            let cap_len=usize::from(cfg[pointer+2]);
            let kind=cfg[pointer+3];
            if cap_len<16 || pointer.checked_add(cap_len).is_none()
                || pointer+cap_len>PCI_BYTES
            {
                return Err(CapabilityError::MalformedCapability);
            }
            if occupied[pointer..pointer+cap_len].iter().any(|taken| *taken) {
                return Err(CapabilityError::MalformedCapability);
            }
            occupied[pointer..pointer+cap_len].fill(true);
            // Future vendor-specific types must NOT be misidentified as a
            // required configuration capability.
            if (1..=4).contains(&kind) {
                let bar=cfg[pointer+4];
                let offset=le32(cfg,pointer+8);
                let length=le32(cfg,pointer+12);
                let min_len=match kind {
                    1=>56, // common_cfg v1.0 basic structure
                    2=>2,  // notification location
                    3=>1,  // ISR status byte
                    4=>16, // GPU device config
                    _=>unreachable!(),
                };
                if bar>5 { return Err(CapabilityError::BadBar); }
                if length<min_len || offset.checked_add(length).is_none() {
                    return Err(CapabilityError::InvalidRange);
                }
                if kinds[(kind-1) as usize].is_some() {
                    return Err(CapabilityError::DuplicateType);
                }
                if kind==2 {
                    if cap_len<20 { return Err(CapabilityError::MalformedCapability); }
                    multiplier=le32(cfg,pointer+16);
                    if multiplier==0 { return Err(CapabilityError::InvalidRange); }
                }
                kinds[(kind-1) as usize]=Some((bar,length));
                vendor_caps=vendor_caps.saturating_add(1);
            }
        }
        if id!=0x09 {
            occupied[pointer]=true;
            occupied[pointer+1]=true;
        }
        pointer=next;
    }
    let [Some((common_bar,_)),Some((notify_bar,_)),
         Some((isr_bar,_)),Some((device_bar,_))]=kinds else {
        return Err(CapabilityError::IncompleteTypes);
    };
    Ok(VirtioGpuCapabilities {
        common_bar,notify_bar,isr_bar,device_bar,
        notify_multiplier:multiplier,vendor_caps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vendor_cap(cfg:&mut [u8;256],p:usize,next:u8,kind:u8,bar:u8,len:u32) {
        cfg[p]=9;cfg[p+1]=next;cfg[p+2]=if kind==2 {20} else {16};
        cfg[p+3]=kind;cfg[p+4]=bar;cfg[p+8..p+12].copy_from_slice(&0x100u32.to_le_bytes());
        cfg[p+12..p+16].copy_from_slice(&len.to_le_bytes());
        if kind==2 {cfg[p+16..p+20].copy_from_slice(&4u32.to_le_bytes());}
    }
    fn example()->[u8;256] {
        let mut c=[0u8;256];
        c[0..2].copy_from_slice(&VIRTIO_VENDOR.to_le_bytes());
        c[2..4].copy_from_slice(&VIRTIO_GPU_DEVICE.to_le_bytes());
        c[6]=0x10;c[0x0b]=3;c[0x34]=0x40;
        vendor_cap(&mut c,0x40,0x60,1,4,64);
        vendor_cap(&mut c,0x60,0x80,2,4,2);
        vendor_cap(&mut c,0x80,0xa0,3,4,1);
        vendor_cap(&mut c,0xa0,0,4,4,16);
        c
    }
    #[test]
    fn known_valid_four_required_capabilities() {
        let s=inspect(&example()).unwrap();
        assert_eq!((s.vendor_caps,s.common_bar,s.notify_bar,s.isr_bar,s.device_bar),
                   (4,4,4,4,4));
        assert_eq!(s.notify_multiplier,4);
    }
    #[test]
    fn wrong_vendor_device_or_pci_class_rejected() {
        let mut c=example();c[0]=0;assert_eq!(inspect(&c),Err(CapabilityError::WrongIdentity));
        let mut c=example();c[2]=0;assert_eq!(inspect(&c),Err(CapabilityError::WrongIdentity));
        let mut c=example();c[0x0b]=2;assert_eq!(inspect(&c),Err(CapabilityError::WrongIdentity));
    }
    #[test]
    fn status_and_pointer_required() {
        let mut c=example();c[6]=0;assert_eq!(inspect(&c),Err(CapabilityError::NoCapabilityList));
        let mut c=example();c[0x34]=0;assert_eq!(inspect(&c),Err(CapabilityError::NoCapabilityList));
    }
    #[test]
    fn reject_unaligned_or_header_overlapping_cap_pointer() {
        let mut c=example();c[0x34]=0x41;assert_eq!(inspect(&c),Err(CapabilityError::BadPointer));
        let mut c=example();c[0x34]=0x20;assert_eq!(inspect(&c),Err(CapabilityError::BadPointer));
    }
    #[test]
    fn detect_cycle_and_duplicated_cap_kind() {
        let mut c=example();c[0xa1]=0x40;
        assert_eq!(inspect(&c),Err(CapabilityError::CapabilityLoop));
        let mut c=example();c[0xa3]=1;
        // Keep the payload range valid so duplicate detection is the first
        // violated contract. Otherwise InvalidRange correctly wins.
        c[0xac..0xb0].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(inspect(&c),Err(CapabilityError::DuplicateType));
    }
    #[test]
    fn reject_capability_pointer_into_previous_vendor_payload() {
        let mut c=example();
        c[0x41]=0x44; // A spurious next header inside the first 16-byte cap
        assert_eq!(inspect(&c),Err(CapabilityError::MalformedCapability));
    }
    #[test]
    fn reject_capabilities_truncated_by_config_boundary() {
        let mut c=example();c[0xa1]=0xf8;c[0xf8]=9;c[0xf9]=0;c[0xfa]=16;
        assert_eq!(inspect(&c),Err(CapabilityError::MalformedCapability));
    }
    #[test]
    fn reject_short_vendor_cap_and_notify_without_multiplier() {
        let mut c=example();c[0x42]=15;
        assert_eq!(inspect(&c),Err(CapabilityError::MalformedCapability));
        let mut c=example();c[0x62]=16;
        assert_eq!(inspect(&c),Err(CapabilityError::MalformedCapability));
    }
    #[test]
    fn reject_missing_required_device_capability() {
        let mut c=example();c[0x81]=0;
        assert_eq!(inspect(&c),Err(CapabilityError::IncompleteTypes));
    }
    #[test]
    fn reject_invalid_bar_and_zero_size() {
        let mut c=example();c[0x44]=6;
        assert_eq!(inspect(&c),Err(CapabilityError::BadBar));
        let mut c=example();c[0x4c..0x50].fill(0);
        assert_eq!(inspect(&c),Err(CapabilityError::InvalidRange));
    }
    #[test]
    fn reject_offset_plus_length_overflow() {
        let mut c=example();c[0x48..0x4c].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(inspect(&c),Err(CapabilityError::InvalidRange));
    }
    #[test]
    fn reject_bad_notification_multiplier() {
        let mut c=example();c[0x70..0x74].fill(0);
        assert_eq!(inspect(&c),Err(CapabilityError::InvalidRange));
    }
    #[test]
    fn unrecognized_vendor_cap_does_not_substitute_for_required_type() {
        let mut c=example();c[0xa3]=7;
        assert_eq!(inspect(&c),Err(CapabilityError::IncompleteTypes));
    }
    #[test]
    fn nonvendor_capabilities_can_coexist_in_chain() {
        let mut c=example();c[0xa1]=0xc0;
        c[0xc0]=0x11;c[0xc1]=0;
        assert_eq!(inspect(&c).unwrap().vendor_caps,4);
    }
    #[test]
    fn notification_multiplier_and_bars_are_preserved_without_mapping() {
        let mut c=example();c[0x64]=2;c[0x70..0x74].copy_from_slice(&8u32.to_le_bytes());
        let s=inspect(&c).unwrap();
        assert_eq!((s.notify_bar,s.notify_multiplier),(2,8));
    }
}
