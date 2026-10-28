//! Strict, no-heap EDID 1.x + *one* CTA-861 revision-3 extension.
//!
//! Fail closed on unknown video identification codes and unparsed block
//! families (including HDMI/vendor, HDR, 4:2:0 and DisplayID). Never infer
//! a physical refresh rate or write display registers here. Supported VIC
//! modes are explicitly published CTA nominal timings, not measurements.
//! Actual GPU scanout still requires a driver's link/PLL capability check.

use crate::display_edid_base::{self, EdidError};
use crate::display_mode_policy::DisplayMode;

const BLOCK_LEN: usize = 128;
const DTD_LEN: usize = 18;
const CAP: usize = 16;
const EMPTY: DisplayMode = DisplayMode {
    width: 0, height: 0, refresh_millihz: 0,
    pixel_clock_khz: 0, preferred: false, interlaced: false,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FullEdidError {
    WrongLength,
    UnsupportedExtensionCount,
    Base(EdidError),
    InvalidExtensionChecksum,
    UnsupportedExtension,
    UnsupportedCtaRevision,
    InvalidCtaLayout,
    MalformedDataBlock,
    UnsupportedDataBlock,
    UnsupportedVic,
    InvalidDetailedTiming,
    InvalidNativeCount,
    ModeLimit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorModes {
    modes: [DisplayMode; CAP],
    len: usize,
    pub revision: u8,
}
impl ConnectorModes {
    pub fn modes(&self) -> &[DisplayMode] { &self.modes[..self.len] }
    pub fn len(&self) -> usize { self.len }
    fn insert(&mut self, mode: DisplayMode) -> Result<(), FullEdidError> {
        for existing in &mut self.modes[..self.len] {
            if existing.same_timing(mode) {
                // Native/preferred metadata can upgrade the same timing.
                existing.preferred |= mode.preferred;
                return Ok(());
            }
        }
        if self.len == CAP { return Err(FullEdidError::ModeLimit); }
        self.modes[self.len] = mode;
        self.len += 1;
        Ok(())
    }
}

fn nominal_vic(vic: u8, preferred: bool) -> Result<DisplayMode, FullEdidError> {
    // Nominal CTA timings verified against upstream DRM CEA mode table.
    // We intentionally implement only well-understood progressive VICs.
    // Unsupported, fractional-rate and pixel-repetition variants are NOT
    // silently fabricated into distinct user-selectable refresh rates.
    let (width,height,clock,htotal,vtotal): (u32,u32,u32,u32,u32) = match vic {
        1 => (640,480,25_175,800,525),     // 59.940 Hz (VIC 1)
        4 => (1280,720,74_250,1650,750),   // 60 Hz
        16 => (1920,1080,148_500,2200,1125), // 60 Hz
        31 => (1920,1080,148_500,2640,1125), // 50 Hz
        95 => (3840,2160,297_000,4400,2250), // 30 Hz
        97 => (3840,2160,594_000,4400,2250), // 60 Hz
        _ => return Err(FullEdidError::UnsupportedVic),
    };
    let frame_pixels = u64::from(htotal) * u64::from(vtotal);
    let mhz = (u64::from(clock) * 1_000_000 + frame_pixels/2) / frame_pixels;
    Ok(DisplayMode {
        width,height,refresh_millihz:mhz as u32,
        pixel_clock_khz:clock,preferred,interlaced:false,
    })
}

fn parse_cta(block: &[u8], modes: &mut ConnectorModes) -> Result<(), FullEdidError> {
    if block.len()!=BLOCK_LEN { return Err(FullEdidError::WrongLength); }
    if block.iter().fold(0u8, |sum,byte|sum.wrapping_add(*byte))!=0 {
        return Err(FullEdidError::InvalidExtensionChecksum);
    }
    if block[0]!=0x02 { return Err(FullEdidError::UnsupportedExtension); }
    if block[1]!=3 { return Err(FullEdidError::UnsupportedCtaRevision); }
    let dtd_offset = usize::from(block[2]);
    let native_dtds = block[3]&0x0f;
    if dtd_offset==0 {
        if native_dtds!=0 || block[4..127].iter().any(|b|*b!=0) {
            return Err(FullEdidError::InvalidCtaLayout);
        }
        return Ok(());
    }
    if !(4..=127).contains(&dtd_offset) {
        return Err(FullEdidError::InvalidCtaLayout);
    }
    let mut cursor=4usize;
    while cursor < dtd_offset {
        let header=block[cursor];
        cursor+=1;
        let tag=header>>5;
        let count=usize::from(header&0x1f);
        if cursor+count>dtd_offset {
            return Err(FullEdidError::MalformedDataBlock);
        }
        match tag {
            2 => {
                // CTA Video Data Block, with narrow canonical VIC support.
                for raw in &block[cursor..cursor+count] {
                    if *raw==0 { return Err(FullEdidError::UnsupportedVic); }
                    // Bit 7 is "native" for classic VICs 1..64 only.
                    // Reject newer/ambiguous high-byte encodings entirely.
                    let (vic, native) = if *raw>127 {
                        let low=*raw&0x7f;
                        if low==0 || low>64 {
                            return Err(FullEdidError::UnsupportedVic);
                        }
                        (low,true)
                    } else { (*raw,false) };
                    modes.insert(nominal_vic(vic,native)?)?;
                }
            }
            1 | 4 => {
                // Audio and speaker metadata cannot add video timings.
            }
            // Vendor video modes, extended YCbCr/HDR/video descriptors, etc.
            // are deliberately unparsed, so do not trust a partial mode list.
            _ => return Err(FullEdidError::UnsupportedDataBlock),
        }
        cursor+=count;
    }
    let mut native_seen=0u8;
    let mut dtd_cursor=dtd_offset;
    while dtd_cursor+DTD_LEN<=127 {
        let item=&block[dtd_cursor..dtd_cursor+DTD_LEN];
        if let Some(mut mode)=display_edid_base::detailed_timing(item)
            .map_err(|_|FullEdidError::InvalidDetailedTiming)?
        {
            mode.preferred=native_seen<native_dtds;
            native_seen+=1;
            modes.insert(mode)?;
        }
        dtd_cursor+=DTD_LEN;
    }
    if block[dtd_cursor..127].iter().any(|b|*b!=0) {
        return Err(FullEdidError::InvalidCtaLayout);
    }
    if native_dtds>native_seen { return Err(FullEdidError::InvalidNativeCount); }
    Ok(())
}

/// Accept a complete, checksummed EDID with no extension or exactly one
/// *fully understood* CTA revision-3 extension; all other shapes fail closed.
/// This is a pure parser, not DDC, a driver, or a real modeset.
pub fn parse_complete(edid: &[u8]) -> Result<ConnectorModes,FullEdidError> {
    if edid.len()<BLOCK_LEN || edid.len()%BLOCK_LEN!=0 {
        return Err(FullEdidError::WrongLength);
    }
    let extensions=usize::from(edid[126]);
    if extensions>1 { return Err(FullEdidError::UnsupportedExtensionCount); }
    if edid.len()!=(extensions+1)*BLOCK_LEN {
        return Err(FullEdidError::WrongLength);
    }
    let base=display_edid_base::parse_base_with_checked_extensions(&edid[..BLOCK_LEN])
        .map_err(FullEdidError::Base)?;
    let mut result=ConnectorModes {
        modes:[EMPTY;CAP],len:0,revision:base.revision,
    };
    for mode in base.modes() { result.insert(*mode)?; }
    if extensions==1 { parse_cta(&edid[BLOCK_LEN..], &mut result)?; }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display_mode_policy::{
        choose, ModeError, PipelineLimits, RefreshChoice, ResolutionChoice, UserChoice,
    };

    fn checksum(e: &mut [u8]) {
        e[127]=0;
        let sum=e.iter().fold(0u8,|acc,b|acc.wrapping_add(*b));
        e[127]=0u8.wrapping_sub(sum);
    }
    fn base() -> [u8;128] {
        let mut b=[0u8;128];
        b[..8].copy_from_slice(&[0,255,255,255,255,255,255,0]);
        b[18]=1;b[19]=4;b[24]=2;b[126]=1;
        // A real-layout 148.5 MHz 1920x1080@60 DTD.
        b[54..62].copy_from_slice(&[2,58,128,24,113,56,45,64]);
        checksum(&mut b);b
    }
    fn extension() -> [u8;128] {
        let mut c=[0u8;128];
        c[0]=2;c[1]=3;c[2]=7;
        c[4]=0x42;c[5]=16;c[6]=97;
        checksum(&mut c);c
    }
    fn joined(b:[u8;128],c:[u8;128])->[u8;256] {
        let mut both=[0u8;256];
        both[..128].copy_from_slice(&b);
        both[128..].copy_from_slice(&c);
        both
    }
    fn gpu()->PipelineLimits {
        PipelineLimits {
            max_width:3840,max_height:2160,max_pixel_clock_khz:600_000,
            max_refresh_millihz:144_000,supports_interlaced:false,
        }
    }
    #[test]
    fn cta_vic16_and_97_are_verified_distinct_modes() {
        let result=parse_complete(&joined(base(),extension())).unwrap();
        assert_eq!(result.len(),2); // base 1080p60 == VIC16
        assert_eq!(result.modes()[0].refresh_millihz,60_000);
        assert_eq!((result.modes()[1].width,result.modes()[1].height,
                    result.modes()[1].refresh_millihz,result.modes()[1].pixel_clock_khz),
                   (3840,2160,60_000,594_000));
        assert!(result.modes()[0].preferred);
        assert_eq!(choose(result.modes(),gpu(),UserChoice{
            resolution:ResolutionChoice::Exact{width:3840,height:2160},
            refresh:RefreshChoice::ExactMilliHz(60_000),
        }),Ok(result.modes()[1]));
        assert_eq!(choose(result.modes(),gpu(),UserChoice{
            resolution:ResolutionChoice::Exact{width:3840,height:2160},
            refresh:RefreshChoice::ExactMilliHz(120_000),
        }),Err(ModeError::UnsupportedSelection));
    }
    #[test]
    fn no_extension_is_still_supported_without_fabricated_modes() {
        let mut b=base();b[126]=0;checksum(&mut b);
        assert_eq!(parse_complete(&b).unwrap().len(),1);
    }
    #[test]
    fn native_svd_upgrades_matching_base_dtd() {
        let mut c=extension();c[5]=0x90;checksum(&mut c);
        let mut b=base();b[19]=3;b[24]=0;checksum(&mut b);
        let r=parse_complete(&joined(b,c)).unwrap();
        assert_eq!(r.len(),2);
        assert!(r.modes()[0].preferred);
    }
    #[test]
    fn nominal_vic1_is_59940_millihz_not_fake_60000() {
        let mut c=extension();c[5]=1;c[6]=31;checksum(&mut c);
        let r=parse_complete(&joined(base(),c)).unwrap();
        assert_eq!(r.len(),3);
        assert_eq!(r.modes()[1].refresh_millihz,59_940);
        assert_eq!(r.modes()[2].refresh_millihz,50_000);
    }
    #[test]
    fn vic_4k30_supported_independently_of_4k60() {
        let mut c=extension();c[5]=95;c[6]=97;checksum(&mut c);
        let r=parse_complete(&joined(base(),c)).unwrap();
        assert_eq!(r.len(),3);
        assert_eq!(r.modes()[1].refresh_millihz,30_000);
        assert_eq!(r.modes()[2].refresh_millihz,60_000);
    }
    #[test]
    fn cta_native_dtd_is_parsed_with_exact_clock() {
        let mut c=extension();
        c[2]=4;c[3]=1;c[4..7].fill(0);
        // 497.76 MHz, 2560x1440, total 2720x1525 => 120 Hz.
        c[4..12].copy_from_slice(&[112,194,0,160,160,160,85,80]);
        checksum(&mut c);
        let r=parse_complete(&joined(base(),c)).unwrap();
        assert_eq!(r.len(),2);
        assert_eq!(r.modes()[1].refresh_millihz,120_000);
        assert!(r.modes()[1].preferred);
    }
    #[test]
    fn duplicate_cta_dtd_does_not_create_fake_duplicate() {
        let mut c=extension();c[2]=4;c[4..7].fill(0);
        c[4..12].copy_from_slice(&base()[54..62]);
        checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)).unwrap().len(),1);
    }
    #[test]
    fn reject_checksum_mismatch_in_either_block() {
        let mut b=base();b[40]^=1;
        assert_eq!(parse_complete(&joined(b,extension())),
                   Err(FullEdidError::Base(EdidError::InvalidChecksum)));
        let mut c=extension();c[6]^=1;
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::InvalidExtensionChecksum));
    }
    #[test]
    fn reject_missing_or_surplus_extension_bytes() {
        assert_eq!(parse_complete(&base()),Err(FullEdidError::WrongLength));
        let mut b=base();b[126]=0;checksum(&mut b);
        assert_eq!(parse_complete(&joined(b,extension())),Err(FullEdidError::WrongLength));
        assert_eq!(parse_complete(&joined(base(),extension())[..255]),
                   Err(FullEdidError::WrongLength));
    }
    #[test]
    fn reject_more_than_one_extension_even_with_valid_checksums() {
        let mut b=base();b[126]=2;checksum(&mut b);
        assert_eq!(parse_complete(&joined(b,extension())),
                   Err(FullEdidError::UnsupportedExtensionCount));
    }
    #[test]
    fn reject_displayid_and_wrong_cta_version() {
        let mut c=extension();c[0]=0x70;checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::UnsupportedExtension));
        let mut c=extension();c[1]=2;checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::UnsupportedCtaRevision));
    }
    #[test]
    fn reject_unparsed_vendor_and_extended_video_blocks() {
        let mut c=extension();c[4]=0x62;checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::UnsupportedDataBlock));
        let mut c=extension();c[4]=0xe2;checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::UnsupportedDataBlock));
    }
    #[test]
    fn reject_unknown_or_reserved_vic_even_if_other_vic_is_valid() {
        let mut c=extension();c[6]=0;checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::UnsupportedVic));
        let mut c=extension();c[6]=120;checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::UnsupportedVic));
        let mut c=extension();c[6]=0xff;checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::UnsupportedVic));
    }
    #[test]
    fn reject_out_of_bounds_data_block_and_offset() {
        let mut c=extension();c[4]=0x44;checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::MalformedDataBlock));
        let mut c=extension();c[2]=3;checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::InvalidCtaLayout));
    }
    #[test]
    fn accept_non_video_audio_and_speaker_data_blocks() {
        let mut c=extension();
        c[2]=10;c[4]=0x23;c[5]=1;c[6]=2;c[7]=3;c[8]=0x81;c[9]=0;
        checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)).unwrap().len(),1);
    }
    #[test]
    fn reject_non_zero_dtd_padding_and_invalid_native_count() {
        let mut c=extension();c[126]=1;checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::InvalidCtaLayout));
        let mut c=extension();c[3]=1;checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::InvalidNativeCount));
    }
    #[test]
    fn no_dtd_offset_accepts_only_empty_video_free_extension() {
        let mut c=extension();c[2]=0;c[4..7].fill(0);checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)).unwrap().len(),1);
        c[4]=1;checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::InvalidCtaLayout));
    }
    #[test]
    fn malformed_cta_dtd_rejects_entire_result() {
        let mut c=extension();c[2]=4;c[4..7].fill(0);
        c[4..12].copy_from_slice(&[112,194,0,0,160,160,85,80]);
        checksum(&mut c);
        assert_eq!(parse_complete(&joined(base(),c)),
                   Err(FullEdidError::InvalidDetailedTiming));
    }
}
