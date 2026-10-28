//! Strict, bounded EDID 1.x base-block detailed timing reader.
//! No I2C, DDC, GPU MMIO or monitor writes occur in this module.
//! CTA-861/DisplayID extensions are explicitly rejected until parsed
//! and checksummed; unknown timings never become automatic modes.

use crate::display_mode_policy::DisplayMode;

const HEADER: [u8; 8] = [0x00,0xff,0xff,0xff,0xff,0xff,0xff,0x00];
const BASE_LEN: usize = 128;
const DTD_START: usize = 54;
const DTD_SIZE: usize = 18;
const MODE_CAP: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdidError {
    WrongLength,
    InvalidHeader,
    InvalidChecksum,
    UnsupportedVersion,
    UnparsedExtensions,
    InvalidDetailedTiming,
    MissingDetailedTiming,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BaseModes {
    modes: [DisplayMode; MODE_CAP],
    len: usize,
    pub revision: u8,
}

impl BaseModes {
    pub fn modes(&self) -> &[DisplayMode] { &self.modes[..self.len] }
    pub fn len(&self) -> usize { self.len }
    pub fn is_empty(&self) -> bool { self.len == 0 }
}

const ZERO_MODE: DisplayMode = DisplayMode {
    width: 0, height: 0, refresh_millihz: 0,
    pixel_clock_khz: 0, preferred: false, interlaced: false,
};

pub(crate) fn detailed_timing(bytes: &[u8]) -> Result<Option<DisplayMode>, EdidError> {
    let pixel_clock_units = u16::from_le_bytes([bytes[0], bytes[1]]);
    if pixel_clock_units == 0 {
        // EDID monitor name/range/serial descriptors are not timings.
        // They must not be guessed as refresh/resolution capabilities.
        return Ok(None);
    }
    let h_active = u32::from(bytes[2]) | (u32::from(bytes[4] & 0xf0) << 4);
    let h_blank = u32::from(bytes[3]) | (u32::from(bytes[4] & 0x0f) << 8);
    let v_active = u32::from(bytes[5]) | (u32::from(bytes[7] & 0xf0) << 4);
    let v_blank = u32::from(bytes[6]) | (u32::from(bytes[7] & 0x0f) << 8);
    let h_total = h_active.checked_add(h_blank).ok_or(EdidError::InvalidDetailedTiming)?;
    let v_total = v_active.checked_add(v_blank).ok_or(EdidError::InvalidDetailedTiming)?;
    if h_active == 0 || v_active == 0 || h_blank == 0 || v_blank == 0
        || h_active > 8192 || v_active > 8192
        || h_total > 8192 || v_total > 8192
    {
        return Err(EdidError::InvalidDetailedTiming);
    }
    let pixel_clock_khz = u32::from(pixel_clock_units) * 10;
    let period_pixels = u64::from(h_total) * u64::from(v_total);
    // kHz * 1000 Hz/kHz * 1000 mHz/Hz. Nearest millihertz.
    let numerator = u64::from(pixel_clock_khz) * 1_000_000;
    let refresh_millihz = ((numerator + period_pixels / 2) / period_pixels)
        .try_into().map_err(|_| EdidError::InvalidDetailedTiming)?;
    if refresh_millihz == 0 {
        return Err(EdidError::InvalidDetailedTiming);
    }
    Ok(Some(DisplayMode {
        width: h_active,
        height: v_active,
        refresh_millihz,
        pixel_clock_khz,
        preferred: false,
        interlaced: bytes[17] & 0x80 != 0,
    }))
}

/// Only return verified modes when the ENTIRE EDID base block is valid and
/// has no unparsed extensions. The driver may feed this to the independent
/// display mode/pipeline selection policy, never directly to register I/O.
pub fn parse_base(edid: &[u8]) -> Result<BaseModes, EdidError> {
    parse_base_inner(edid, false)
}

/// Used only after a complete EDID consumer verifies *all* advertised
/// extension blocks. The base-only API continues to reject extensions.
pub(crate) fn parse_base_with_checked_extensions(edid: &[u8]) -> Result<BaseModes, EdidError> {
    parse_base_inner(edid, true)
}

fn parse_base_inner(edid: &[u8], extensions_checked: bool) -> Result<BaseModes, EdidError> {
    if edid.len() != BASE_LEN { return Err(EdidError::WrongLength); }
    if edid[..8] != HEADER { return Err(EdidError::InvalidHeader); }
    if edid.iter().fold(0u8, |sum,byte|sum.wrapping_add(*byte)) != 0 {
        return Err(EdidError::InvalidChecksum);
    }
    if edid[18] != 1 || edid[19] > 4 {
        return Err(EdidError::UnsupportedVersion);
    }
    if edid[126] != 0 && !extensions_checked {
        return Err(EdidError::UnparsedExtensions);
    }
    let mut result = BaseModes {
        modes: [ZERO_MODE; MODE_CAP],
        len: 0,
        revision: edid[19],
    };
    // EDID 1.4 always treats the first detailed mode as preferred.
    // EDID <= 1.3 requires the feature flag bit 1.
    let prefer_first = edid[19] >= 4 || edid[24] & 0x02 != 0;
    for index in 0..MODE_CAP {
        let start = DTD_START + index * DTD_SIZE;
        if let Some(mut mode) = detailed_timing(&edid[start..start + DTD_SIZE])? {
            mode.preferred = result.len == 0 && prefer_first;
            if result.modes[..result.len].iter().any(|m|m.same_timing(mode)) {
                continue;
            }
            result.modes[result.len] = mode;
            result.len += 1;
        }
    }
    if result.is_empty() { return Err(EdidError::MissingDetailedTiming); }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display_mode_policy::{
        choose,PipelineLimits,UserChoice,ResolutionChoice,RefreshChoice,ModeError,
    };

    fn edid() -> [u8;BASE_LEN] {
        let mut e=[0u8;BASE_LEN];
        e[..8].copy_from_slice(&HEADER);
        e[18]=1;
        e[19]=4; // EDID 1.4
        e[24]=0x02;
        // 1920x1080@60: pixel clock 148.50 MHz; total 2200x1125.
        e[54..62].copy_from_slice(&[0x02,0x3a,0x80,0x18,0x71,0x38,0x2d,0x40]);
        checksum(&mut e);
        e
    }
    fn checksum(e:&mut [u8;BASE_LEN]) {
        e[127]=0;
        let sum=e.iter().fold(0u8,|a,b|a.wrapping_add(*b));
        e[127]=0u8.wrapping_sub(sum);
    }
    fn dtd_1440p120() -> [u8;18] {
        // pixel clock 497.76 MHz; totals 2720x1525 -> 120000 mHz.
        let mut d=[0u8;18];
        d[..8].copy_from_slice(&[0x70,0xc2,0x00,0xa0,0xa0,0xa0,0x55,0x50]);
        d
    }
    fn pipeline()->PipelineLimits {
        PipelineLimits {
            max_width:3840,max_height:2160,max_pixel_clock_khz:600_000,
            max_refresh_millihz:240_000,supports_interlaced:false,
        }
    }
    #[test]
    fn valid_1080p_edid_yields_native_60hz() {
        let modes=parse_base(&edid()).unwrap();
        assert_eq!(modes.len(),1);
        assert_eq!(modes.revision,4);
        let m=modes.modes()[0];
        assert_eq!((m.width,m.height,m.refresh_millihz,m.pixel_clock_khz),
                   (1920,1080,60_000,148_500));
        assert!(m.preferred);
        assert_eq!(choose(modes.modes(),pipeline(),UserChoice::AUTOMATIC),Ok(m));
    }
    #[test]
    fn two_dtds_are_deduplicated_and_auto_prefers_first() {
        let mut e=edid();
        e[72..90].copy_from_slice(&dtd_1440p120());
        checksum(&mut e);
        let ms=parse_base(&e).unwrap();
        assert_eq!(ms.len(),2);
        assert_eq!((ms.modes()[1].width,ms.modes()[1].height,ms.modes()[1].refresh_millihz),
                   (2560,1440,120_000));
        assert!(!ms.modes()[1].preferred);
        assert_eq!(choose(ms.modes(),pipeline(),UserChoice::AUTOMATIC),Ok(ms.modes()[0]));
        assert_eq!(choose(ms.modes(),pipeline(),UserChoice {
            resolution:ResolutionChoice::Exact{width:2560,height:1440},
            refresh:RefreshChoice::Automatic
        }),Ok(ms.modes()[1]));
    }
    #[test]
    fn duplicate_dtd_not_exposed_twice() {
        let mut e=edid();
        let original=e[54..72].to_vec();
        e[72..90].copy_from_slice(&original);
        checksum(&mut e);
        assert_eq!(parse_base(&e).unwrap().len(),1);
    }
    #[test]
    fn valid_monitor_name_descriptor_is_not_mode() {
        let mut e=edid();
        e[72..90].copy_from_slice(&[0,0,0,0xfc,0, b'W',b'o',b'l',b'f',b'O',b'S',0,0,0,0,0,0,0]);
        checksum(&mut e);
        assert_eq!(parse_base(&e).unwrap().len(),1);
    }
    #[test]
    fn reject_missing_checksum() {
        let mut e=edid();e[20]^=1;
        assert_eq!(parse_base(&e),Err(EdidError::InvalidChecksum));
    }
    #[test]
    fn reject_corrupt_header_even_if_checksum_fixed() {
        let mut e=edid();e[0]=1;checksum(&mut e);
        assert_eq!(parse_base(&e),Err(EdidError::InvalidHeader));
    }
    #[test]
    fn reject_incorrect_block_length() {
        assert_eq!(parse_base(&edid()[..127]),Err(EdidError::WrongLength));
        let mut e=edid().to_vec();e.push(0);
        assert_eq!(parse_base(&e),Err(EdidError::WrongLength));
    }
    #[test]
    fn reject_unsupported_edid_revision() {
        let mut e=edid();e[18]=2;checksum(&mut e);
        assert_eq!(parse_base(&e),Err(EdidError::UnsupportedVersion));
        e[18]=1;e[19]=5;checksum(&mut e);
        assert_eq!(parse_base(&e),Err(EdidError::UnsupportedVersion));
    }
    #[test]
    fn do_not_ignore_unparsed_cta_or_displayid_extensions() {
        let mut e=edid();e[126]=1;checksum(&mut e);
        assert_eq!(parse_base(&e),Err(EdidError::UnparsedExtensions));
    }
    #[test]
    fn no_video_timing_means_no_automatic_mode() {
        let mut e=edid();e[54..72].fill(0);checksum(&mut e);
        assert_eq!(parse_base(&e),Err(EdidError::MissingDetailedTiming));
    }
    #[test]
    fn reject_zero_horizontal_blank_and_zero_vertical_blank() {
        let mut e=edid();e[57]=0;e[58]&=0xf0;checksum(&mut e);
        assert_eq!(parse_base(&e),Err(EdidError::InvalidDetailedTiming));
        let mut e=edid();e[60]=0;e[61]&=0xf0;checksum(&mut e);
        assert_eq!(parse_base(&e),Err(EdidError::InvalidDetailedTiming));
    }
    #[test]
    fn interlace_is_decoded_but_pipeline_may_refuse() {
        let mut e=edid();e[54+17]=0x80;checksum(&mut e);
        let modes=parse_base(&e).unwrap();
        assert!(modes.modes()[0].interlaced);
        assert_eq!(choose(modes.modes(),pipeline(),UserChoice::AUTOMATIC),
                   Err(ModeError::UnsupportedSelection));
    }
    #[test]
    fn old_edid_preferred_flag_controls_preference() {
        let mut e=edid();e[19]=3;e[24]=0;checksum(&mut e);
        assert!(!parse_base(&e).unwrap().modes()[0].preferred);
        e[24]=0x02;checksum(&mut e);
        assert!(parse_base(&e).unwrap().modes()[0].preferred);
    }
    #[test]
    fn base_edid_14_prefers_first_timing_even_without_flag() {
        let mut e=edid();e[24]=0;checksum(&mut e);
        assert!(parse_base(&e).unwrap().modes()[0].preferred);
    }
    #[test]
    fn bad_second_dtd_rejects_entire_mode_list() {
        let mut e=edid();e[72..90].copy_from_slice(&dtd_1440p120());
        e[72+3]=0;e[72+4]&=0xf0;checksum(&mut e);
        assert_eq!(parse_base(&e),Err(EdidError::InvalidDetailedTiming));
    }
    #[test]
    fn no_manual_165hz_without_edid_support() {
        let modes=parse_base(&edid()).unwrap();
        assert_eq!(choose(modes.modes(),pipeline(),UserChoice {
            resolution: ResolutionChoice::Automatic,
            refresh: RefreshChoice::ExactMilliHz(165_000)
        }),Err(ModeError::UnsupportedSelection));
    }
}
