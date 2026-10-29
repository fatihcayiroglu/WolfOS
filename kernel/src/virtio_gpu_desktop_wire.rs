//! Real 1024x768 desktop framebuffer presentation wire contract.
//!
//! Pure encoding, validation and pixel arithmetic only: no PCI, no unsafe,
//! no DMA and no device state. The kernel driver owns every actual write;
//! this module can only describe exactly what it is allowed to send.
//!
//! The resource is the kernel's *real* Limine framebuffer geometry, so the
//! guest buffer is 3 MiB of real VRAM content, not a synthetic tile. QEMU
//! requires one ATTACH_BACKING for the whole resource, so the driver merges
//! physically sequential backing pages into runs and refuses the mode when
//! the fragmention would exceed the single-page request limit.

pub const WIDTH: u32 = 1024;
pub const HEIGHT: u32 = 768;
pub const BYTES_PER_PIXEL: u32 = 4;
/// One scanline of a 1024-pixel B8G8R8X8 row. The backing page index of a
/// row is therefore exactly its y coordinate.
pub const ROW_BYTES: usize = (WIDTH as usize) * (BYTES_PER_PIXEL as usize);
pub const RESOURCE_BYTES: usize = ROW_BYTES * (HEIGHT as usize);
pub const PAGES: usize = RESOURCE_BYTES / 4096;
pub const FRAME_BYTES: u64 = 4096;

pub const BAND_ROWS: u32 = 64;
pub const BANDS: usize = (HEIGHT / BAND_ROWS) as usize;
pub const REQUEST_LIMIT: usize = 4096;
pub const ATTACH_HEADER_BYTES: usize = 32;
pub const ENTRY_BYTES: usize = 16;
/// ATTACH_BACKING carries every entry inside ONE page-sized control request.
pub const MAX_ENTRIES: usize = (REQUEST_LIMIT - ATTACH_HEADER_BYTES) / ENTRY_BYTES;

pub const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
pub const CMD_RESOURCE_UNREF: u32 = 0x0102;
pub const CMD_SET_SCANOUT: u32 = 0x0103;
pub const CMD_RESOURCE_FLUSH: u32 = 0x0104;
pub const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
pub const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
pub const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
pub const FLAG_FENCE: u32 = 1;
pub const FORMAT_B8G8R8X8_UNORM: u32 = 2;
pub const SCANOUT_ID: u32 = 0;
pub const RESOURCE_ID: u32 = 1;
pub const CREATE_BYTES: usize = 40;
pub const RECT_BYTES: usize = 48;
pub const TRANSFER_BYTES: usize = 56;
pub const DETACH_BYTES: usize = 32;
pub const UNREF_BYTES: usize = 32;

/// Standard xRGB8888 channel placement. The attestation digest maps the
/// guest's memory bytes to canonical RGB, so any other layout would make the
/// host comparison meaningless and is refused instead of guessed.
pub const RED_SHIFT: u32 = 16;
pub const GREEN_SHIFT: u32 = 8;
pub const BLUE_SHIFT: u32 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidResource,
    InvalidFence,
    InvalidBand,
    WrongGeometry,
    UnalignedFrame,
    DuplicateFrame,
    ExtentMismatch,
    TooManyRuns,
    ShortBuffer,
    UnsupportedFramebuffer,
}

/// The real framebuffer the driver is allowed to present. Field values come
/// from the bootloader response and are re-validated here, never trusted.
#[derive(Clone, Copy)]
pub struct Framebuffer {
    pub address: u64,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bits_per_pixel: u32,
    pub red_shift: u32,
    pub green_shift: u32,
    pub blue_shift: u32,
}

impl Framebuffer {
    pub const NONE: Self = Self {
        address: 0,
        width: 0,
        height: 0,
        pitch: 0,
        bits_per_pixel: 0,
        red_shift: 0,
        green_shift: 0,
        blue_shift: 0,
    };

    /// Exactly one geometry is presented: 1024x768 xRGB8888 with a pitch
    /// covering a full row. Anything else must be refused, not resampled.
    pub fn supported(&self) -> Result<(), Error> {
        if self.address == 0
            || self.address % 4 != 0
            || self.bits_per_pixel != 32
            || self.width != WIDTH
            || self.height != HEIGHT
            || (self.pitch as usize) < ROW_BYTES
            || self.red_shift != RED_SHIFT
            || self.green_shift != GREEN_SHIFT
            || self.blue_shift != BLUE_SHIFT
        {
            return Err(Error::UnsupportedFramebuffer);
        }
        let extent = (self.pitch as u64)
            .checked_mul(u64::from(HEIGHT))
            .ok_or(Error::UnsupportedFramebuffer)?;
        self.address
            .checked_add(extent)
            .ok_or(Error::UnsupportedFramebuffer)?;
        Ok(())
    }
}

fn header(command: u32, fence: u64, bytes: &mut [u8]) -> Result<(), Error> {
    if fence == 0 {
        return Err(Error::InvalidFence);
    }
    if bytes.len() < 24 {
        return Err(Error::ShortBuffer);
    }
    bytes[0..4].copy_from_slice(&command.to_le_bytes());
    bytes[4..8].copy_from_slice(&FLAG_FENCE.to_le_bytes());
    bytes[8..16].copy_from_slice(&fence.to_le_bytes());
    Ok(())
}

pub fn create(fence: u64) -> Result<[u8; CREATE_BYTES], Error> {
    let mut bytes = [0u8; CREATE_BYTES];
    header(CMD_RESOURCE_CREATE_2D, fence, &mut bytes)?;
    bytes[24..28].copy_from_slice(&RESOURCE_ID.to_le_bytes());
    bytes[28..32].copy_from_slice(&FORMAT_B8G8R8X8_UNORM.to_le_bytes());
    bytes[32..36].copy_from_slice(&WIDTH.to_le_bytes());
    bytes[36..40].copy_from_slice(&HEIGHT.to_le_bytes());
    Ok(bytes)
}

/// `(y, rows, byte offset)` of one transfer band. The bands cover the whole
/// resource exactly once: no gap, no overlap, no out-of-bounds rectangle.
pub fn band(index: usize) -> Result<(u32, u32, u64), Error> {
    if index >= BANDS {
        return Err(Error::InvalidBand);
    }
    let y = (index as u32) * BAND_ROWS;
    let rows = (HEIGHT - y).min(BAND_ROWS);
    if rows != BAND_ROWS {
        return Err(Error::InvalidBand);
    }
    let offset = (u64::from(y))
        .checked_mul(ROW_BYTES as u64)
        .ok_or(Error::InvalidBand)?;
    if offset >= RESOURCE_BYTES as u64 {
        return Err(Error::InvalidBand);
    }
    Ok((y, rows, offset))
}

pub fn transfer(index: usize, fence: u64) -> Result<[u8; TRANSFER_BYTES], Error> {
    let (y, rows, offset) = band(index)?;
    let mut bytes = [0u8; TRANSFER_BYTES];
    header(CMD_TRANSFER_TO_HOST_2D, fence, &mut bytes)?;
    // rect.x stays zero; rect.y is the band's first scanline.
    bytes[28..32].copy_from_slice(&y.to_le_bytes());
    bytes[32..36].copy_from_slice(&WIDTH.to_le_bytes());
    bytes[36..40].copy_from_slice(&rows.to_le_bytes());
    bytes[40..48].copy_from_slice(&offset.to_le_bytes());
    bytes[48..52].copy_from_slice(&RESOURCE_ID.to_le_bytes());
    Ok(bytes)
}

pub fn set_scanout(fence: u64) -> Result<[u8; RECT_BYTES], Error> {
    let mut bytes = [0u8; RECT_BYTES];
    header(CMD_SET_SCANOUT, fence, &mut bytes)?;
    bytes[32..36].copy_from_slice(&WIDTH.to_le_bytes());
    bytes[36..40].copy_from_slice(&HEIGHT.to_le_bytes());
    bytes[40..44].copy_from_slice(&SCANOUT_ID.to_le_bytes());
    bytes[44..48].copy_from_slice(&RESOURCE_ID.to_le_bytes());
    Ok(bytes)
}

pub fn flush(fence: u64) -> Result<[u8; RECT_BYTES], Error> {
    let mut bytes = [0u8; RECT_BYTES];
    header(CMD_RESOURCE_FLUSH, fence, &mut bytes)?;
    bytes[32..36].copy_from_slice(&WIDTH.to_le_bytes());
    bytes[36..40].copy_from_slice(&HEIGHT.to_le_bytes());
    bytes[40..44].copy_from_slice(&RESOURCE_ID.to_le_bytes());
    Ok(bytes)
}

pub fn detach(fence: u64) -> Result<[u8; DETACH_BYTES], Error> {
    let mut bytes = [0u8; DETACH_BYTES];
    header(CMD_RESOURCE_DETACH_BACKING, fence, &mut bytes)?;
    bytes[24..28].copy_from_slice(&RESOURCE_ID.to_le_bytes());
    Ok(bytes)
}

pub fn unref(fence: u64) -> Result<[u8; UNREF_BYTES], Error> {
    let mut bytes = [0u8; UNREF_BYTES];
    header(CMD_RESOURCE_UNREF, fence, &mut bytes)?;
    bytes[24..28].copy_from_slice(&RESOURCE_ID.to_le_bytes());
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachPlan {
    pub len: usize,
    pub entries: usize,
}

/// Merge physically sequential backing pages, in pixel-page order, into
/// scatter-gather runs and encode the single ATTACH_BACKING request.
///
/// `addrs[i]` MUST be the exclusively owned PMM frame that holds resource
/// bytes `i*4096..(i+1)*4096`. Runs are only merged when the *pixel* order
/// and the physical order agree, so a fragmented allocation still maps every
/// resource byte to the page that really contains it.
pub fn attach(addrs: &[u64], out: &mut [u8], fence: u64) -> Result<AttachPlan, Error> {
    if addrs.len() != PAGES {
        return Err(Error::ExtentMismatch);
    }
    if out.len() < REQUEST_LIMIT {
        return Err(Error::ShortBuffer);
    }
    for (i, addr) in addrs.iter().copied().enumerate() {
        if addr == 0 || addr % FRAME_BYTES != 0 || addr.checked_add(FRAME_BYTES).is_none() {
            return Err(Error::UnalignedFrame);
        }
        if addrs[..i].iter().any(|other| *other == addr) {
            return Err(Error::DuplicateFrame);
        }
    }
    let mut runs = [(0u64, 0u64); MAX_ENTRIES];
    let mut entries = 0usize;
    for addr in addrs.iter().copied() {
        if entries > 0 {
            let (start, len) = runs[entries - 1];
            if start + len == addr {
                runs[entries - 1] = (start, len + FRAME_BYTES);
                continue;
            }
        }
        if entries == MAX_ENTRIES {
            return Err(Error::TooManyRuns);
        }
        runs[entries] = (addr, FRAME_BYTES);
        entries += 1;
    }
    let mut total = 0u64;
    for (_, len) in runs[..entries].iter().copied() {
        total = total.checked_add(len).ok_or(Error::ExtentMismatch)?;
    }
    if total != RESOURCE_BYTES as u64 || entries == 0 {
        return Err(Error::ExtentMismatch);
    }
    let len = ATTACH_HEADER_BYTES + entries * ENTRY_BYTES;
    if len > REQUEST_LIMIT {
        return Err(Error::TooManyRuns);
    }
    for byte in out[..len].iter_mut() {
        *byte = 0;
    }
    header(CMD_RESOURCE_ATTACH_BACKING, fence, out)?;
    out[24..28].copy_from_slice(&RESOURCE_ID.to_le_bytes());
    out[28..32].copy_from_slice(&(entries as u32).to_le_bytes());
    for (i, (start, run_bytes)) in runs[..entries].iter().copied().enumerate() {
        let at = ATTACH_HEADER_BYTES + i * ENTRY_BYTES;
        out[at..at + 8].copy_from_slice(&start.to_le_bytes());
        out[at + 8..at + 12].copy_from_slice(&(run_bytes as u32).to_le_bytes());
        // The entry's 32-bit padding stays zero.
    }
    Ok(AttachPlan { len, entries })
}

/// Deterministic desktop-wide test image in canonical RGB order.
/// Every pixel differs from its left, right, upper and lower neighbour, so a
/// stride error, row shift, band overlap or channel swap cannot survive.
pub fn pixel_rgb(x: u32, y: u32) -> [u8; 3] {
    [
        (x.wrapping_mul(3).wrapping_add(y.wrapping_mul(7)).wrapping_add(29) & 0xff) as u8,
        (x.wrapping_mul(11).wrapping_add(y.wrapping_mul(5)).wrapping_add(71) & 0xff) as u8,
        (x.wrapping_mul(13).wrapping_add(y.wrapping_mul(17)).wrapping_add(173) & 0xff) as u8,
    ]
}

/// The exact 32-bit xRGB8888 word the driver stores in real framebuffer VRAM.
pub fn pixel_word(x: u32, y: u32) -> u32 {
    let [r, g, b] = pixel_rgb(x, y);
    ((r as u32) << RED_SHIFT) | ((g as u32) << GREEN_SHIFT) | (b as u32) << BLUE_SHIFT
}

#[cfg(test)]
mod tests {
    use super::*;
    fn u32at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }
    fn u64at(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }
    fn contiguous() -> Vec<u64> {
        (0..PAGES as u64).map(|i| 0x10_0000 + i * FRAME_BYTES).collect()
    }

    #[test]
    fn real_desktop_geometry_is_exactly_three_mib() {
        assert_eq!(ROW_BYTES, 4096);
        assert_eq!(RESOURCE_BYTES, 3_145_728);
        assert_eq!(PAGES, 768);
        assert_eq!(BANDS, 12);
        assert_eq!(MAX_ENTRIES, 254);
    }

    #[test]
    fn create_wire_describes_the_real_geometry_once() {
        let bytes = create(0x1111).unwrap();
        assert_eq!(u32at(&bytes, 0), CMD_RESOURCE_CREATE_2D);
        assert_eq!(u32at(&bytes, 4), FLAG_FENCE);
        assert_eq!(u64at(&bytes, 8), 0x1111);
        assert_eq!(u32at(&bytes, 24), RESOURCE_ID);
        assert_eq!(u32at(&bytes, 28), FORMAT_B8G8R8X8_UNORM);
        assert_eq!(u32at(&bytes, 32), 1024);
        assert_eq!(u32at(&bytes, 36), 768);
    }

    #[test]
    fn every_band_covers_the_resource_exactly_once() {
        let mut covered = vec![0u8; HEIGHT as usize];
        for index in 0..BANDS {
            let (y, rows, offset) = band(index).unwrap();
            assert_eq!(y, index as u32 * BAND_ROWS);
            assert_eq!(rows, BAND_ROWS);
            assert_eq!(offset, y as u64 * ROW_BYTES as u64);
            for row in y..y + rows {
                covered[row as usize] += 1;
            }
            let bytes = transfer(index, 0x2222).unwrap();
            assert_eq!(u32at(&bytes, 0), CMD_TRANSFER_TO_HOST_2D);
            assert_eq!(u32at(&bytes, 24), 0);
            assert_eq!(u32at(&bytes, 28), y);
            assert_eq!(u32at(&bytes, 32), WIDTH);
            assert_eq!(u32at(&bytes, 36), rows);
            assert_eq!(u64at(&bytes, 40), offset);
            assert_eq!(u32at(&bytes, 48), RESOURCE_ID);
        }
        assert!(covered.iter().all(|count| *count == 1));
        assert_eq!(band(BANDS).err(), Some(Error::InvalidBand));
        assert_eq!(transfer(BANDS, 1).err(), Some(Error::InvalidBand));
    }

    #[test]
    fn scanout_flush_detach_unref_wire() {
        let set = set_scanout(0x3333).unwrap();
        assert_eq!(u32at(&set, 0), CMD_SET_SCANOUT);
        assert_eq!(u32at(&set, 32), 1024);
        assert_eq!(u32at(&set, 36), 768);
        assert_eq!(u32at(&set, 40), SCANOUT_ID);
        assert_eq!(u32at(&set, 44), RESOURCE_ID);
        let flush_bytes = flush(0x4444).unwrap();
        assert_eq!(u32at(&flush_bytes, 0), CMD_RESOURCE_FLUSH);
        assert_eq!(u32at(&flush_bytes, 40), RESOURCE_ID);
        let detach_bytes = detach(0x5555).unwrap();
        assert_eq!(u32at(&detach_bytes, 0), CMD_RESOURCE_DETACH_BACKING);
        assert_eq!(u32at(&detach_bytes, 24), RESOURCE_ID);
        let unref_bytes = unref(0x6666).unwrap();
        assert_eq!(u32at(&unref_bytes, 0), CMD_RESOURCE_UNREF);
        assert_eq!(u32at(&unref_bytes, 24), RESOURCE_ID);
    }

    #[test]
    fn zero_fence_is_refused_everywhere() {
        assert_eq!(create(0).err(), Some(Error::InvalidFence));
        assert_eq!(set_scanout(0).err(), Some(Error::InvalidFence));
        assert_eq!(flush(0).err(), Some(Error::InvalidFence));
        assert_eq!(detach(0).err(), Some(Error::InvalidFence));
        assert_eq!(unref(0).err(), Some(Error::InvalidFence));
        assert_eq!(transfer(0, 0).err(), Some(Error::InvalidFence));
        assert_eq!(attach(&contiguous(), &mut [0u8; REQUEST_LIMIT], 0).err(),
                   Some(Error::InvalidFence));
    }

    #[test]
    fn contiguous_backing_merges_into_one_run() {
        let addrs = contiguous();
        let mut out = [0u8; REQUEST_LIMIT];
        let plan = attach(&addrs, &mut out, 0x7777).unwrap();
        assert_eq!(plan.entries, 1);
        assert_eq!(plan.len, ATTACH_HEADER_BYTES + ENTRY_BYTES);
        assert_eq!(u32at(&out, 0), CMD_RESOURCE_ATTACH_BACKING);
        assert_eq!(u32at(&out, 28), 1);
        assert_eq!(u64at(&out, 32), addrs[0]);
        assert_eq!(u32at(&out, 40), RESOURCE_BYTES as u32);
    }

    #[test]
    fn fragmented_backing_keeps_pixel_order() {
        let mut addrs = contiguous();
        // Break the run in three places without changing pixel order.
        for index in [1usize, 300, 767] {
            addrs[index] = 0x90_0000 + index as u64 * 0x1_0000;
        }
        let mut out = [0u8; REQUEST_LIMIT];
        let plan = attach(&addrs, &mut out, 0x8888).unwrap();
        // Page 0 alone, page 1 alone, pages 2..=299, page 300 alone,
        // pages 301..=766, page 767 alone.
        assert_eq!(plan.entries, 6);
        assert_eq!(plan.len, ATTACH_HEADER_BYTES + 6 * ENTRY_BYTES);
        for (entry, (start, run_bytes)) in [
            (addrs[0], 1u32),
            (addrs[1], 1),
            (addrs[2], 298),
            (addrs[300], 1),
            (addrs[301], 466),
            (addrs[767], 1),
        ]
        .iter()
        .copied()
        .enumerate()
        {
            let at = ATTACH_HEADER_BYTES + entry * ENTRY_BYTES;
            assert_eq!(u64at(&out, at), start);
            assert_eq!(u32at(&out, at + 8), run_bytes * 4096);
        }
        let mut total = 0u32;
        for entry in 0..plan.entries {
            total += u32at(&out, 32 + entry * 16 + 8);
        }
        assert_eq!(total, RESOURCE_BYTES as u32);
    }

    #[test]
    fn wire_rejects_duplicate_zero_or_unaligned_frames() {
        let mut addrs = contiguous();
        addrs[0] = 0;
        assert_eq!(attach(&addrs, &mut [0u8; REQUEST_LIMIT], 1).err(),
                   Some(Error::UnalignedFrame));
        let mut addrs = contiguous();
        addrs[17] = 0x1001;
        assert_eq!(attach(&addrs, &mut [0u8; REQUEST_LIMIT], 1).err(),
                   Some(Error::UnalignedFrame));
        let mut addrs = contiguous();
        addrs[700] = addrs[3];
        assert_eq!(attach(&addrs, &mut [0u8; REQUEST_LIMIT], 1).err(),
                   Some(Error::DuplicateFrame));
        assert_eq!(attach(&addrs[..PAGES - 1], &mut [0u8; REQUEST_LIMIT], 1).err(),
                   Some(Error::ExtentMismatch));
        assert_eq!(attach(&contiguous(), &mut [0u8; 4095], 1).err(),
                   Some(Error::ShortBuffer));
    }

    #[test]
    fn wire_refuses_missing_or_fragmented_coverage() {
        // A page cannot cover another page's bytes: coverage must be exact.
        let mut addrs = contiguous();
        addrs[0] = addrs[1];
        assert!(attach(&addrs, &mut [0u8; REQUEST_LIMIT], 1).is_err());
        // 255 one-page runs exceed the single-page request budget.
        let pages: Vec<u64> = (0..PAGES as u64)
            .map(|i| 0x20_0000 + i * 0x2000)
            .collect();
        assert_eq!(attach(&pages, &mut [0u8; REQUEST_LIMIT], 1).err(),
                   Some(Error::TooManyRuns));
    }

    #[test]
    fn exactly_max_entries_is_accepted() {
        let mut pages: Vec<u64> = Vec::with_capacity(PAGES);
        let mut page = 0usize;
        while page < PAGES {
            // Runs of 4 pages separated by a one-page gap: 768/4 = 192 runs.
            let base = 0x40_0000 + (page as u64) * 0x2000;
            for offset in 0..4 {
                if page < PAGES {
                    pages.push(base + offset as u64 * FRAME_BYTES);
                    page += 1;
                }
            }
        }
        let mut out = [0u8; REQUEST_LIMIT];
        let plan = attach(&pages, &mut out, 0x9999).unwrap();
        assert_eq!(plan.entries, 192);
        assert!(plan.len <= REQUEST_LIMIT);
    }

    #[test]
    fn pattern_changes_at_every_neighbour() {
        for (x, y) in [(0u32, 0u32), (1, 0), (0, 1), (1023, 767), (512, 384)] {
            let centre = pixel_rgb(x, y);
            assert_ne!(centre, pixel_rgb(x.wrapping_add(1) % WIDTH, y));
            assert_ne!(centre, pixel_rgb(x, y.wrapping_add(1) % HEIGHT));
        }
        // Channel order is observably distinct, so a BGR swap cannot pass.
        let [r, g, b] = pixel_rgb(37, 91);
        assert_ne!(r, g);
        assert_ne!(g, b);
        let word = pixel_word(37, 91);
        assert_eq!((word >> 16) as u8, r);
        assert_eq!((word >> 8) as u8, g);
        assert_eq!(word as u8, b);
    }

    #[test]
    fn framebuffer_geometry_is_strictly_supported_or_refused() {
        let good = Framebuffer {
            address: 0xfd00_0000,
            width: 1024,
            height: 768,
            pitch: 4096,
            bits_per_pixel: 32,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
        };
        assert_eq!(good.supported(), Ok(()));
        let padded = Framebuffer { pitch: 8192, ..good };
        assert_eq!(padded.supported(), Ok(()));
        for broken in [
            Framebuffer { address: 0, ..good },
            Framebuffer { address: 0xfd00_0002, ..good },
            Framebuffer { bits_per_pixel: 24, ..good },
            Framebuffer { width: 800, ..good },
            Framebuffer { height: 600, ..good },
            Framebuffer { pitch: 4095, ..good },
            Framebuffer { red_shift: 0, green_shift: 8, blue_shift: 16, ..good },
            Framebuffer { address: u64::MAX - 8, ..good },
        ] {
            assert_eq!(broken.supported(), Err(Error::UnsupportedFramebuffer));
        }
    }
}
