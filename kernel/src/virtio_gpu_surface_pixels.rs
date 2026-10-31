//! Allocation-free composition from separately owned, read-only pixel slices.
//!
//! This pure contract has NO user-memory mapping, DMA, PCI, input dispatch,
//! or proof of on-screen pixels. The trusted caller must authenticate the
//! process/handle identities and verify real GPU fences before presenting.
//! On any validation failure the destination is left byte-for-byte unchanged.

use super::damage::Rect;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidIdentity,
    DuplicateSurface,
    StaleBinding,
    InvalidTop,
    InvalidRect,
    DamageOutsideViewport,
    BadStride,
    SizeOverflow,
    BadPixelLength,
}

/// A slot alone can be recycled. Both the surface and its owning process
/// require generations, so the caller can reject stale PID/handle reuse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub slot: u32,
    pub surface_generation: u64,
    pub pid: u64,
    pub process_generation: u64,
}

impl Identity {
    fn validate(self) -> Result<(), Error> {
        if self.slot == 0 || self.surface_generation == 0
            || self.pid == 0 || self.process_generation == 0
        {
            Err(Error::InvalidIdentity)
        } else {
            Ok(())
        }
    }
}

/// Immutable, application-associated xRGB8888 pixels. No caller obtains a
/// mutable reference to another surface through this compositor.
#[derive(Clone, Copy, Debug)]
pub struct SurfacePixels<'a> {
    identity: Identity,
    rect: Rect,
    stride: usize, // pixels, not bytes; padding at row ends is allowed
    pixels: &'a [u32],
}

fn check_rect(rect: Rect) -> Result<(), Error> {
    Rect::checked(rect.x, rect.y, rect.width, rect.height)
        .map(|_| ())
        .map_err(|_| Error::InvalidRect)
}

fn exact_len(stride: usize, width: u32, height: u32, len: usize)
    -> Result<(), Error>
{
    if stride < width as usize {
        return Err(Error::BadStride);
    }
    let required = stride.checked_mul(height as usize)
        .ok_or(Error::SizeOverflow)?;
    if required != len {
        return Err(Error::BadPixelLength);
    }
    Ok(())
}

impl<'a> SurfacePixels<'a> {
    pub fn new(identity: Identity, rect: Rect, stride: usize, pixels: &'a [u32])
        -> Result<Self, Error>
    {
        identity.validate()?;
        check_rect(rect)?;
        exact_len(stride, rect.width, rect.height, pixels.len())?;
        Ok(Self { identity, rect, stride, pixels })
    }

    pub fn identity(&self) -> Identity { self.identity }
    pub fn rect(&self) -> Rect { self.rect }

    fn covers(&self, x: u32, y: u32) -> bool {
        x >= self.rect.x && x < self.rect.x + self.rect.width
            && y >= self.rect.y && y < self.rect.y + self.rect.height
    }

    fn sample(&self, x: u32, y: u32) -> u32 {
        // covers() and validated exact lengths must hold at every call site.
        let offset = (y - self.rect.y) as usize * self.stride
            + (x - self.rect.x) as usize;
        self.pixels[offset]
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CompositionReport {
    pub background: u32,
    pub first: u32,
    pub second: u32,
}

/// Recompose ONLY `damage` in `viewport`. The original background is an
/// immutable reference image, not the potentially modified destination.
/// A top surface completely replaces the lower pixel; no XOR/alpha mixing.
///
/// Expected identities must come from the kernel's authoritative handle
/// table, NOT from the untrusted image producer. The full identity including
/// both generations is checked before ANY pixel is changed.
#[allow(clippy::too_many_arguments)]
pub fn compose(
    destination: &mut [u32],
    background: &[u32],
    viewport: Rect,
    stride: usize,
    damage: Rect,
    first: SurfacePixels<'_>,
    second: SurfacePixels<'_>,
    expected: [Identity; 2],
    top: Identity,
) -> Result<CompositionReport, Error> {
    check_rect(viewport)?;
    check_rect(damage)?;
    exact_len(stride, viewport.width, viewport.height, destination.len())?;
    if background.len() != destination.len() {
        return Err(Error::BadPixelLength);
    }
    expected[0].validate()?;
    expected[1].validate()?;
    if expected[0].slot == expected[1].slot {
        return Err(Error::DuplicateSurface);
    }
    if first.identity != expected[0] || second.identity != expected[1] {
        return Err(Error::StaleBinding);
    }
    if top != expected[0] && top != expected[1] {
        return Err(Error::InvalidTop);
    }
    // check_rect makes the additions safe and bounds them to the resource.
    if damage.x < viewport.x || damage.y < viewport.y
        || damage.x + damage.width > viewport.x + viewport.width
        || damage.y + damage.height > viewport.y + viewport.height
    {
        return Err(Error::DamageOutsideViewport);
    }

    let mut report = CompositionReport::default();
    for y in damage.y..damage.y + damage.height {
        let row = (y - viewport.y) as usize * stride;
        for x in damage.x..damage.x + damage.width {
            let at = row + (x - viewport.x) as usize;
            let a = first.covers(x, y);
            let b = second.covers(x, y);
            destination[at] = match (a, b) {
                (true, true) if top == expected[0] => {
                    report.first += 1;
                    first.sample(x, y)
                }
                (true, true) => {
                    report.second += 1;
                    second.sample(x, y)
                }
                (true, false) => {
                    report.first += 1;
                    first.sample(x, y)
                }
                (false, true) => {
                    report.second += 1;
                    second.sample(x, y)
                }
                (false, false) => {
                    report.background += 1;
                    background[at]
                }
            };
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: u32, y: u32, w: u32, h: u32) -> Rect {
        Rect::checked(x, y, w, h).unwrap()
    }

    fn id(slot: u32, generation: u64, pid: u64, process_generation: u64)
        -> Identity
    {
        Identity {
            slot, surface_generation: generation, pid, process_generation,
        }
    }

    const RED: u32 = 0x00e2_1409;
    const BLUE: u32 = 0x000c_1eda;
    const BG: u32 = 0x0033_5577;
    const SENTINEL: u32 = 0x00be_ef01;

    #[test]
    fn overlap_has_one_owner_and_clips_source_without_mutating_it() {
        let a_id = id(1, 4, 22, 7);
        let b_id = id(2, 9, 23, 6);
        let a_pixels = [RED; 6 * 4];
        let b_pixels = [BLUE; 6 * 4];
        let a = SurfacePixels::new(a_id, rect(42, 31, 6, 4), 6, &a_pixels).unwrap();
        let b = SurfacePixels::new(b_id, rect(45, 32, 6, 4), 6, &b_pixels).unwrap();
        let viewport = rect(40, 30, 16, 8);
        let background = [BG; 16 * 8];
        let mut target = [SENTINEL; 16 * 8];

        let red_front = compose(&mut target, &background, viewport, 16,
                                viewport, a, b, [a_id, b_id], a_id).unwrap();
        assert_eq!(red_front, CompositionReport {
            first: 24, second: 15, background: 89,
        });
        for y in 30..38 {
            for x in 40..56 {
                let in_a = x >= 42 && x < 48 && y >= 31 && y < 35;
                let in_b = x >= 45 && x < 51 && y >= 32 && y < 36;
                let expected = if in_a { RED } else if in_b { BLUE } else { BG };
                assert_eq!(target[((y-30)*16 + (x-40)) as usize], expected);
            }
        }

        let blue_front = compose(&mut target, &background, viewport, 16,
                                 viewport, a, b, [a_id, b_id], b_id).unwrap();
        assert_eq!(blue_front, CompositionReport {
            first: 15, second: 24, background: 89,
        });
        assert_eq!(target[((32-30)*16 + (45-40)) as usize], BLUE);
        assert_eq!(a_pixels, [RED; 24]);
        assert_eq!(b_pixels, [BLUE; 24]);
    }

    #[test]
    fn dirty_region_keeps_every_pixel_outside_it_untouched() {
        let a_id = id(1, 1, 21, 1);
        let b_id = id(2, 1, 22, 1);
        let a_px = [RED; 8 * 4];
        let b_px = [BLUE; 8 * 4];
        let a = SurfacePixels::new(a_id, rect(42, 31, 8, 4), 8, &a_px).unwrap();
        let b = SurfacePixels::new(b_id, rect(47, 33, 8, 4), 8, &b_px).unwrap();
        let view = rect(40, 30, 16, 8);
        let dirty = rect(44, 32, 5, 3);
        let background = [BG; 128];
        let mut target = [SENTINEL; 128];
        let report = compose(&mut target, &background, view, 16, dirty,
                             a, b, [a_id, b_id], a_id).unwrap();
        assert_eq!(report.first + report.second + report.background, 15);
        for y in 30..38 {
            for x in 40..56 {
                let in_dirty = (44..49).contains(&x) && (32..35).contains(&y);
                let pixel = target[((y-30)*16 + (x-40)) as usize];
                if !in_dirty {
                    assert_eq!(pixel, SENTINEL);
                } else if (42..50).contains(&x) && (31..35).contains(&y) {
                    assert_eq!(pixel, RED);
                } else if (47..55).contains(&x) && (33..37).contains(&y) {
                    assert_eq!(pixel, BLUE);
                } else {
                    assert_eq!(pixel, BG);
                }
            }
        }
    }

    #[test]
    fn stale_owner_invalid_top_and_bad_damage_fail_before_writing() {
        let a_id = id(1, 10, 20, 3);
        let b_id = id(2, 10, 21, 3);
        let a_px = [RED; 4];
        let b_px = [BLUE; 4];
        let a = SurfacePixels::new(a_id, rect(11, 11, 2, 2), 2, &a_px).unwrap();
        let b = SurfacePixels::new(b_id, rect(12, 12, 2, 2), 2, &b_px).unwrap();
        let view = rect(10, 10, 8, 8);
        let bg = [BG; 64];
        let mut target = [SENTINEL; 64];
        let stale = id(1, 10, 20, 4);
        assert_eq!(compose(&mut target, &bg, view, 8, view, a, b,
                           [stale, b_id], b_id), Err(Error::StaleBinding));
        assert_eq!(compose(&mut target, &bg, view, 8, view, a, b,
                           [a_id, b_id], stale), Err(Error::InvalidTop));
        assert_eq!(compose(&mut target, &bg, view, 8, view, a, b,
                           [a_id, a_id], a_id), Err(Error::DuplicateSurface));
        assert_eq!(compose(&mut target, &bg, view, 8, rect(17,17,2,2), a, b,
                           [a_id, b_id], a_id),
                   Err(Error::DamageOutsideViewport));
        assert_eq!(target, [SENTINEL; 64]);
    }

    #[test]
    fn padded_source_rows_and_clipped_viewport_use_correct_stride() {
        let a_id = id(3, 1, 70, 9);
        let b_id = id(4, 1, 71, 1);
        let a_px = [RED, RED, SENTINEL, BLUE, BLUE, SENTINEL];
        let b_px = [BLUE; 1];
        let a = SurfacePixels::new(a_id, rect(1022, 766, 2, 2), 3, &a_px).unwrap();
        let b = SurfacePixels::new(b_id, rect(1, 1, 1, 1), 1, &b_px).unwrap();
        let view = rect(1021, 765, 3, 3);
        let bg = [BG; 9];
        let mut target = [SENTINEL; 9];
        let r = compose(&mut target, &bg, view, 3, view, a, b,
                        [a_id, b_id], a_id).unwrap();
        assert_eq!(r.first, 4);
        assert_eq!(r.background, 5);
        assert_eq!(target, [BG, BG, BG, BG, RED, RED, BG, BLUE, BLUE]);
    }

    #[test]
    fn rejects_zero_generation_short_slice_overflow_and_broken_stride() {
        let valid = id(1, 1, 1, 1);
        let p = [0u32; 4];
        assert!(matches!(
            SurfacePixels::new(id(1, 0, 1, 1), rect(1,1,2,2), 2, &p),
            Err(Error::InvalidIdentity)));
        assert!(matches!(
            SurfacePixels::new(valid, rect(1,1,2,2), 1, &p),
            Err(Error::BadStride)));
        assert!(matches!(
            SurfacePixels::new(valid, rect(1,1,2,2), 2, &p[..3]),
            Err(Error::BadPixelLength)));
        assert!(matches!(
            SurfacePixels::new(valid, rect(1,1,2,2), usize::MAX, &p),
            Err(Error::SizeOverflow)));
        assert!(matches!(
            SurfacePixels::new(valid, Rect {x:1023,y:0,width:2,height:1}, 2, &p[..2]),
            Err(Error::InvalidRect)));
    }
}
