//! Bounded VirtIO-GPU 2D damage rectangles and acknowledgement policy.
//!
//! Pure, no_std-compatible contract. No MMIO, DMA, allocation, or host pixel
//! claims. A rectangle is not completed until the caller has independently
//! validated *both* real fenced control-queue replies in order.
//! A failed or missing reply leaves the backing/resource pinned: never free
//! anything based on a merely submitted request.

pub const WIDTH: u32 = 1024;
pub const HEIGHT: u32 = 768;
pub const BYTES_PER_PIXEL: u64 = 4;
pub const STRIDE_BYTES: u64 = WIDTH as u64 * BYTES_PER_PIXEL;
pub const RESOURCE_BYTES: u64 = STRIDE_BYTES * HEIGHT as u64;
pub const RESOURCE_ID: u32 = 1;
pub const TRANSFER_BYTES: usize = 56;
pub const FLUSH_BYTES: usize = 48;
const FLAG_FENCE: u32 = 1;
const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const CMD_RESOURCE_FLUSH: u32 = 0x0104;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Empty,
    OutOfBounds,
    InvalidFence,
    DuplicateFence,
    NoDamage,
    InFlight,
    UnexpectedAck,
    FlushBeforeTransfer,
    Full,
    OverlappingDamage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub fn checked(x: u32, y: u32, width: u32, height: u32) -> Result<Self, Error> {
        if width == 0 || height == 0 {
            return Err(Error::Empty);
        }
        if x.checked_add(width).is_none_or(|end| end > WIDTH)
            || y.checked_add(height).is_none_or(|end| end > HEIGHT)
        {
            return Err(Error::OutOfBounds);
        }
        Ok(Self { x, y, width, height })
    }

    fn validate(self) -> Result<(), Error> {
        Self::checked(self.x, self.y, self.width, self.height).map(|_| ())
    }

    /// Offset is the first pixel's position in the *full-resource* stride.
    /// Never multiply by the width of a smaller scanout rectangle.
    pub fn offset(self) -> u64 {
        self.y as u64 * STRIDE_BYTES + self.x as u64 * BYTES_PER_PIXEL
    }

    /// Conservative compositor coalescing may transfer unchanged pixels inside
    /// the bounding box, but must never omit a changed pixel.
    pub fn union(self, other: Self) -> Result<Self, Error> {
        self.validate()?;
        other.validate()?;
        let x0 = self.x.min(other.x);
        let y0 = self.y.min(other.y);
        let x1 = (self.x + self.width).max(other.x + other.width);
        let y1 = (self.y + self.height).max(other.y + other.height);
        Self::checked(x0, y0, x1 - x0, y1 - y0)
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.x < other.x + other.width && other.x < self.x + self.width
            && self.y < other.y + other.height && other.y < self.y + self.height
    }

    pub fn pixels(self) -> u64 {
        self.width as u64 * self.height as u64
    }
}

fn header(command: u32, fence: u64, out: &mut [u8]) -> Result<(), Error> {
    if fence == 0 { return Err(Error::InvalidFence); }
    out[0..4].copy_from_slice(&command.to_le_bytes());
    out[4..8].copy_from_slice(&FLAG_FENCE.to_le_bytes());
    out[8..16].copy_from_slice(&fence.to_le_bytes());
    Ok(())
}

/// Exactly 56 wire bytes: x/y/w/h, offset, resource id and zero padding.
pub fn encode_transfer(rect: Rect, fence: u64) -> Result<[u8; TRANSFER_BYTES], Error> {
    rect.validate()?;
    let mut bytes = [0u8; TRANSFER_BYTES];
    header(CMD_TRANSFER_TO_HOST_2D, fence, &mut bytes)?;
    bytes[24..28].copy_from_slice(&rect.x.to_le_bytes());
    bytes[28..32].copy_from_slice(&rect.y.to_le_bytes());
    bytes[32..36].copy_from_slice(&rect.width.to_le_bytes());
    bytes[36..40].copy_from_slice(&rect.height.to_le_bytes());
    bytes[40..48].copy_from_slice(&rect.offset().to_le_bytes());
    bytes[48..52].copy_from_slice(&RESOURCE_ID.to_le_bytes());
    Ok(bytes)
}

/// Exactly 48 wire bytes: matching x/y/w/h, resource id and zero padding.
pub fn encode_flush(rect: Rect, fence: u64) -> Result<[u8; FLUSH_BYTES], Error> {
    rect.validate()?;
    let mut bytes = [0u8; FLUSH_BYTES];
    header(CMD_RESOURCE_FLUSH, fence, &mut bytes)?;
    bytes[24..28].copy_from_slice(&rect.x.to_le_bytes());
    bytes[28..32].copy_from_slice(&rect.y.to_le_bytes());
    bytes[32..36].copy_from_slice(&rect.width.to_le_bytes());
    bytes[36..40].copy_from_slice(&rect.height.to_le_bytes());
    bytes[40..44].copy_from_slice(&RESOURCE_ID.to_le_bytes());
    Ok(bytes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Submission {
    pub rect: Rect,
    pub transfer_fence: u64,
    pub flush_fence: u64,
    pub transfer: [u8; TRANSFER_BYTES],
    pub flush: [u8; FLUSH_BYTES],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InFlight {
    transfer_fence: u64,
    flush_fence: u64,
    transfer_acked: bool,
}

/// One-resource compositor damage accumulator. No implicit acknowledgement:
/// caller must validate used-index/head/length/type/fence from hardware before
/// calling ack_transfer or ack_flush. Unsettled submissions keep their damage.
#[derive(Default, Debug)]
pub struct DamageTracker {
    pending: Option<Rect>,
    in_flight: Option<InFlight>,
}

impl DamageTracker {
    pub fn new() -> Self { Self::default() }

    pub fn mark(&mut self, rect: Rect) -> Result<(), Error> {
        rect.validate()?;
        if self.in_flight.is_some() { return Err(Error::InFlight); }
        self.pending = Some(match self.pending {
            Some(previous) => previous.union(rect)?,
            None => rect,
        });
        Ok(())
    }

    pub fn pending(&self) -> Option<Rect> { self.pending }
    pub fn must_keep_resource_pinned(&self) -> bool { self.in_flight.is_some() }

    /// Returns both immutable commands; does not submit either one.
    pub fn begin(&mut self, transfer_fence: u64, flush_fence: u64)
        -> Result<Submission, Error>
    {
        if self.in_flight.is_some() { return Err(Error::InFlight); }
        let rect = self.pending.ok_or(Error::NoDamage)?;
        if transfer_fence == flush_fence { return Err(Error::DuplicateFence); }
        let transfer = encode_transfer(rect, transfer_fence)?;
        let flush = encode_flush(rect, flush_fence)?;
        self.in_flight = Some(InFlight {
            transfer_fence, flush_fence, transfer_acked: false,
        });
        Ok(Submission { rect, transfer_fence, flush_fence, transfer, flush })
    }

    /// Call only after a genuine, validated transfer reply from the device.
    pub fn ack_transfer(&mut self, fence: u64) -> Result<(), Error> {
        let state = self.in_flight.as_mut().ok_or(Error::UnexpectedAck)?;
        if state.transfer_fence != fence || state.transfer_acked {
            return Err(Error::UnexpectedAck);
        }
        state.transfer_acked = true;
        Ok(())
    }

    /// Clear damage only after *both* distinct hardware fence completions.
    pub fn ack_flush(&mut self, fence: u64) -> Result<(), Error> {
        let state = self.in_flight.ok_or(Error::UnexpectedAck)?;
        if state.flush_fence != fence { return Err(Error::UnexpectedAck); }
        if !state.transfer_acked { return Err(Error::FlushBeforeTransfer); }
        self.in_flight = None;
        self.pending = None;
        Ok(())
    }
}

/// Fixed-capacity queue for independent, disjoint dirty rectangles.
/// Never replace disjoint rectangles with their bounding box. The queue only
/// retires one rectangle after *two* separately validated GPU completions.
/// No heap, implicit retry or DMA access happens here.
#[derive(Debug)]
pub struct DamageQueue<const N: usize> {
    slots: [Option<Rect>; N],
    head: usize,
    count: usize,
    active: DamageTracker,
}

impl<const N: usize> DamageQueue<N> {
    pub fn new() -> Self {
        Self { slots: [None; N], head: 0, count: 0, active: DamageTracker::new() }
    }

    pub fn count(&self) -> usize { self.count }
    pub fn must_keep_resource_pinned(&self) -> bool {
        self.count != 0 || self.active.must_keep_resource_pinned()
    }

    pub fn push(&mut self, rect: Rect) -> Result<(), Error> {
        rect.validate()?;
        if self.active.must_keep_resource_pinned() { return Err(Error::InFlight); }
        if N == 0 || self.count == N { return Err(Error::Full); }
        for i in 0..self.count {
            let queued=self.slots[(self.head+i)%N].ok_or(Error::UnexpectedAck)?;
            if queued.overlaps(rect) { return Err(Error::OverlappingDamage); }
        }
        self.slots[(self.head+self.count)%N]=Some(rect);
        self.count+=1;
        Ok(())
    }

    pub fn begin(&mut self, transfer_fence:u64, flush_fence:u64)
        ->Result<Submission,Error>
    {
        if self.active.must_keep_resource_pinned() { return Err(Error::InFlight); }
        if self.count==0 { return Err(Error::NoDamage); }
        let rect=self.slots[self.head].ok_or(Error::UnexpectedAck)?;
        self.active.mark(rect)?;
        self.active.begin(transfer_fence,flush_fence)
    }

    pub fn ack_transfer(&mut self, fence:u64)->Result<(),Error>{
        self.active.ack_transfer(fence)
    }

    pub fn ack_flush(&mut self,fence:u64)->Result<(),Error>{
        self.active.ack_flush(fence)?;
        self.slots[self.head]=None;
        self.head=(self.head+1)%N;
        self.count-=1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn u32at(b: &[u8], i: usize) -> u32 {
        u32::from_le_bytes(b[i..i + 4].try_into().unwrap())
    }
    fn u64at(b: &[u8], i: usize) -> u64 {
        u64::from_le_bytes(b[i..i + 8].try_into().unwrap())
    }


    #[test]
    fn two_disjoint_rectangles_remain_separate_and_need_four_acks() {
        let a=Rect::checked(11,19,16,16).unwrap();
        let b=Rect::checked(811,401,32,16).unwrap();
        let mut q=DamageQueue::<2>::new();
        assert_eq!(q.begin(10,11),Err(Error::NoDamage));
        q.push(a).unwrap();
        q.push(b).unwrap();
        assert_eq!(q.count(),2);
        assert_eq!(q.push(Rect::checked(2,2,1,1).unwrap()),Err(Error::Full));
        let first=q.begin(0x100,0x101).unwrap();
        assert_eq!(first.rect,a);
        assert_eq!(u64at(&first.transfer,40),19*STRIDE_BYTES+11*4);
        assert_eq!(q.ack_flush(0x101),Err(Error::FlushBeforeTransfer));
        assert_eq!(q.ack_transfer(0x101),Err(Error::UnexpectedAck));
        assert_eq!(q.ack_transfer(0x100),Ok(()));
        assert!(q.must_keep_resource_pinned());
        assert_eq!(q.count(),2);
        assert_eq!(q.ack_flush(0x102),Err(Error::UnexpectedAck));
        assert_eq!(q.ack_flush(0x101),Ok(()));
        assert_eq!(q.count(),1);
        let second=q.begin(0x200,0x201).unwrap();
        assert_eq!(second.rect,b);
        assert_eq!(u64at(&second.transfer,40),401*STRIDE_BYTES+811*4);
        assert_eq!(q.ack_transfer(0x200),Ok(()));
        assert_eq!(q.ack_flush(0x201),Ok(()));
        assert_eq!(q.count(),0);
        assert!(!q.must_keep_resource_pinned());
        assert_eq!(q.begin(3,4),Err(Error::NoDamage));
        q.push(a).unwrap();
        assert_eq!(q.begin(5,6).unwrap().rect,a);
    }

    #[test]
    fn refuse_overlap_and_duplicate_and_inflight_damage() {
        let a=Rect::checked(10,20,16,16).unwrap();
        let mut q=DamageQueue::<3>::new();
        q.push(a).unwrap();
        assert_eq!(q.push(a),Err(Error::OverlappingDamage));
        assert_eq!(q.push(Rect::checked(25,35,2,2).unwrap()),
                   Err(Error::OverlappingDamage));
        q.push(Rect::checked(26,20,1,16).unwrap()).unwrap();
        assert_eq!(q.count(),2);
        assert_eq!(q.begin(0,4),Err(Error::InvalidFence));
        assert_eq!(q.begin(4,4),Err(Error::DuplicateFence));
        q.begin(7,8).unwrap();
        assert_eq!(q.push(Rect::checked(100,100,1,1).unwrap()),Err(Error::InFlight));
        assert_eq!(q.begin(9,10),Err(Error::InFlight));
        q.ack_transfer(7).unwrap();
        assert_eq!(q.ack_flush(9),Err(Error::UnexpectedAck));
        assert_eq!(q.count(),2);
        q.ack_flush(8).unwrap();
        assert_eq!(q.count(),1);
        let mut empty=DamageQueue::<0>::new();
        assert_eq!(empty.push(a),Err(Error::Full));
        assert_eq!(empty.begin(1,2),Err(Error::NoDamage));
    }

    #[test]
    fn single_pixel_in_last_column_has_full_resource_stride() {
        let r = Rect::checked(1023, 767, 1, 1).unwrap();
        assert_eq!(r.offset(), RESOURCE_BYTES - 4);
        let t = encode_transfer(r, 41).unwrap();
        let f = encode_flush(r, 42).unwrap();
        assert_eq!(t.len(), 56);
        assert_eq!(f.len(), 48);
        assert_eq!(u32at(&t, 0), CMD_TRANSFER_TO_HOST_2D);
        assert_eq!(u32at(&f, 0), CMD_RESOURCE_FLUSH);
        assert_eq!(u32at(&t, 24), 1023);
        assert_eq!(u32at(&t, 28), 767);
        assert_eq!(u32at(&t, 32), 1);
        assert_eq!(u32at(&t, 36), 1);
        assert_eq!(u64at(&t, 40), RESOURCE_BYTES - 4);
        assert_eq!(u32at(&t, 48), RESOURCE_ID);
        assert_eq!(u32at(&t, 52), 0);
        assert_eq!(u32at(&f, 40), RESOURCE_ID);
        assert_eq!(u32at(&f, 44), 0);
        assert_eq!(u32at(&t, 4), FLAG_FENCE);
        assert_eq!(u64at(&t, 8), 41);
        assert_eq!(u64at(&f, 8), 42);
    }

    #[test]
    fn reject_empty_overflow_outside_and_zero_fence() {
        assert_eq!(Rect::checked(0, 0, 0, 1), Err(Error::Empty));
        assert_eq!(Rect::checked(0, 0, 1, 0), Err(Error::Empty));
        assert_eq!(Rect::checked(1024, 0, 1, 1), Err(Error::OutOfBounds));
        assert_eq!(Rect::checked(0, 768, 1, 1), Err(Error::OutOfBounds));
        assert_eq!(Rect::checked(u32::MAX, 0, 2, 1), Err(Error::OutOfBounds));
        assert_eq!(Rect::checked(0, u32::MAX, 1, 2), Err(Error::OutOfBounds));
        let invalid = Rect { x: 1023, y: 767, width: 2, height: 2 };
        assert_eq!(encode_transfer(invalid, 1), Err(Error::OutOfBounds));
        assert_eq!(encode_flush(invalid, 1), Err(Error::OutOfBounds));
        let good = Rect::checked(0, 0, 1, 1).unwrap();
        assert_eq!(encode_transfer(good, 0), Err(Error::InvalidFence));
        assert_eq!(encode_flush(good, 0), Err(Error::InvalidFence));
    }

    #[test]
    fn conservative_union_keeps_disjoint_and_touching_damage() {
        let a = Rect::checked(6, 10, 4, 7).unwrap();
        let b = Rect::checked(11, 13, 2, 5).unwrap();
        assert_eq!(a.union(b).unwrap(), Rect::checked(6, 10, 7, 8).unwrap());
        let mut d = DamageTracker::new();
        d.mark(a).unwrap();
        d.mark(b).unwrap();
        assert_eq!(d.pending(), Some(Rect::checked(6, 10, 7, 8).unwrap()));
        d.mark(Rect::checked(0, 0, WIDTH, HEIGHT).unwrap()).unwrap();
        assert_eq!(d.pending(), Some(Rect::checked(0, 0, WIDTH, HEIGHT).unwrap()));
    }

    #[test]
    fn two_exact_fenced_acks_required_before_reusing_or_discarding_damage() {
        let rect = Rect::checked(7, 9, 3, 2).unwrap();
        let mut d = DamageTracker::new();
        assert_eq!(d.begin(1, 2), Err(Error::NoDamage));
        d.mark(rect).unwrap();
        assert_eq!(d.begin(1, 1), Err(Error::DuplicateFence));
        assert_eq!(d.begin(0, 2), Err(Error::InvalidFence));
        let batch = d.begin(11, 12).unwrap();
        assert_eq!(batch.rect, rect);
        assert_eq!(u64at(&batch.transfer, 40), 9 * STRIDE_BYTES + 7 * 4);
        assert_eq!(d.begin(13, 14), Err(Error::InFlight));
        assert_eq!(d.mark(rect), Err(Error::InFlight));
        assert_eq!(d.ack_flush(12), Err(Error::FlushBeforeTransfer));
        assert_eq!(d.ack_transfer(12), Err(Error::UnexpectedAck));
        assert_eq!(d.ack_transfer(11), Ok(()));
        assert_eq!(d.ack_transfer(11), Err(Error::UnexpectedAck));
        assert_eq!(d.ack_flush(13), Err(Error::UnexpectedAck));
        assert_eq!(d.pending(), Some(rect));
        assert!(d.must_keep_resource_pinned());
        assert_eq!(d.ack_flush(12), Ok(()));
        assert_eq!(d.pending(), None);
        assert!(!d.must_keep_resource_pinned());
        assert_eq!(d.ack_flush(12), Err(Error::UnexpectedAck));
        d.mark(rect).unwrap();
        assert!(d.begin(21, 22).is_ok());
    }

    #[test]
    fn partial_row_does_not_use_tight_cropped_stride() {
        let rect = Rect::checked(20, 65, 8, 2).unwrap();
        let t = encode_transfer(rect, 0x9988).unwrap();
        assert_eq!(u64at(&t, 40), 65 * 4096 + 80);
        assert_eq!(u32at(&t, 32), 8);
        assert_eq!(u32at(&t, 36), 2);
        assert_eq!(u32at(&t, 52), 0);
        assert!(t[16..24].iter().all(|b| *b == 0));
    }

    #[test]
    fn existing_full_width_band_is_identically_encoded() {
        let rect = Rect::checked(0, 384, 1024, 64).unwrap();
        let transfer = encode_transfer(rect, 101).unwrap();
        let flush = encode_flush(rect, 102).unwrap();
        assert_eq!(u64at(&transfer, 40), 384 * 4096);
        assert_eq!(u32at(&transfer, 28), 384);
        assert_eq!(u32at(&transfer, 32), 1024);
        assert_eq!(u32at(&flush, 28), 384);
        assert_eq!(u32at(&flush, 32), 1024);
        assert_eq!(u32at(&flush, 36), 64);
    }
}
