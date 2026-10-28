//! Bounded, allocation-free CPU reference backend for a future WolfOS GPU
//! command API. This software queue is NOT GPU hardware command submission.
//! Only checked 32bpp surfaces, fixed-capacity batches and synchronous fences.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub width: u32,
    pub height: u32,
    pub pitch_bytes: usize,
    pub backing_bytes: usize,
}

impl Layout {
    pub fn valid(self) -> bool {
        if self.width == 0 || self.height == 0 || self.pitch_bytes == 0
            || self.pitch_bytes % 4 != 0
        {
            return false;
        }
        let Some(row) = (self.width as usize).checked_mul(4) else { return false };
        let Some(bytes) = self.pitch_bytes.checked_mul(self.height as usize) else {
            return false;
        };
        self.pitch_bytes >= row && self.backing_bytes >= bytes && bytes > 0
    }

    fn offset(self, x: u32, y: u32) -> usize {
        // Only reached after validating layout and rect bounds.
        (y as usize) * self.pitch_bytes + (x as usize) * 4
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect { pub x: u32, pub y: u32, pub width: u32, pub height: u32 }

impl Rect {
    fn inside(self, layout: Layout) -> bool {
        self.width > 0 && self.height > 0
            && self.x.checked_add(self.width).is_some_and(|x| x <= layout.width)
            && self.y.checked_add(self.height).is_some_and(|y| y <= layout.height)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Fill { rect: Rect, pixel: u32 },
    Copy { src: Rect, dst_x: u32, dst_y: u32 },
}

impl Command {
    fn allowed(self, layout: Layout) -> bool {
        match self {
            Self::Fill { rect, .. } => rect.inside(layout),
            Self::Copy { src, dst_x, dst_y } => {
                src.inside(layout)
                    && dst_x.checked_add(src.width).is_some_and(|x| x <= layout.width)
                    && dst_y.checked_add(src.height).is_some_and(|y| y <= layout.height)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueError {
    InvalidLayout,
    InvalidCommand,
    Capacity,
    Busy,
    EmptyBatch,
    WrongLayout,
    ShortBacking,
    FenceExhausted,
    NotSubmitted,
}

pub const MAX_COMMANDS: usize = 8;

pub struct SoftwareQueue {
    entries: [Option<Command>; MAX_COMMANDS],
    count: usize,
    submitted: u64,
    completed: u64,
    pending_layout: Option<Layout>,
}
impl SoftwareQueue {
    pub const fn new() -> Self {
        Self {
            entries: [None; MAX_COMMANDS],
            count: 0,
            submitted: 0,
            completed: 0,
            pending_layout: None,
        }
    }

    pub fn submitted_fence(&self) -> u64 { self.submitted }
    pub fn completed_fence(&self) -> u64 { self.completed }
    pub fn pending_count(&self) -> usize { self.count }

    /// Validate the ENTIRE batch before any state change. A rejected command
    /// cannot change queue contents, issued fences, or a framebuffer.
    pub fn stage(&mut self, layout: Layout, commands: &[Command]) -> Result<u64, QueueError> {
        if self.pending_layout.is_some() { return Err(QueueError::Busy); }
        if !layout.valid() { return Err(QueueError::InvalidLayout); }
        if commands.is_empty() { return Err(QueueError::EmptyBatch); }
        if commands.len() > MAX_COMMANDS { return Err(QueueError::Capacity); }
        if !commands.iter().all(|cmd| cmd.allowed(layout)) {
            return Err(QueueError::InvalidCommand);
        }
        let next = self.submitted.checked_add(1).ok_or(QueueError::FenceExhausted)?;
        for (i, command) in commands.iter().copied().enumerate() {
            self.entries[i] = Some(command);
        }
        self.count = commands.len();
        self.pending_layout = Some(layout);
        self.submitted = next;
        Ok(next)
    }

    /// Execute a staged batch on mapped 32bpp pixels with VOLATILE bytes.
    /// Backing memory is validated before any write; fence completion occurs
    /// only after the entire synchronous software batch is executed.
    /// No asynchronous GPU engine or real hardware fence is implied.
    pub fn execute(&mut self, layout: Layout, backing: &mut [u8]) -> Result<u64, QueueError> {
        let staged = self.pending_layout.ok_or(QueueError::NotSubmitted)?;
        if staged != layout { return Err(QueueError::WrongLayout); }
        if !layout.valid() { return Err(QueueError::InvalidLayout); }
        if backing.len() < layout.backing_bytes { return Err(QueueError::ShortBacking); }
        for index in 0..self.count {
            let command = self.entries[index].expect("staged command is present");
            match command {
                Command::Fill { rect, pixel } => fill(layout, backing, rect, pixel),
                Command::Copy { src, dst_x, dst_y } =>
                    copy(layout, backing, src, dst_x, dst_y),
            }
        }
        self.completed = self.submitted;
        self.entries = [None; MAX_COMMANDS];
        self.count = 0;
        self.pending_layout = None;
        Ok(self.completed)
    }
}

#[inline]
fn load_pixel(backing: &[u8], offset: usize) -> u32 {
    let p = backing.as_ptr();
    // SAFETY: layout and every rectangle were validated before execute.
    // Four individual volatile bytes avoid alignment-dependent u32 access.
    let bytes = unsafe {
        [
            p.add(offset).read_volatile(),
            p.add(offset + 1).read_volatile(),
            p.add(offset + 2).read_volatile(),
            p.add(offset + 3).read_volatile(),
        ]
    };
    u32::from_le_bytes(bytes)
}
#[inline]
fn store_pixel(backing: &mut [u8], offset: usize, pixel: u32) {
    let p = backing.as_mut_ptr();
    let bytes = pixel.to_le_bytes();
    // SAFETY: layout and every rectangle were validated before execute;
    // backing.len() covers backing_bytes, which covers the full visible plane.
    unsafe {
        for (i, byte) in bytes.iter().copied().enumerate() {
            p.add(offset + i).write_volatile(byte);
        }
    }
}
fn fill(layout: Layout, backing: &mut [u8], rect: Rect, pixel: u32) {
    for row in 0..rect.height {
        for col in 0..rect.width {
            store_pixel(backing, layout.offset(rect.x + col, rect.y + row), pixel);
        }
    }
}
fn copy(layout: Layout, backing: &mut [u8], src: Rect, dst_x: u32, dst_y: u32) {
    // memmove semantics for a single source/destination surface. Bottom-up
    // when moving down; right-to-left on same-row right shifts.
    let reverse_y = dst_y > src.y;
    let reverse_x = dst_y == src.y && dst_x > src.x;
    for iy in 0..src.height {
        let row = if reverse_y { src.height - 1 - iy } else { iy };
        for ix in 0..src.width {
            let col = if reverse_x { src.width - 1 - ix } else { ix };
            let value = load_pixel(backing, layout.offset(src.x + col, src.y + row));
            store_pixel(backing, layout.offset(dst_x + col, dst_y + row), value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn layout() -> Layout {
        Layout { width: 8, height: 4, pitch_bytes: 32, backing_bytes: 128 }
    }
    fn rect(x:u32,y:u32,w:u32,h:u32)->Rect {
        Rect { x,y,width:w,height:h }
    }
    fn fill_cmd(x:u32,y:u32,w:u32,h:u32,v:u32)->Command {
        Command::Fill { rect:rect(x,y,w,h),pixel:v }
    }
    fn pixel(bytes:&[u8],x:u32,y:u32)->u32 {
        load_pixel(bytes,layout().offset(x,y))
    }
    #[test]
    fn valid_exact_and_padded_surface() {
        assert!(layout().valid());
        assert!(Layout { pitch_bytes:40,backing_bytes:160,..layout() }.valid());
    }
    #[test]
    fn no_zero_geometry() {
        assert!(!Layout { width:0,..layout() }.valid());
        assert!(!Layout { height:0,..layout() }.valid());
    }
    #[test]
    fn no_understride_or_partial_pixel_stride() {
        assert!(!Layout { pitch_bytes:31,..layout() }.valid());
        assert!(!Layout { pitch_bytes:28,..layout() }.valid());
    }
    #[test]
    fn no_short_or_overflowed_surface() {
        assert!(!Layout { backing_bytes:127,..layout() }.valid());
        assert!(!Layout { pitch_bytes:usize::MAX,..layout() }.valid());
    }
    #[test]
    fn stage_rejects_empty_and_long_batch() {
        let mut q=SoftwareQueue::new();
        assert_eq!(q.stage(layout(),&[]),Err(QueueError::EmptyBatch));
        let nine=[fill_cmd(0,0,1,1,1);9];
        assert_eq!(q.stage(layout(),&nine),Err(QueueError::Capacity));
        assert_eq!(q.submitted_fence(),0);
    }
    #[test]
    fn reject_zero_and_overflow_rectangle() {
        let mut q=SoftwareQueue::new();
        for r in [rect(0,0,0,1),rect(0,0,1,0),rect(7,0,2,1),
                  rect(u32::MAX,0,2,1),rect(0,u32::MAX,1,2)] {
            assert_eq!(q.stage(layout(),&[Command::Fill{rect:r,pixel:1}]),
                       Err(QueueError::InvalidCommand));
        }
        assert_eq!(q.pending_count(),0);
    }
    #[test]
    fn invalid_copy_destination_rejected() {
        let mut q=SoftwareQueue::new();
        for (x,y) in [(7,0),(0,3),(u32::MAX,0),(0,u32::MAX)] {
            assert_eq!(q.stage(layout(),&[Command::Copy {
                src:rect(0,0,2,2),dst_x:x,dst_y:y
            }]),Err(QueueError::InvalidCommand));
        }
    }
    #[test]
    fn atomic_stage_rejects_one_bad_command() {
        let mut q=SoftwareQueue::new();
        assert_eq!(q.stage(layout(),&[
            fill_cmd(0,0,1,1,1),fill_cmd(8,0,1,1,2)
        ]),Err(QueueError::InvalidCommand));
        assert_eq!(q.pending_count(),0);
        assert_eq!(q.submitted_fence(),0);
    }
    #[test]
    fn queue_busy_does_not_overwrite_pending_batch() {
        let mut q=SoftwareQueue::new();
        assert_eq!(q.stage(layout(),&[fill_cmd(0,0,1,1,1)]),Ok(1));
        assert_eq!(q.stage(layout(),&[fill_cmd(0,0,1,1,2)]),Err(QueueError::Busy));
        assert_eq!(q.pending_count(),1);
        assert_eq!(q.submitted_fence(),1);
    }
    #[test]
    fn cannot_execute_without_submission() {
        let mut q=SoftwareQueue::new();
        let mut bytes=[0u8;128];
        assert_eq!(q.execute(layout(),&mut bytes),Err(QueueError::NotSubmitted));
    }
    #[test]
    fn wrong_layout_does_not_execute_or_complete_fence() {
        let mut q=SoftwareQueue::new();
        let mut bytes=[0u8;128];
        q.stage(layout(),&[fill_cmd(0,0,1,1,0x12345678)]).unwrap();
        let wrong=Layout{height:2,..layout()};
        assert_eq!(q.execute(wrong,&mut bytes),Err(QueueError::WrongLayout));
        assert_eq!(q.completed_fence(),0);
        assert_eq!(bytes[0],0);
        assert_eq!(q.pending_count(),1);
    }
    #[test]
    fn backing_shortage_does_not_execute_or_complete_fence() {
        let mut q=SoftwareQueue::new();
        let mut bytes=[0u8;127];
        q.stage(layout(),&[fill_cmd(0,0,1,1,0x12345678)]).unwrap();
        assert_eq!(q.execute(layout(),&mut bytes),Err(QueueError::ShortBacking));
        assert_eq!(q.completed_fence(),0);
        assert!(bytes.iter().all(|b|*b==0));
    }
    #[test]
    fn single_fill_writes_only_target_pixel() {
        let mut q=SoftwareQueue::new();
        let mut bytes=[0u8;128];
        assert_eq!(q.stage(layout(),&[fill_cmd(1,1,1,1,0xaabbccdd)]),Ok(1));
        assert_eq!(q.execute(layout(),&mut bytes),Ok(1));
        assert_eq!(pixel(&bytes,1,1),0xaabbccdd);
        assert_eq!(pixel(&bytes,0,1),0);
        assert_eq!(pixel(&bytes,2,1),0);
        assert_eq!(q.pending_count(),0);
    }
    #[test]
    fn fills_are_in_order_and_fence_monotonic() {
        let mut q=SoftwareQueue::new();
        let mut bytes=[0u8;128];
        assert_eq!(q.stage(layout(),&[
            fill_cmd(0,0,2,2,1),fill_cmd(1,1,1,1,2)
        ]),Ok(1));
        assert_eq!(q.completed_fence(),0);
        assert_eq!(q.execute(layout(),&mut bytes),Ok(1));
        assert_eq!(pixel(&bytes,1,1),2);
        assert_eq!(pixel(&bytes,0,0),1);
        assert_eq!(q.stage(layout(),&[fill_cmd(1,1,1,1,3)]),Ok(2));
        assert_eq!(q.execute(layout(),&mut bytes),Ok(2));
        assert_eq!(q.completed_fence(),2);
    }
    #[test]
    fn horizontal_overlap_has_memmove_semantics() {
        let mut q=SoftwareQueue::new();
        let mut bytes=[0u8;128];
        q.stage(layout(),&[
            fill_cmd(0,0,1,1,1),fill_cmd(1,0,1,1,2),
            fill_cmd(2,0,1,1,3),
        ]).unwrap();
        q.execute(layout(),&mut bytes).unwrap();
        q.stage(layout(),&[Command::Copy{src:rect(0,0,3,1),dst_x:1,dst_y:0}]).unwrap();
        q.execute(layout(),&mut bytes).unwrap();
        assert_eq!((0..4).map(|x|pixel(&bytes,x,0)).collect::<Vec<_>>(),
                   vec![1,1,2,3]);
    }
    #[test]
    fn vertical_overlap_has_memmove_semantics() {
        let mut q=SoftwareQueue::new();
        let mut bytes=[0u8;128];
        q.stage(layout(),&[
            fill_cmd(0,0,1,1,11),fill_cmd(0,1,1,1,22),
            fill_cmd(0,2,1,1,33),
        ]).unwrap();
        q.execute(layout(),&mut bytes).unwrap();
        q.stage(layout(),&[Command::Copy{src:rect(0,0,1,3),dst_x:0,dst_y:1}]).unwrap();
        q.execute(layout(),&mut bytes).unwrap();
        assert_eq!((0..4).map(|y|pixel(&bytes,0,y)).collect::<Vec<_>>(),
                   vec![11,11,22,33]);
    }
    #[test]
    fn upward_overlapping_copy_uses_top_down() {
        let mut q=SoftwareQueue::new();
        let mut bytes=[0u8;128];
        q.stage(layout(),&[
            fill_cmd(0,0,1,1,1),fill_cmd(0,1,1,1,2),
            fill_cmd(0,2,1,1,3),fill_cmd(0,3,1,1,4)
        ]).unwrap();
        q.execute(layout(),&mut bytes).unwrap();
        q.stage(layout(),&[Command::Copy{src:rect(0,1,1,3),dst_x:0,dst_y:0}]).unwrap();
        q.execute(layout(),&mut bytes).unwrap();
        assert_eq!((0..4).map(|y|pixel(&bytes,0,y)).collect::<Vec<_>>(),
                   vec![2,3,4,4]);
    }
    #[test]
    fn fence_exhaustion_fails_closed() {
        let mut q=SoftwareQueue::new();
        q.submitted=u64::MAX;
        assert_eq!(q.stage(layout(),&[fill_cmd(0,0,1,1,1)]),
                   Err(QueueError::FenceExhausted));
        assert_eq!(q.pending_count(),0);
    }
    #[test]
    fn full_capacity_is_accepted() {
        let mut q=SoftwareQueue::new();
        let mut bytes=[0u8;128];
        let eight=[fill_cmd(0,0,1,1,42);8];
        assert_eq!(q.stage(layout(),&eight),Ok(1));
        assert_eq!(q.execute(layout(),&mut bytes),Ok(1));
        assert_eq!(pixel(&bytes,0,0),42);
    }
    #[test]
    fn wrong_surface_at_stage_does_not_allocate_fence() {
        let mut q=SoftwareQueue::new();
        assert_eq!(q.stage(Layout{pitch_bytes:4,..layout()},&[fill_cmd(0,0,1,1,1)]),
                   Err(QueueError::InvalidLayout));
        assert_eq!(q.submitted_fence(),0);
    }
}
