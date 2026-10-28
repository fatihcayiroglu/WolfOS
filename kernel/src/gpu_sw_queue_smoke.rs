//! Real QEMU-only CPU software command queue exercising the validated
//! Limine framebuffer. This is *not* GPU DMA or accelerated command submission.
//! Uses bounded volatile writes and restores every touched pixel.

use crate::{
    gpu_sw_queue_contract::{Command, Layout, QueueError, Rect, SoftwareQueue},
    serial,
};

const WIDTH: u32 = 1280;
const HEIGHT: u32 = 800;
const PITCH: usize = 5120;
const BYTES: usize = PITCH * HEIGHT;
const A: u32 = 0x0044_2211;
const B: u32 = 0x0088_5533;
const C: u32 = 0x0000_aa66;

#[inline]
fn sample(p: *mut u32, i: usize) -> u32 {
    // SAFETY: opt-in one-vCPU QEMU stdvga, first five validated mapped
    // 32bpp framebuffer pixels, before any framebuffer console work.
    unsafe { p.add(i).read_volatile() }
}
#[inline]
fn restore(p: *mut u32, i: usize, value: u32) {
    // SAFETY: same bounded validated QEMU framebuffer mapping.
    unsafe { p.add(i).write_volatile(value); }
}

pub(crate) fn prove(width:u64, height:u64, pitch:u64, pointer:*mut u8) -> bool {
    // Caller already checked Limine RGB framebuffer and PCI 1234:1111
    // against real Bochs VBE geometry and full virtual state.
    if width != WIDTH as u64 || height != HEIGHT as u64 || pitch != PITCH as u64
        || pointer.is_null() || (pointer as usize) % 4 != 0
    {
        serial::write_line("WOLFOS_GPU_SW_QUEUE_FAIL stage=layout");
        return false;
    }
    let layout=Layout {
        width: WIDTH, height: HEIGHT, pitch_bytes:PITCH, backing_bytes:BYTES
    };
    if !layout.valid() {
        serial::write_line("WOLFOS_GPU_SW_QUEUE_FAIL stage=layout_policy");
        return false;
    }
    // SAFETY: guarded exact QEMU 1280x800x32bpp framebuffer with pitch=5120;
    // 4,096,000 bytes is strictly below pre-attested 16 MiB video memory.
    let backing=unsafe { core::slice::from_raw_parts_mut(pointer,BYTES) };
    let pixels=backing.as_mut_ptr().cast::<u32>();
    let saved=[sample(pixels,0),sample(pixels,1),sample(pixels,2),
               sample(pixels,3),sample(pixels,4)];
    let mut queue=SoftwareQueue::new();

    let result=(|| -> Result<bool,QueueError> {
        let commands=[
            Command::Fill {rect:Rect{x:0,y:0,width:1,height:1},pixel:A},
            Command::Fill {rect:Rect{x:1,y:0,width:1,height:1},pixel:B},
            Command::Fill {rect:Rect{x:2,y:0,width:1,height:1},pixel:C},
        ];
        if queue.stage(layout,&commands)? != 1 {
            return Ok(false);
        }
        if queue.completed_fence()!=0 || queue.pending_count()!=3 {
            return Ok(false);
        }
        if queue.execute(layout,backing)? != 1 {
            return Ok(false);
        }
        let shifted=[Command::Copy {
            src:Rect{x:0,y:0,width:3,height:1},dst_x:1,dst_y:0
        }];
        if queue.stage(layout,&shifted)? != 2 {
            return Ok(false);
        }
        if queue.execute(layout,backing)? != 2 {
            return Ok(false);
        }
        Ok(
            [sample(pixels,0),sample(pixels,1),sample(pixels,2),sample(pixels,3)]
                == [A,A,B,C]
            && sample(pixels,4)==saved[4]
            && queue.submitted_fence()==2
            && queue.completed_fence()==2
            && queue.pending_count()==0
        )
    })();

    // Restore the exact original scanout pixel bytes on ALL outcomes, even if
    // a stage/execute check failed. No window over the framebuffer persists.
    for (i,pixel) in saved.iter().copied().enumerate() { restore(pixels,i,pixel); }
    let restored=(0..5).all(|i|sample(pixels,i)==saved[i]);
    if result != Ok(true) || !restored {
        serial::write_fmt(format_args!(
            "WOLFOS_GPU_SW_QUEUE_FAIL stage=execute result={:?} restored={}\n",
            result,u8::from(restored),
        ));
        return false;
    }
    serial::write_line(
        "WOLFOS_GPU_SW_QUEUE_OK pci=1234:1111 size=1280x800 pitch=5120 submissions=2 commands=4 last_fence=2 overlap_copy=1 untouched_pixel=1 pixels_restored=1 native_accel=0"
    );
    true
}
