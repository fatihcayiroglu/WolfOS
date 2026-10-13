#![no_std]
#![no_main]

//! WolfOS P0: original Rust kernel. Limine is a bootloader, not the OS kernel.
//! No heap, userspace, real-disk operations or device driver manager yet.

use core::arch::asm;
use core::panic::PanicInfo;
use limine::{BaseRevision, RequestsEndMarker, RequestsStartMarker};
use limine::request::{FramebufferRequest, MemmapRequest};

mod serial;
mod cpu;
mod pmm;

#[used]
#[unsafe(link_section = ".requests_start_marker")]
static START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[unsafe(link_section = ".requests")]
static BASE_REVISION: BaseRevision = BaseRevision::with_revision(0);

#[used]
#[unsafe(link_section = ".requests")]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static MEMMAP_REQUEST: MemmapRequest = MemmapRequest::new();

#[used]
#[unsafe(link_section = ".requests_end_marker")]
static END_MARKER: RequestsEndMarker = RequestsEndMarker::new();

#[unsafe(no_mangle)]
pub extern "C" fn kmain() -> ! {
    serial::init();
    serial::write_line("WOLFOS: Rust kernel entered");

    if !BASE_REVISION.is_supported() {
        serial::write_line("WOLFOS_ERROR: unsupported Limine base revision");
        halt_forever();
    }
    serial::write_line("WOLFOS_LIMINE_OK");
    cpu::log_identity();

    let Some(memmap) = MEMMAP_REQUEST.response() else {
        serial::write_line("WOLFOS_ERROR: memory map unavailable");
        halt_forever();
    };
    let entries = memmap.entries();
    if entries.is_empty() {
        serial::write_line("WOLFOS_ERROR: empty memory map");
        halt_forever();
    }
    let usable_bytes: u64 = entries
        .iter()
        .filter(|entry| entry.type_ == limine::memmap::MEMMAP_USABLE)
        .fold(0_u64, |acc, entry| acc.saturating_add(entry.length));
    serial::write_fmt(format_args!(
        "WOLFOS_MEMMAP_OK entries={} usable_mib={}\n",
        entries.len(), usable_bytes / 1_048_576
    ));
    match pmm::initialize(entries) {
        Ok(stats) => serial::write_fmt(format_args!(
            "WOLFOS_PMM_OK regions={} total_frames={} free_frames={}\n",
            stats.usable_regions, stats.total_frames, stats.free_frames()
        )),
        Err(error) => {
            serial::write_fmt(format_args!("WOLFOS_PMM_ERROR {error:?}\n"));
            halt_forever();
        }
    }
    if !pmm::self_test() {
        serial::write_line("WOLFOS_PMM_TEST_FAILED");
        halt_forever();
    }
    serial::write_line("WOLFOS_PMM_TEST_OK iterations=10000 unique=128");


    let Some(fb_response) = FRAMEBUFFER_REQUEST.response() else {
        serial::write_line("WOLFOS_ERROR: framebuffer unavailable");
        halt_forever();
    };
    let Some(fb) = fb_response.framebuffers().first() else {
        serial::write_line("WOLFOS_ERROR: no framebuffer provided");
        halt_forever();
    };
    if fb.bpp != 32
        || fb.memory_model != limine::framebuffer::FRAMEBUFFER_RGB
        || fb.red_mask_size != 8
        || fb.green_mask_size != 8
        || fb.blue_mask_size != 8
    {
        serial::write_line("WOLFOS_ERROR: unsupported framebuffer pixel format");
        halt_forever();
    }
    let width = fb.width.min(640);
    let height = fb.height.min(192);
    if fb.pitch < fb.width.saturating_mul(4) || width == 0 || height == 0 {
        serial::write_line("WOLFOS_ERROR: invalid framebuffer geometry");
        halt_forever();
    }
    for y in 0..height {
        for x in 0..width {
            let (r,g,b) = if y < 64 { (22_u32, 54_u32, 68_u32) }
                          else { (12_u32, 22_u32, 39_u32) };
            let value = ((r & ((1 << fb.red_mask_size) - 1)) << fb.red_mask_shift)
                      | ((g & ((1 << fb.green_mask_size) - 1)) << fb.green_mask_shift)
                      | ((b & ((1 << fb.blue_mask_size) - 1)) << fb.blue_mask_shift);
            let offset = (y * fb.pitch + x * 4) as usize;
            // SAFETY: Limine gives a mapped framebuffer and we clamp coordinates.
            unsafe { fb.address().cast::<u8>().add(offset).cast::<u32>().write_volatile(value); }
        }
    }
    serial::write_fmt(format_args!("WOLFOS_FRAMEBUFFER_OK {}x{}\n", fb.width, fb.height));
    serial::write_line("WOLFOS_BOOT_OK");

    #[cfg(feature = "smoke-exit")]
    serial::qemu_exit_success();

    #[cfg(not(feature = "smoke-exit"))]
    halt_forever()
}

pub fn halt_forever() -> ! {
    loop {
        // SAFETY: interrupts are disabled before halting in P0.
        unsafe { asm!("cli; hlt", options(nomem, nostack)); }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    serial::write_fmt(format_args!("WOLFOS_PANIC: {info}\n"));
    halt_forever()
}
