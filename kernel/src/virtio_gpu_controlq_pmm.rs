//! QEMU-only PMM ownership test for a future VirtIO-GPU controlq.
//! Allocates three real, independent RAM frames and frees all of them.
//! It NEVER submits frame addresses to the GPU or enables DMA/queues.
use crate::{pmm, serial, virtio_gpu_controlq_ro_contract as controlq};
use x86_64::VirtAddr;

pub fn verify(hhdm:u64, layout:controlq::Layout)->bool {
    if x86_64::instructions::interrupts::are_enabled() {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_PMM_FAIL interrupts_enabled");
        return false;
    }
    // The deliberately capped 256-descriptor split-ring layout guarantees
    // each of the 3 distinct queue parts fits in one physical PMM frame.
    if layout.selected < 2 || layout.desc_pages != 1
        || layout.avail_pages != 1 || layout.used_pages != 1
        || layout.desc_bytes > controlq::PAGE_BYTES
        || layout.avail_bytes > controlq::PAGE_BYTES
        || layout.used_bytes > controlq::PAGE_BYTES
    {
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_PMM_FAIL layout");
        return false;
    }
    let baseline = pmm::statistics().allocated_frames;
    let mut frames=[0u64;3];
    let mut acquired=0usize;
    for slot in &mut frames {
        match pmm::allocate_frame() {
            Some(addr) => {
                *slot=addr;
                acquired+=1;
            }
            None => break,
        }
    }
    // NO early return after any PMM allocation. Every acquired frame
    // must be released even after invalid layout, VA or zeroing evidence.
    let peak = pmm::statistics().allocated_frames;
    let addresses_ok = acquired==3
        && controlq::validate_future_regions(layout, frames[0],frames[1],frames[2]).is_ok();
    let sizes=[layout.desc_bytes, layout.avail_bytes, layout.used_bytes];
    let mut zero_verified=addresses_ok;
    if addresses_ok {
        for (index,frame) in frames.iter().copied().enumerate() {
            let addr = hhdm.checked_add(frame)
                .and_then(|x| VirtAddr::try_new(x).ok());
            let Some(va)=addr else {zero_verified=false;break;};
            // SAFETY: every frame came from exclusive PMM allocation of
            // usable RAM, is page-aligned and HHDM mapped; no interrupt or
            // other CPU is operating in this opt-in single-vCPU QEMU flavor.
            // Only these 3 owned RAM pages are zeroed, never PCI MMIO.
            let ptr=va.as_mut_ptr::<u8>();
            unsafe { core::ptr::write_bytes(ptr,0,controlq::PAGE_BYTES as usize); }
            // Read all 4096 bytes back using volatile loads; no marker is
            // emitted merely because memset returned without an exception.
            for offset in 0..controlq::PAGE_BYTES as usize {
                if unsafe { ptr.add(offset).read_volatile() } != 0 {
                    zero_verified=false;
                    break;
                }
            }
            // The planned active ring footprint must itself fit the page.
            if !zero_verified || sizes[index] > controlq::PAGE_BYTES {
                zero_verified=false;
                break;
            }
        }
    }
    let mut released=0usize;
    let mut release_errors=0usize;
    for frame in frames[..acquired].iter().rev().copied() {
        if pmm::free_frame(frame).is_ok() {released+=1;}
        else {release_errors+=1;}
    }
    let after=pmm::statistics().allocated_frames;
    let balanced=baseline.checked_add(3)==Some(peak)
        && acquired==3 && released==3 && release_errors==0 && after==baseline;
    if !addresses_ok || !zero_verified || !balanced {
        serial::write_fmt(format_args!(
            "WOLFOS_VIRTIO_GPU_CONTROLQ_PMM_FAIL acquired={} released={} peak={} baseline={} after={} addresses_ok={} zero_verified={}\n",
            acquired,released,peak,baseline,after,addresses_ok,zero_verified
        ));
        return false;
    }
    serial::write_fmt(format_args!(
        "WOLFOS_VIRTIO_GPU_CONTROLQ_PMM_OK layout_n={} frames_allocated=3 frames_released=3 disjoint=1 zeroed=1 pmm_leak=0 no_queue=1 dma=0\n",
        layout.selected
    ));
    true
}
