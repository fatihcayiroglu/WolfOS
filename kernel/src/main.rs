#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

//! WolfOS P0: original Rust kernel. Limine is a bootloader, not the OS kernel.
//! No heap, userspace, real-disk operations or device driver manager yet.

use core::arch::asm;
use core::panic::PanicInfo;
use limine::{BaseRevision, RequestsEndMarker, RequestsStartMarker};
use limine::request::{FramebufferRequest, HhdmRequest, MemmapRequest, MpRequest, RsdpRequest};

mod serial;
mod cpu;
mod pmm;
mod pmm_layout;
#[cfg(any(feature = "address-space-retirement-smoke", feature = "smp-address-space-retirement-smoke"))]
mod address_space_retirement;
mod tlb_shootdown;
#[cfg(feature = "smp-address-space-retirement-smoke")]
mod active_address_space;
#[cfg(feature = "smp-address-space-retirement-smoke")]
mod saved_context_retirement;
#[cfg(feature = "address-space-retirement-smoke")]
mod address_space_retirement_smoke;
#[cfg(feature = "smp-address-space-retirement-smoke")]
mod smp_address_space_retirement_smoke;
mod interrupts;
#[cfg(any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "p2-handoff-preflight-smoke", any(feature = "user-ring-prep-smoke", feature = "user-ring3-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke", feature = "user-file-io-smoke")), feature = "user-process-smoke")))))]
mod user_ring_entry;
#[cfg(feature = "user-ring3-smoke")]
mod user_ring3_smoke;
#[cfg(feature = "user-ring3-isolation-smoke")]
mod user_ring3_isolation_smoke;
#[cfg(any(feature = "process-table-smoke", any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "p2-handoff-preflight-smoke", any(feature = "kernel-stack-lease-smoke", any(feature = "user-context-smoke", any(feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke"))))))))]
mod user_syscall_abi;
#[cfg(any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke"))))]
mod user_syscall_entry;
#[cfg(feature = "user-syscall-smoke")]
mod user_syscall_smoke;
#[cfg(any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke"))]
mod user_elf_run_smoke;
#[cfg(any(any(feature = "user-copy-smoke", feature = "user-file-io-smoke"), feature = "user-vfs-smoke"))]
mod user_copy;
#[cfg(any(feature = "user-vfs-smoke", feature = "user-file-io-smoke"))]
mod user_file_io;
#[cfg(feature = "user-file-io-smoke")]
mod user_file_io_smoke;
#[cfg(any(feature = "p3-ring3-event-wait-hardware-smoke", any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "p2-handoff-preflight-smoke", any(feature = "user-fx-smoke", any(feature = "kernel-stack-lease-smoke", any(feature = "user-context-smoke", any(feature = "process-table-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))))))))]
mod process_lifecycle;
#[cfg(any(feature = "p3-ring3-event-wait-hardware-smoke", any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "p2-handoff-preflight-smoke", any(feature = "user-fx-smoke", any(feature = "kernel-stack-lease-smoke", any(feature = "process-table-smoke", feature = "user-context-smoke")))))))]
mod process_table;
#[cfg(any(feature = "process-table-smoke", any(feature = "p3-ring3-four-elf-preflight-smoke", feature = "p2-handoff-preflight-smoke", any(feature = "kernel-stack-lease-smoke", feature = "user-context-smoke"))))]
mod user_context_bank;
#[cfg(feature = "user-context-smoke")]
mod user_context_smoke;
#[cfg(feature = "kernel-stack-lease-smoke")]
mod kernel_stack_lease;
#[cfg(feature = "kernel-stack-lease-smoke")]
mod kernel_stack_lease_smoke;
#[cfg(any(feature = "kernel-stack-guard-smoke", feature = "kernel-stack-guard-fault-smoke", feature = "kernel-stack-guard-upper-fault-smoke"))]
mod kernel_stack_guard;
#[cfg(any(feature = "kernel-stack-guard-smoke", feature = "kernel-stack-guard-fault-smoke", feature = "kernel-stack-guard-upper-fault-smoke"))]
mod kernel_stack_guard_smoke;
#[cfg(any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "p2-handoff-preflight-smoke", any(feature = "high-half-stack-arena-smoke", feature = "high-half-stack-arena-lower-fault-smoke", feature = "high-half-stack-arena-upper-fault-smoke"))))]
mod high_half_stack_arena;
#[cfg(any(feature = "high-half-stack-arena-smoke", feature = "high-half-stack-arena-lower-fault-smoke", feature = "high-half-stack-arena-upper-fault-smoke"))]
mod high_half_stack_arena_smoke;
#[cfg(feature = "process-table-smoke")]
mod process_table_smoke;
#[cfg(any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke", feature = "user-file-io-smoke"))]
mod ramfs;
#[cfg(any(feature = "user-vfs-smoke", feature = "user-file-io-smoke"))]
mod vfs;
#[cfg(feature = "user-vfs-smoke")]
mod vfs_smoke;
#[cfg(any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke"))]
mod ramfs_smoke;
mod pci;
mod paging;
#[cfg(any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "elf64-preflight-smoke", feature = "user-vm-shadow-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke"))))]
mod elf64_preflight;
#[cfg(feature = "elf64-preflight-smoke")]
mod elf64_preflight_smoke;
#[cfg(any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "elf64-preflight-smoke", feature = "user-vm-shadow-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke"))))]
mod elf64_page_image;
#[cfg(feature = "user-vm-shadow-smoke")]
mod user_vm_layout;
#[cfg(feature = "user-vm-shadow-smoke")]
mod user_vm_shadow_smoke;
#[cfg(feature = "user-vm-shadow-smoke")]
mod user_vm_multi;
#[cfg(any(feature = "user-vm-shadow-smoke", feature = "smp-address-space-retirement-smoke"))]
mod pmm_frame_batch;
#[cfg(feature = "user-vm-shadow-smoke")]
mod user_image_admission;
#[cfg(any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "p2-handoff-preflight-smoke", any(feature = "user-vm-shadow-smoke", feature = "user-ring3-isolation-smoke", feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))))]
mod kernel_half_shadow;
#[cfg(feature = "user-vm-shadow-smoke")]
mod user_vm_multi_smoke;
mod acpi;
mod acpi_layout;
mod acpi_tables;
mod acpi_walk;
mod smp;
#[cfg(any(feature = "ap-ipi-smoke", feature = "tlb-shootdown-hardware-smoke", feature = "ap-local-timer-smoke",
           feature = "ap-smp-preempt-smoke", feature = "ap-remote-work-smoke",
           feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
mod ipi_layout;
#[cfg(any(feature = "ap-ipi-smoke", feature = "tlb-shootdown-hardware-smoke", feature = "ap-local-timer-smoke",
           feature = "ap-smp-preempt-smoke", feature = "ap-remote-work-smoke",
           feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
mod ap_ipi_smoke;
#[cfg(feature = "tlb-shootdown-hardware-smoke")]
mod tlb_shootdown_hardware_smoke;
#[cfg(any(feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke",
           feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
mod task_handoff;
#[cfg(any(feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
mod migrating_stack_contract;
#[cfg(feature = "ap-stack-migrate-smoke")]
mod ap_stack_migrate_smoke;
#[cfg(feature = "ap-irq-migrate-smoke")]
mod ap_irq_migrate_entry;
#[cfg(feature = "ap-irq-migrate-smoke")]
mod ap_irq_migrate_smoke;
#[cfg(feature = "ap-handoff-smoke")]
mod ap_handoff_smoke;
#[cfg(feature = "ap-handoff-smoke")]
mod ap_handoff_validation;
#[cfg(any(feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke",
           feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
mod remote_runqueue;
#[cfg(feature = "ap-remote-work-smoke")]
mod ap_remote_work_smoke;
#[cfg(feature = "ap-runqueue-smoke")]
mod percpu_work_queue;
#[cfg(feature = "ap-runqueue-smoke")]
mod ap_work_placement;
#[cfg(feature = "ap-runqueue-smoke")]
mod ap_runqueue_smoke;
#[cfg(feature = "ap-smp-preempt-smoke")]
mod ap_preempt_irq_entry;
#[cfg(feature = "ap-smp-preempt-smoke")]
mod ap_smp_preempt_smoke;
#[cfg(feature = "ap-smp-preempt-smoke")]
mod ap_preempt_progress_budget;
#[cfg(feature = "ap-smp-preempt-smoke")]
mod fx_bootstrap_image;
#[cfg(feature = "ap-local-timer-smoke")]
mod ap_local_timer_smoke;
mod ap_stack;
mod scheduler;
mod thread_scheduler;
mod context_switch;
mod kernel_threads;
mod context_batch;
mod percpu_context;
mod lapic_layout;
mod lapic_probe;
mod lapic_mmio_layout;
mod lapic_timer_layout;
mod lapic_mmio;
#[cfg(any(any(feature = "apic-timer-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")), feature = "apic-calibration-smoke",
           feature = "apic-preempt-smoke", feature = "ap-local-timer-smoke",
           feature = "ap-smp-preempt-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
mod lapic_timer_plan;
#[cfg(any(any(feature = "apic-timer-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")), feature = "apic-calibration-smoke",
           feature = "apic-preempt-smoke", feature = "ap-ipi-smoke",
           feature = "tlb-shootdown-hardware-smoke", feature = "ap-local-timer-smoke", feature = "ap-smp-preempt-smoke",
           feature = "ap-remote-work-smoke", feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
mod lapic_irq_layout;
#[cfg(any(any(feature = "apic-timer-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")), feature = "apic-calibration-smoke",
           feature = "apic-preempt-smoke"))]
mod apic_timer_smoke;
#[cfg(any(any(feature = "apic-timer-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")), feature = "apic-calibration-smoke",
           feature = "apic-preempt-smoke"))]
mod irq_frame_observation;
#[cfg(any(any(feature = "apic-timer-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")), feature = "apic-calibration-smoke",
           feature = "apic-preempt-smoke", feature = "ap-smp-preempt-smoke",
           feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
mod kernel_trap_frame;
#[cfg(any(any(feature = "apic-timer-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")), feature = "apic-calibration-smoke",
           feature = "apic-preempt-smoke"))]
mod apic_irq_entry;
#[cfg(feature = "apic-preempt-smoke")]
mod apic_preempt_smoke;
#[cfg(any(feature = "apic-preempt-smoke", feature = "ap-smp-preempt-smoke"))]
mod preempt_depth;
#[cfg(any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "p2-handoff-preflight-smoke", any(feature = "apic-preempt-smoke", feature = "user-fx-smoke"))))]
mod fx_state;
#[cfg(any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "p2-handoff-preflight-smoke", feature = "user-fx-smoke")))]
mod user_fx_bank;
#[cfg(feature = "user-fx-smoke")]
mod user_fx_smoke;
#[cfg(feature = "p2-handoff-preflight-smoke")]
mod handoff_preflight_smoke;
#[cfg(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))))]
mod user_yield_switch_smoke;
#[cfg(feature = "p2-ring3-timer-preempt-smoke")]
mod ring3_round_robin;
// Generation-safe N-task policy is shared by Ring3 IRQ smoke and standalone
// context-preflight flavors. It never performs hardware state transitions.
#[cfg(any(feature = "p2-ring3-timer-nonyield-smoke",
          feature = "p2-ring3-timer-preempt-smoke",
          feature = "p3-ring3-event-wait-hardware-smoke",
          feature = "p2-handoff-preflight-smoke",
          feature = "kernel-stack-lease-smoke",
          feature = "user-context-smoke",
          feature = "process-table-smoke"))]
mod ring3_runqueue;
// A no-heap event registration/notification gate for the isolated real
// two-ELF WAIT/SIGNAL QEMU feature. The caller must serialize it against
// BSP interrupts and independently authenticate producer provenance.
#[cfg(feature = "p3-ring3-event-wait-hardware-smoke")]
mod ring3_event_wait_gate;
// Only the real four-user BSP QEMU IRQ acceptance uses this EOI audit;
// legacy two-user and simulated policy paths are left unchanged.
#[cfg(feature = "p3-ring3-four-elf-live-smoke")]
mod ring3_irq_eoi_ledger;
#[cfg(any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")))]
mod user_irq_preempt_contract;
#[cfg(any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))]
mod user_xapic_high;
#[cfg(feature = "apic-preempt-smoke")]
mod rr_policy;
#[cfg(feature = "apic-preempt-smoke")]
mod task_slot;
#[cfg(feature = "apic-calibration-smoke")]
mod lapic_timer_calibration;
#[cfg(feature = "timer-smoke")]
mod timer;
#[cfg(any(feature = "timer-smoke", any(feature = "apic-timer-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke")),
          feature = "apic-calibration-smoke", feature = "apic-preempt-smoke"))]
mod timer_tasks;

#[used]
#[unsafe(link_section = ".requests_start_marker")]
static START_MARKER: RequestsStartMarker = RequestsStartMarker::new();

#[used]
#[unsafe(link_section = ".requests")]
// Base revision 4 guarantees ACPI firmware tables are mapped in typed HHDM regions.
static BASE_REVISION: BaseRevision = BaseRevision::with_revision(4);

#[used]
#[unsafe(link_section = ".requests")]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static MEMMAP_REQUEST: MemmapRequest = MemmapRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static HHDM_REQUEST: HhdmRequest = HhdmRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static RSDP_REQUEST: RsdpRequest = RsdpRequest::new();

#[used]
#[unsafe(link_section = ".requests")]
static MP_REQUEST: MpRequest = MpRequest::new(0);

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
    interrupts::initialize();
    #[cfg(feature = "user-ring-prep-smoke")]
    if !interrupts::verify_ring3_preconditions() {
        serial::write_line("WOLFOS_RING_PREP_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "exception-smoke")]
    interrupts::trigger_invalid_opcode();

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
    let Some(hhdm) = HHDM_REQUEST.response() else {
        serial::write_line("WOLFOS_ERROR: HHDM unavailable");
        halt_forever();
    };
    match pmm::initialize(entries, hhdm.offset) {
        Ok(stats) => serial::write_fmt(format_args!(
            "WOLFOS_PMM_OK regions={} total_frames={} free_frames={} metadata_frames={} bitmap_bytes={}\n",
            stats.usable_regions, stats.total_frames, stats.free_frames(),
            stats.metadata_frames, stats.bitmap_bytes
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
    serial::write_line("WOLFOS_PMM_DYNAMIC_OK");
    let pci_summary = pci::discover();
    if pci_summary.devices == 0 || pci_summary.displays == 0 {
        serial::write_line("WOLFOS_PCI_TEST_FAILED no supported QEMU VGA/PCI devices");
        halt_forever();
    }
    serial::write_line("WOLFOS_PCI_TEST_OK");
    let Some(rsdp_response) = RSDP_REQUEST.response() else {
        serial::write_line("WOLFOS_ACPI_ERROR no Limine RSDP response");
        halt_forever();
    };
    let Some(acpi_info) = acpi::report_rsdp(rsdp_response.address) else {
        serial::write_line("WOLFOS_ACPI_TEST_FAILED");
        halt_forever();
    };
    if !acpi_walk::discover(acpi_info, hhdm.offset, entries) {
        serial::write_line("WOLFOS_ACPI_TOPOLOGY_TEST_FAILED");
        halt_forever();
    }

    if !paging::mapping_roundtrip(hhdm.offset) {
        serial::write_line("WOLFOS_PAGING_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "elf64-preflight-smoke")]
    if !elf64_preflight_smoke::verify(hhdm.offset) {
        serial::write_line("WOLFOS_ELF64_PREFLIGHT_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "user-vm-shadow-smoke")]
    if !user_vm_shadow_smoke::verify(hhdm.offset) {
        serial::write_line("WOLFOS_USER_ROOT_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "user-vm-shadow-smoke")]
    if !user_vm_multi_smoke::verify(hhdm.offset) {
        serial::write_line("WOLFOS_USER_MULTI_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "paging-fault-smoke")]
    paging::trigger_unmapped_read();

    #[cfg(feature = "address-space-retirement-smoke")]
    if !address_space_retirement_smoke::verify(hhdm.offset) {
        serial::write_line("WOLFOS_ADDRESS_SPACE_RETIRE_TEST_FAILED");
        halt_forever();
    }



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
    let Some(mp) = MP_REQUEST.response() else {
        serial::write_line("WOLFOS_SMP_ERROR no Limine MP response");
        halt_forever();
    };
    if !lapic_mmio::verify_bsp(mp.bsp_lapic_id, hhdm.offset, entries) {
        serial::write_line("WOLFOS_LAPIC_MMIO_TEST_FAILED");
        halt_forever();
    }
    // Feature-isolated BSP mapping exists BEFORE AP startup: APs inherit
    // a writable UC local-APIC alias for private IRQ acknowledgement.
    #[cfg(any(feature = "ap-ipi-smoke", feature = "tlb-shootdown-hardware-smoke", feature = "ap-local-timer-smoke",
               feature = "ap-smp-preempt-smoke", feature = "ap-remote-work-smoke",
               feature = "ap-handoff-smoke", feature = "ap-stack-migrate-smoke", feature = "ap-irq-migrate-smoke", feature = "ap-runqueue-smoke"))]
    if !ap_ipi_smoke::prepare_bsp(mp.bsp_lapic_id, hhdm.offset, entries, mp.cpus()) {
        serial::write_line("WOLFOS_AP_IPI_ERROR cannot_prepare_xapic");
        halt_forever();
    }
    #[cfg(feature = "smp-address-space-retirement-smoke")]
    if !smp_address_space_retirement_smoke::prepare_bsp(mp.bsp_lapic_id, mp.cpus(), hhdm.offset) {
        serial::write_line("WOLFOS_SMP_RETIRE_ERROR prepare_failed");
        halt_forever();
    }
    if !smp::boot_aps(mp) {
        serial::write_line("WOLFOS_SMP_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "smp-address-space-retirement-smoke")]
    if !smp_address_space_retirement_smoke::verify_bsp() {
        serial::write_line("WOLFOS_SMP_RETIRE_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "ap-irq-migrate-smoke")]
    if !ap_irq_migrate_smoke::verify_bsp(mp.bsp_lapic_id, mp.cpus()) {
        serial::write_line("WOLFOS_AP_IRQ_MIGRATE_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "ap-stack-migrate-smoke")]
    if !ap_stack_migrate_smoke::verify_bsp(mp.bsp_lapic_id, mp.cpus()) {
        serial::write_line("WOLFOS_AP_STACK_MIGRATE_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "ap-handoff-smoke")]
    if !ap_handoff_smoke::verify_bsp(mp.bsp_lapic_id, mp.cpus()) {
        serial::write_line("WOLFOS_AP_HANDOFF_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "ap-runqueue-smoke")]
    if !ap_runqueue_smoke::verify_bsp(mp.bsp_lapic_id, mp.cpus()) {
        serial::write_line("WOLFOS_AP_RUNQUEUE_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "ap-remote-work-smoke")]
    if !ap_remote_work_smoke::verify_bsp(mp.bsp_lapic_id, mp.cpus()) {
        serial::write_line("WOLFOS_REMOTE_WORK_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "ap-smp-preempt-smoke")]
    if !ap_smp_preempt_smoke::verify_bsp(mp.bsp_lapic_id, mp.cpus()) {
        serial::write_line("WOLFOS_AP_SMP_PREEMPT_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "ap-local-timer-smoke")]
    if !ap_local_timer_smoke::verify_bsp(mp.bsp_lapic_id, mp.cpus()) {
        serial::write_line("WOLFOS_AP_LOCAL_TIMER_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "tlb-shootdown-hardware-smoke")]
    if !ap_ipi_smoke::verify_tlb_shootdown_bsp(mp.bsp_lapic_id, mp.cpus()) {
        serial::write_line("WOLFOS_TLB_SHOOTDOWN_HW_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "ap-ipi-smoke")]
    if !ap_ipi_smoke::verify_bsp(mp.bsp_lapic_id, mp.cpus()) {
        serial::write_line("WOLFOS_AP_IPI_TEST_FAILED");
        halt_forever();
    }
    if !context_switch::verify_roundtrip() {
        serial::write_line("WOLFOS_CONTEXT_TEST_FAILED");
        halt_forever();
    }
    if !kernel_threads::verify() {
        serial::write_line("WOLFOS_KTHREAD_TEST_FAILED");
        halt_forever();
    }
    if !context_batch::verify() {
        serial::write_line("WOLFOS_CTX_BATCH_TEST_FAILED");
        halt_forever();
    }
    #[cfg(feature = "timer-smoke")]
    if !timer::verify() {
        serial::write_line("WOLFOS_TIMER_TEST_FAILED");
        halt_forever();
    }
    #[cfg(any(feature = "apic-timer-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"),
           feature = "apic-calibration-smoke", feature = "apic-preempt-smoke"))]
    if !apic_timer_smoke::verify(mp.bsp_lapic_id, hhdm.offset, entries) {
        serial::write_line("WOLFOS_APIC_TIMER_TEST_FAILED");
        halt_forever();
    }
    serial::write_line("WOLFOS_BOOT_OK");

    #[cfg(any(feature = "p2-ring3-yield-smoke", feature = "p2-ring3-irq-ready-smoke"))]
    user_yield_switch_smoke::enter(hhdm.offset);

    #[cfg(feature = "user-ring3-smoke")]
    user_ring3_smoke::enter(hhdm.offset);

    #[cfg(feature = "user-ring3-isolation-smoke")]
    user_ring3_isolation_smoke::enter(hhdm.offset);

    #[cfg(feature = "user-syscall-smoke")]
    user_syscall_smoke::enter(hhdm.offset);

    #[cfg(any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke"))]
    user_elf_run_smoke::enter(hhdm.offset);

    #[cfg(feature = "process-table-smoke")]
    process_table_smoke::verify();

    #[cfg(feature = "user-context-smoke")]
    user_context_smoke::verify();

    #[cfg(feature = "kernel-stack-lease-smoke")]
    kernel_stack_lease_smoke::verify(hhdm.offset);

    #[cfg(any(feature = "kernel-stack-guard-smoke", feature = "kernel-stack-guard-fault-smoke", feature = "kernel-stack-guard-upper-fault-smoke"))]
    kernel_stack_guard_smoke::verify(hhdm.offset);

    #[cfg(any(feature = "high-half-stack-arena-smoke", feature = "high-half-stack-arena-lower-fault-smoke", feature = "high-half-stack-arena-upper-fault-smoke"))]
    high_half_stack_arena_smoke::verify(hhdm.offset);

    #[cfg(feature = "user-fx-smoke")]
    user_fx_smoke::verify();

    #[cfg(feature = "p2-handoff-preflight-smoke")]
    handoff_preflight_smoke::verify(hhdm.offset);

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
