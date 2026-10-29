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
mod framebuffer_text;
mod framebuffer_console;
mod shell_command;
#[cfg(feature = "ps2-graphics-demo")]
mod ps2_keyboard;
#[cfg(feature = "ps2-graphics-demo")]
mod ps2_graphics_demo;
#[cfg(feature = "ps2-graphics-demo")]
mod graphical_diagnostics;
#[cfg(feature = "ps2-graphics-demo")]
mod graphical_line_editor;
#[cfg(feature = "ps2-graphics-irq-smoke")]
mod ps2_scancode_queue;
#[cfg(feature = "ps2-graphics-irq-smoke")]
mod ps2_irq;
#[cfg(feature = "serial-shell")]
mod serial_shell;
mod cpu;
mod pmm;
mod pmm_layout;
#[cfg(any(
    feature = "address-space-retirement-smoke",
    feature = "smp-address-space-retirement-smoke",
    feature = "user-elf-run-smoke",
    feature = "user-process-smoke",
    feature = "user-copy-smoke",
    feature = "user-file-io-smoke",
    feature = "user-ramfs-smoke",
    feature = "user-vfs-smoke",
))]
mod address_space_retirement;
mod tlb_shootdown;
#[cfg(any(
    feature = "smp-address-space-retirement-smoke",
    feature = "user-elf-run-smoke",
    feature = "user-process-smoke",
    feature = "user-copy-smoke",
    feature = "user-file-io-smoke",
    feature = "user-ramfs-smoke",
    feature = "user-vfs-smoke",
))]
mod active_address_space;
#[cfg(feature = "smp-address-space-retirement-smoke")]
mod ring3_context_retirement;
#[cfg(any(
    feature = "smp-address-space-retirement-smoke",
    feature = "user-elf-run-smoke",
    feature = "user-process-smoke",
    feature = "user-copy-smoke",
    feature = "user-file-io-smoke",
    feature = "user-ramfs-smoke",
    feature = "user-vfs-smoke",
))]
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
#[cfg(any(feature = "smp-address-space-retirement-smoke", feature = "process-table-smoke", any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "p2-handoff-preflight-smoke", any(feature = "kernel-stack-lease-smoke", any(feature = "user-context-smoke", any(feature = "user-syscall-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke"))))))))]
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
#[cfg(feature = "user-file-io-smoke")]
mod app_permissions;
#[cfg(any(feature = "smp-address-space-retirement-smoke", feature = "p3-ring3-event-wait-hardware-smoke", any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "p2-handoff-preflight-smoke", any(feature = "user-fx-smoke", any(feature = "kernel-stack-lease-smoke", any(feature = "user-context-smoke", any(feature = "process-table-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke")))))))))]
mod process_lifecycle;
#[cfg(any(feature = "user-elf-run-smoke", feature = "user-process-smoke", feature = "user-copy-smoke", feature = "user-file-io-smoke", feature = "user-ramfs-smoke", feature = "user-vfs-smoke", feature = "smp-address-space-retirement-smoke", feature = "p3-ring3-event-wait-hardware-smoke", any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "p2-handoff-preflight-smoke", any(feature = "user-fx-smoke", any(feature = "kernel-stack-lease-smoke", any(feature = "process-table-smoke", feature = "user-context-smoke")))))))]
mod process_table;
#[cfg(any(feature = "smp-address-space-retirement-smoke", feature = "process-table-smoke", any(feature = "p3-ring3-four-elf-preflight-smoke", feature = "p2-handoff-preflight-smoke", any(feature = "kernel-stack-lease-smoke", feature = "user-context-smoke"))))]
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
mod display_driver_policy;
mod display_mode_policy;
mod display_mode_catalog;
mod display_edid_base;
mod display_edid_cta;
mod virtio_gpu_edid_wire;
#[cfg(feature = "qemu-virtio-gpu-edid-live-smoke")]
mod virtio_gpu_edid_live_contract;
#[cfg(feature = "qemu-virtio-gpu-resource2d-smoke")]
mod virtio_gpu_resource2d_contract;
#[cfg(feature = "qemu-virtio-gpu-attach-backing-smoke")]
mod virtio_gpu_backing_contract;
#[cfg(feature = "qemu-virtio-gpu-transfer2d-smoke")]
mod virtio_gpu_transfer2d_contract;
#[cfg(feature = "qemu-virtio-gpu-scanout-live-smoke")]
mod virtio_gpu_scanout_contract;
#[cfg(feature = "qemu-virtio-gpu-pci-smoke")]
mod virtio_gpu_pci_caps;
#[cfg(feature = "qemu-virtio-gpu-bars-smoke")]
mod virtio_gpu_pci_bars;
#[cfg(feature = "qemu-virtio-gpu-bar-size-smoke")]
mod virtio_gpu_bar_size_contract;
#[cfg(feature = "qemu-virtio-gpu-common-mmio-smoke")]
mod virtio_gpu_mmio_contract;
#[cfg(feature = "qemu-virtio-gpu-common-mmio-smoke")]
mod virtio_gpu_common_mmio;
#[cfg(feature = "qemu-virtio-gpu-device-mmio-smoke")]
mod virtio_gpu_device_mmio_contract;
#[cfg(feature = "qemu-virtio-gpu-device-mmio-smoke")]
mod virtio_gpu_device_mmio;
#[cfg(feature = "qemu-virtio-gpu-transport-preflight-smoke")]
mod virtio_gpu_transport_preflight_contract;
#[cfg(feature = "qemu-virtio-gpu-transport-preflight-smoke")]
mod virtio_gpu_transport_preflight;
#[cfg(feature = "qemu-virtio-gpu-bank1-tx-smoke")]
mod virtio_gpu_bank1_tx_contract;
#[cfg(feature = "qemu-virtio-gpu-bank1-tx-smoke")]
mod virtio_gpu_bank1_tx;
#[cfg(feature = "qemu-virtio-gpu-negotiate-smoke")]
mod virtio_gpu_feature_neg_contract;
#[cfg(feature = "qemu-virtio-gpu-negotiate-smoke")]
mod virtio_gpu_feature_neg;
#[cfg(feature = "qemu-virtio-gpu-controlq-ro-smoke")]
mod virtio_gpu_controlq_ro_contract;
#[cfg(feature = "qemu-virtio-gpu-controlq-ro-smoke")]
mod virtio_gpu_controlq_ro;
#[cfg(feature = "qemu-virtio-gpu-controlq-pmm-smoke")]
mod virtio_gpu_controlq_pmm;
#[cfg(feature = "qemu-virtio-gpu-controlq-tx-smoke")]
mod virtio_gpu_controlq_tx_contract;
#[cfg(feature = "qemu-virtio-gpu-controlq-tx-smoke")]
mod virtio_gpu_controlq_tx;
#[cfg(feature = "qemu-virtio-gpu-notify-ro-smoke")]
mod virtio_gpu_notify_contract;
#[cfg(feature = "qemu-virtio-gpu-notify-ro-smoke")]
mod virtio_gpu_notify_ro;
#[cfg(feature = "qemu-virtio-gpu-display-info-smoke")]
mod virtio_gpu_display_info_contract;
#[cfg(feature = "qemu-virtio-gpu-display-info-smoke")]
mod virtio_gpu_display_info;
#[cfg(feature = "qemu-stdvga-dispi-smoke")]
mod qemu_dispi_contract;
#[cfg(feature = "qemu-stdvga-dispi-smoke")]
mod qemu_display_attestation;
#[cfg(feature = "qemu-stdvga-dispi-smoke")]
mod qemu_stdvga_dispi_smoke;
#[cfg(feature = "qemu-stdvga-enable-tx-smoke")]
mod qemu_vbe_transaction_contract;
#[cfg(feature = "qemu-stdvga-enable-tx-smoke")]
mod qemu_vbe_enable_tx;
#[cfg(feature = "qemu-stdvga-full-state-smoke")]
mod qemu_vbe_full_state_contract;
#[cfg(feature = "qemu-stdvga-full-state-smoke")]
mod qemu_vbe_full_state_smoke;
#[cfg(feature = "qemu-stdvga-mode-rollback-smoke")]
mod qemu_vbe_mode_rollback_contract;
#[cfg(feature = "qemu-stdvga-mode-rollback-smoke")]
mod qemu_vbe_mode_rollback_smoke;
mod gpu_sw_queue_contract;
#[cfg(feature = "qemu-stdvga-software-queue-smoke")]
mod gpu_sw_queue_smoke;
mod paging;
#[cfg(any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "elf64-preflight-smoke", feature = "user-vm-shadow-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke"))))]
mod elf64_preflight;
#[cfg(any(feature = "user-vm-shadow-smoke", feature = "user-elf-run-smoke",
          feature = "user-process-smoke", feature = "user-copy-smoke",
          feature = "user-file-io-smoke", feature = "user-ramfs-smoke",
          feature = "user-vfs-smoke"))]
mod user_elf_launch_layout;
#[cfg(any(feature = "user-elf-run-smoke", feature = "user-process-smoke",
          feature = "user-copy-smoke", feature = "user-file-io-smoke",
          feature = "user-ramfs-smoke", feature = "user-vfs-smoke"))]
mod user_elf_page_tables;
#[cfg(any(feature = "user-elf-run-smoke", feature = "user-process-smoke",
          feature = "user-copy-smoke", feature = "user-file-io-smoke",
          feature = "user-ramfs-smoke", feature = "user-vfs-smoke"))]
mod elf_launch_transaction;
#[cfg(feature = "elf64-preflight-smoke")]
mod elf64_preflight_smoke;
#[cfg(any(any(feature = "p2-ring3-yield-smoke", any(feature = "p2-ring3-irq-ready-smoke", any(feature = "p2-ring3-timer-observe-smoke", feature = "p2-ring3-timer-preempt-smoke"))), any(feature = "elf64-preflight-smoke", feature = "user-vm-shadow-smoke", any(any(any(feature = "user-elf-run-smoke", any(feature = "user-copy-smoke", feature = "user-file-io-smoke")), any(feature = "user-ramfs-smoke", feature = "user-vfs-smoke")), feature = "user-process-smoke"))))]
mod elf64_page_image;
#[cfg(any(feature = "user-vm-shadow-smoke", feature = "user-elf-two-pt-run-smoke"))]
mod user_vm_layout;
#[cfg(feature = "user-vm-shadow-smoke")]
mod user_vm_shadow_smoke;
#[cfg(any(feature = "user-vm-shadow-smoke", feature = "user-elf-two-pt-run-smoke"))]
mod user_vm_multi;
#[cfg(any(feature = "user-vm-shadow-smoke", feature = "user-elf-two-pt-run-smoke"))]
mod user_vm_two_pt;
#[cfg(any(
    feature = "user-vm-shadow-smoke",
    feature = "smp-address-space-retirement-smoke",
    feature = "user-elf-run-smoke",
    feature = "user-process-smoke",
    feature = "user-copy-smoke",
    feature = "user-file-io-smoke",
    feature = "user-ramfs-smoke",
    feature = "user-vfs-smoke",
))]
mod pmm_frame_batch;
#[cfg(any(feature = "user-vm-shadow-smoke", feature = "user-elf-two-pt-run-smoke"))]
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
          feature = "process-table-smoke",
          feature = "smp-address-space-retirement-smoke"))]
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
    // Every mandatory smoke flavor enables smoke-exit; normal/COM1 boots
    // must not stress-allocate 128 frames and run 10,000 allocator probes
    // before providing a useful interface. CI exercises this path exactly.
    #[cfg(feature = "smoke-exit")]
    {
        if !pmm::self_test() {
            serial::write_line("WOLFOS_PMM_TEST_FAILED");
            halt_forever();
        }
        serial::write_line("WOLFOS_PMM_TEST_OK iterations=10000 unique=128");
        serial::write_line("WOLFOS_PMM_DYNAMIC_OK");
    }
    let pci_summary = pci::discover();
    if pci_summary.devices == 0 || pci_summary.displays == 0 {
        serial::write_line("WOLFOS_PCI_TEST_FAILED no supported QEMU VGA/PCI devices");
        halt_forever();
    }
    serial::write_line("WOLFOS_PCI_TEST_OK");
    #[cfg(feature = "qemu-virtio-gpu-pci-smoke")]
    if pci_summary.virtio_gpu_caps_verified != 1 {
        serial::write_line("WOLFOS_VIRTIO_GPU_PCI_TEST_FAILED");
        halt_forever();
    } else {
        serial::write_line("WOLFOS_VIRTIO_GPU_PCI_TEST_OK");
    }
    #[cfg(feature = "qemu-virtio-gpu-bar-size-smoke")]
    if pci_summary.virtio_gpu_bar_size_verified != 1 {
        serial::write_line("WOLFOS_VIRTIO_GPU_BAR_SIZE_TEST_FAILED");
        halt_forever();
    } else {
        serial::write_line("WOLFOS_VIRTIO_GPU_BAR_SIZE_TEST_OK");
    }
    #[cfg(feature = "qemu-virtio-gpu-common-mmio-smoke")]
    {
        let Some(window) = pci_summary.common_window else {
            serial::write_line("WOLFOS_VIRTIO_GPU_COMMON_MMIO_TEST_FAILED no_window");
            halt_forever();
        };
        if !virtio_gpu_common_mmio::verify(hhdm.offset, entries, window) {
            serial::write_line("WOLFOS_VIRTIO_GPU_COMMON_MMIO_TEST_FAILED");
            halt_forever();
        }
        serial::write_line("WOLFOS_VIRTIO_GPU_COMMON_MMIO_TEST_OK");
    }
    #[cfg(feature = "qemu-virtio-gpu-device-mmio-smoke")]
    {
        let Some(window) = pci_summary.device_window else {
            serial::write_line("WOLFOS_VIRTIO_GPU_DEVICE_MMIO_TEST_FAILED no_window");
            halt_forever();
        };
        if !virtio_gpu_device_mmio::verify(hhdm.offset, entries, window) {
            serial::write_line("WOLFOS_VIRTIO_GPU_DEVICE_MMIO_TEST_FAILED");
            halt_forever();
        }
        serial::write_line("WOLFOS_VIRTIO_GPU_DEVICE_MMIO_TEST_OK");
    }
    #[cfg(feature = "qemu-virtio-gpu-transport-preflight-smoke")]
    {
        let Some(window) = pci_summary.common_window else {
            serial::write_line("WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_TEST_FAILED no_common_window");
            halt_forever();
        };
        if !virtio_gpu_transport_preflight::verify(hhdm.offset, entries, window) {
            serial::write_line("WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_TEST_FAILED");
            halt_forever();
        }
        serial::write_line("WOLFOS_VIRTIO_GPU_TRANSPORT_PREFLIGHT_TEST_OK");
    }
    #[cfg(feature = "qemu-virtio-gpu-bank1-tx-smoke")]
    {
        let Some(window) = pci_summary.common_window else {
            serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_TEST_FAILED no_common_window");
            halt_forever();
        };
        if !virtio_gpu_bank1_tx::verify(hhdm.offset, entries, window) {
            serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_TEST_FAILED");
            halt_forever();
        }
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_BANK1_TX_TEST_OK");
    }
    #[cfg(feature = "qemu-virtio-gpu-negotiate-smoke")]
    {
        let Some(window) = pci_summary.common_window else {
            serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_TEST_FAILED no_common_window");
            halt_forever();
        };
        if !virtio_gpu_feature_neg::verify(hhdm.offset, entries, window) {
            serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_TEST_FAILED");
            halt_forever();
        }
        serial::write_line("WOLFOS_VIRTIO_GPU_FEATURE_NEGOTIATION_TEST_OK");
    }
    #[cfg(feature = "qemu-virtio-gpu-controlq-ro-smoke")]
    {
        let Some(window) = pci_summary.common_window else {
            serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_RO_TEST_FAILED no_common_window");
            halt_forever();
        };
        let Some(controlq_layout) =
            virtio_gpu_controlq_ro::verify(hhdm.offset, entries, window)
        else {
            serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_RO_TEST_FAILED");
            halt_forever();
        };
        serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_RO_TEST_OK");
        #[cfg(feature = "qemu-virtio-gpu-controlq-pmm-smoke")]
        {
            if !virtio_gpu_controlq_pmm::verify(hhdm.offset, controlq_layout) {
                serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_PMM_TEST_FAILED");
                halt_forever();
            }
            serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_PMM_TEST_OK");
            #[cfg(feature = "qemu-virtio-gpu-controlq-tx-smoke")]
            {
                if !virtio_gpu_controlq_tx::verify(
                    hhdm.offset, entries, window, controlq_layout
                ) {
                    serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_TX_TEST_FAILED");
                    halt_forever();
                }
                serial::write_line("WOLFOS_VIRTIO_GPU_CONTROLQ_TX_TEST_OK");
                #[cfg(feature = "qemu-virtio-gpu-notify-ro-smoke")]
                {
                    let Some(notify_window)=pci_summary.notify_window else{
                        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_TEST_FAILED missing_notify_cap");
                        halt_forever();
                    };
                    if !virtio_gpu_notify_ro::verify(
                        hhdm.offset,entries,window,notify_window
                    ){
                        serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_TEST_FAILED");
                        halt_forever();
                    }
                    serial::write_line("WOLFOS_VIRTIO_GPU_NOTIFY_RO_TEST_OK");
                    #[cfg(feature = "qemu-virtio-gpu-display-info-smoke")]
                    {
                        if !virtio_gpu_display_info::verify(
                            hhdm.offset,entries,window,notify_window,controlq_layout
                        ){
                            serial::write_line("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_FAILED");
                            halt_forever();
                        }
                        serial::write_line("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK");
                        #[cfg(feature = "qemu-virtio-gpu-edid-live-smoke")]
                        serial::write_line("WOLFOS_VIRTIO_GPU_EDID_LIVE_TEST_OK");
                        #[cfg(all(feature = "qemu-virtio-gpu-resource2d-smoke",
                                  not(feature = "qemu-virtio-gpu-attach-backing-smoke")))]
                        serial::write_line("WOLFOS_VIRTIO_GPU_RESOURCE2D_TEST_OK");
                        #[cfg(all(feature = "qemu-virtio-gpu-attach-backing-smoke",
                                  not(feature = "qemu-virtio-gpu-transfer2d-smoke")))]
                        serial::write_line("WOLFOS_VIRTIO_GPU_ATTACH_BACKING_TEST_OK");
                        #[cfg(all(feature = "qemu-virtio-gpu-transfer2d-smoke",
                                  not(feature = "qemu-virtio-gpu-scanout-live-smoke")))]
                        serial::write_line("WOLFOS_VIRTIO_GPU_TRANSFER2D_TEST_OK");
                        #[cfg(feature = "qemu-virtio-gpu-scanout-live-smoke")]
                        serial::write_line("WOLFOS_VIRTIO_GPU_SCANOUT_TEST_OK");
                    }
                }
            }
        }
        #[cfg(not(feature = "qemu-virtio-gpu-controlq-pmm-smoke"))]
        let _ = controlq_layout;
    }
    #[cfg(feature = "qemu-stdvga-dispi-smoke")]
    let Some(dispi_snapshot) = qemu_stdvga_dispi_smoke::prove(pci_summary.qemu_stdvga) else {
        serial::write_line("WOLFOS_QEMU_DISPI_TEST_FAILED");
        halt_forever();
    };
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

    // Real page-table exercise belongs to the isolated mandatory smoke
    // flavors; ordinary boot does not map/unmap disposable test pages.
    #[cfg(feature = "smoke-exit")]
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
    // Validate the full mapped pitch*height and aligned pointer BEFORE the
    // first framebuffer write, including the initial color-band fill.
    let Some(layout) = framebuffer_text::Layout::new(fb.width, fb.height, fb.pitch) else {
        serial::write_line("WOLFOS_FB_TEXT_FAILED invalid_geometry");
        halt_forever();
    };
    if (fb.address() as usize) % 4 != 0
        || fb.red_mask_shift > 24
        || fb.green_mask_shift > 24
        || fb.blue_mask_shift > 24
    {
        serial::write_line("WOLFOS_FB_TEXT_FAILED unaligned_or_invalid_shifts");
        halt_forever();
    }
    #[cfg(feature = "qemu-stdvga-dispi-smoke")]
    {
        if !qemu_display_attestation::matches_scanout(
            dispi_snapshot, fb.width, fb.height, fb.pitch, fb.bpp as u16,
        ) {
            serial::write_line("WOLFOS_QEMU_DISPLAY_ATTEST_FAILED stage=mode_or_vram");
            halt_forever();
        }
        serial::write_fmt(format_args!(
            "WOLFOS_QEMU_DISPLAY_ATTEST_OK width={} height={} pitch={} bpp={} vram64k={} rgb=1 mode_writes=0\n",
            fb.width, fb.height, fb.pitch, fb.bpp, dispi_snapshot.vram64k,
        ));
        #[cfg(feature = "qemu-stdvga-full-state-smoke")]
        let Some(full_before) = qemu_vbe_full_state_smoke::capture(dispi_snapshot) else {
            serial::write_line("WOLFOS_QEMU_VBE_FULL_TEST_FAILED stage=before");
            halt_forever();
        };
        #[cfg(feature = "qemu-stdvga-enable-tx-smoke")]
        if !qemu_vbe_enable_tx::prove(dispi_snapshot, fb.address().cast::<u32>()) {
            serial::write_line("WOLFOS_QEMU_VBE_ENABLE_TX_TEST_FAILED");
            halt_forever();
        }
        #[cfg(feature = "qemu-stdvga-full-state-smoke")]
        if !qemu_vbe_full_state_smoke::verify_after(full_before, dispi_snapshot) {
            serial::write_line("WOLFOS_QEMU_VBE_FULL_TEST_FAILED stage=after");
            halt_forever();
        }
        #[cfg(feature = "qemu-stdvga-mode-rollback-smoke")]
        if !qemu_vbe_mode_rollback_smoke::prove(
            dispi_snapshot, full_before, fb.address().cast::<u32>()
        ) {
            serial::write_line("WOLFOS_QEMU_VBE_MODE_ROLLBACK_TEST_FAILED");
            halt_forever();
        }
        #[cfg(feature = "qemu-stdvga-software-queue-smoke")]
        if !gpu_sw_queue_smoke::prove(
            fb.width, fb.height, fb.pitch, fb.address().cast::<u8>()
        ) {
            serial::write_line("WOLFOS_GPU_SW_QUEUE_TEST_FAILED");
            halt_forever();
        }
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
    // Allocation-free original Rust glyphs are written through volatile stores.
    // The mapped stride and raw pointer were already validated before painting.
    let white = (255u32 << fb.red_mask_shift)
        | (255u32 << fb.green_mask_shift)
        | (255u32 << fb.blue_mask_shift);
    let first_line = layout.draw_text(20, 20, "WOLFOS", white, |offset, color| {
        // SAFETY: layout checked offset+4 against pitch*height (<=isize::MAX).
        // Limine supplies an accessible mapped framebuffer; aligned 32-bpp
        // pixel writes are required by the validated pixel layout above.
        unsafe { fb.address().cast::<u8>().add(offset).cast::<u32>().write_volatile(color); }
    });
    let _second_line = layout.draw_text(20, 36, "RUST KERNEL", white, |offset, color| {
        // SAFETY: same validated framebuffer layout and volatile pixel writes.
        unsafe { fb.address().cast::<u8>().add(offset).cast::<u32>().write_volatile(color); }
    });
    let witness = layout.pixel_offset(20, 20);
    let readback_ok = if let Some(offset) = witness {
        // SAFETY: checked in-range aligned 32-bit pixel offset into Limine FB.
        unsafe { fb.address().cast::<u8>().add(offset).cast::<u32>().read_volatile() == white }
    } else {
        false
    };
    if first_line < 10 || !readback_ok {
        serial::write_line("WOLFOS_FB_TEXT_FAILED missing_pixel_readback");
        halt_forever();
    }
    serial::write_fmt(format_args!("WOLFOS_FB_TEXT_OK glyph_pixels={} first_pixel=verified\n", first_line));

    // This is an early static graphical console preview, not a user shell.
    // It uses bounded RAM text cells with no heap and BSP-only volatile writes.
    let console_cols = (fb.width.saturating_sub(20) / 6).min(40) as usize;
    let console_rows = (fb.height.saturating_sub(80) / 8).min(5) as usize;
    if let Some(mut console) = framebuffer_console::TextConsole::new(
        layout, 20, 80, console_cols, console_rows,
    ) {
        console.write("WOLFOS READY\nTEXT CONSOLE PREVIEW\nNO KEYBOARD YET");
        let pixels = console.render(white, 0, |offset, color| {
            // SAFETY: constructor validates every full cell in the mapped
            // 32bpp framebuffer and Layout checks individual byte offsets.
            unsafe { fb.address().cast::<u8>().add(offset).cast::<u32>().write_volatile(color); }
        });
        let expected = console_cols * console_rows * 6 * 8;
        let present = layout.pixel_offset(20, 80)
            .map(|offset| {
                // SAFETY: Layout validated a full aligned in-range pixel.
                unsafe { fb.address().cast::<u8>().add(offset).cast::<u32>().read_volatile() == white }
            }).unwrap_or(false);
        if pixels != expected || !present {
            serial::write_line("WOLFOS_FB_CONSOLE_FAILED bad_first_cell");
            halt_forever();
        }
        serial::write_fmt(format_args!(
            "WOLFOS_FB_CONSOLE_OK cols={} rows={} pixels={} cursor={:?}\n",
            console_cols, console_rows, pixels, console.cursor(),
        ));
    } else {
        serial::write_line("WOLFOS_FB_CONSOLE_SKIPPED small_framebuffer");
    }

    #[cfg(feature = "framebuffer-console-smoke")]
    {
        let Some(mut probe) = framebuffer_console::TextConsole::new(layout, 20, 80, 8, 2) else {
            serial::write_line("WOLFOS_FB_CONSOLE_SCROLL_FAILED bad_geometry");
            halt_forever();
        };
        // At two rows, A must scroll out: B moves to first row, C to second.
        probe.write("A\nB\nC");
        if probe.scroll_count() != 1
            || probe.cell(0, 0) != Some(b'B')
            || probe.cell(0, 1) != Some(b'C')
        {
            serial::write_line("WOLFOS_FB_CONSOLE_SCROLL_FAILED bad_text_cells");
            halt_forever();
        }
        probe.render(white, 0, |offset, color| {
            // SAFETY: checked complete 8x2 cells within mapped framebuffer.
            unsafe { fb.address().cast::<u8>().add(offset).cast::<u32>().write_volatile(color); }
        });
        let check = |x, y| {
            layout.pixel_offset(x, y).map(|offset| {
                // SAFETY: Layout validated the aligned 32bpp pixel read.
                unsafe { fb.address().cast::<u8>().add(offset).cast::<u32>().read_volatile() }
            })
        };
        if check(20, 80) != Some(white)
            || check(20, 88) != Some(0)
            || check(21, 88) != Some(white)
        {
            serial::write_line("WOLFOS_FB_CONSOLE_SCROLL_FAILED bad_pixel_readback");
            halt_forever();
        }
        serial::write_line("WOLFOS_FB_CONSOLE_SCROLL_OK rows=2 scrolls=1 pixels=verified");
    }

    // The bootloader has supplied a validated RGB framebuffer. This is
    // a safe early display fallback, NOT a vendor GPU driver or acceleration.
    let display_plan = display_driver_policy::early_boot_plan(true);
    serial::write_fmt(format_args!(
        "WOLFOS_DISPLAY_BOOT_POLICY backend={} native_accel={} driver_loaded={}\n",
        display_plan.backend.label(),
        u8::from(display_plan.native_acceleration),
        u8::from(display_plan.native_driver_loaded),
    ));
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
    // These tests schedule hundreds of throwaway kernel contexts. Keep
    // running them under every mandatory smoke flavor, never on a normal
    // interactive boot path where no user requested a stress workload.
    #[cfg(feature = "smoke-exit")]
    {
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
    #[cfg(not(feature = "smoke-exit"))]
    serial::write_line("WOLFOS_BOOT_SELFTESTS_SKIPPED mode=non_smoke");
    serial::write_line("WOLFOS_BOOT_OK");

    // Experimental interactive BSP-only COM1 diagnostics, separate from all
    // hardware smoke flavors and deliberately without disk or user processes.
    #[cfg(feature = "ps2-graphics-demo")]
    ps2_graphics_demo::run(layout, fb.address().cast::<u8>(), white, pci_summary);

    #[cfg(feature = "serial-shell")]
    serial_shell::run(pci_summary);

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
