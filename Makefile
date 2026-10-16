# WolfOS P0: builds VM images only. NEVER writes a physical disk.
.DEFAULT_GOAL := iso
SHELL := /bin/bash
FLAVOR ?= normal
OUT := out
TARGET := x86_64-unknown-none
LIMINE_REPO := https://codeberg.org/Limine/Limine.git
LIMINE_BRANCH := v10.x-binary

ifeq ($(FLAVOR),smoke)
FEATURES := --features smoke-exit
else ifeq ($(FLAVOR),exception)
FEATURES := --features exception-smoke
else ifeq ($(FLAVOR),paging-fault)
FEATURES := --features paging-fault-smoke
else ifeq ($(FLAVOR),timer)
FEATURES := --features timer-smoke
else ifeq ($(FLAVOR),apic-timer)
FEATURES := --features apic-timer-smoke
else ifeq ($(FLAVOR),apic-calibration)
FEATURES := --features apic-calibration-smoke
else ifeq ($(FLAVOR),apic-preempt)
FEATURES := --features apic-preempt-smoke
else ifeq ($(FLAVOR),ap-ipi)
FEATURES := --features ap-ipi-smoke
else ifeq ($(FLAVOR),ap-local-timer)
FEATURES := --features ap-local-timer-smoke
else ifeq ($(FLAVOR),ap-smp-preempt)
FEATURES := --features ap-smp-preempt-smoke
else ifeq ($(FLAVOR),ap-remote-work)
FEATURES := --features ap-remote-work-smoke
else ifeq ($(FLAVOR),ap-handoff)
FEATURES := --features ap-handoff-smoke
else ifeq ($(FLAVOR),ap-stack-migrate)
FEATURES := --features ap-stack-migrate-smoke
else ifeq ($(FLAVOR),ap-irq-migrate)
FEATURES := --features ap-irq-migrate-smoke
else ifeq ($(FLAVOR),ap-runqueue)
FEATURES := --features ap-runqueue-smoke
else ifeq ($(FLAVOR),elf64-preflight)
FEATURES := --features elf64-preflight-smoke
else ifeq ($(FLAVOR),user-vm-shadow)
FEATURES := --features user-vm-shadow-smoke
else ifeq ($(FLAVOR),user-ring-prep)
FEATURES := --features user-ring-prep-smoke
else ifeq ($(FLAVOR),user-ring3)
FEATURES := --features user-ring3-smoke
else ifeq ($(FLAVOR),user-ring3-isolation)
FEATURES := --features user-ring3-isolation-smoke
else ifeq ($(FLAVOR),user-syscall)
FEATURES := --features user-syscall-smoke
else ifeq ($(FLAVOR),user-elf-run)
FEATURES := --features user-elf-run-smoke
else ifeq ($(FLAVOR),user-process)
FEATURES := --features user-process-smoke
else ifeq ($(FLAVOR),user-ramfs)
FEATURES := --features user-ramfs-smoke
else ifeq ($(FLAVOR),user-vfs)
FEATURES := --features user-vfs-smoke
else ifeq ($(FLAVOR),p2-ring3-timer-preempt)
FEATURES := --features p2-ring3-timer-preempt-smoke
else ifeq ($(FLAVOR),p2-ring3-timer-nonyield)
FEATURES := --features p2-ring3-timer-nonyield-smoke
else ifeq ($(FLAVOR),p3-ring3-four-elf-preflight)
FEATURES := --features p3-ring3-four-elf-preflight-smoke
else ifeq ($(FLAVOR),p3-ring3-four-live)
FEATURES := --features p3-ring3-four-elf-live-smoke
else ifeq ($(FLAVOR),p2-ring3-timer-observe)
FEATURES := --features p2-ring3-timer-observe-smoke
else ifeq ($(FLAVOR),p2-ring3-irq-ready)
FEATURES := --features p2-ring3-irq-ready-smoke
else ifeq ($(FLAVOR),p2-ring3-yield)
FEATURES := --features p2-ring3-yield-smoke
else ifeq ($(FLAVOR),p2-handoff-preflight)
FEATURES := --features p2-handoff-preflight-smoke
else ifeq ($(FLAVOR),user-fx)
FEATURES := --features user-fx-smoke
else ifeq ($(FLAVOR),high-half-stack-arena)
FEATURES := --features high-half-stack-arena-smoke
else ifeq ($(FLAVOR),high-half-stack-arena-lower-fault)
FEATURES := --features high-half-stack-arena-lower-fault-smoke
else ifeq ($(FLAVOR),high-half-stack-arena-upper-fault)
FEATURES := --features high-half-stack-arena-upper-fault-smoke
else ifeq ($(FLAVOR),kernel-stack-guard)
FEATURES := --features kernel-stack-guard-smoke
else ifeq ($(FLAVOR),kernel-stack-guard-fault)
FEATURES := --features kernel-stack-guard-fault-smoke
else ifeq ($(FLAVOR),kernel-stack-guard-upper-fault)
FEATURES := --features kernel-stack-guard-upper-fault-smoke
else ifeq ($(FLAVOR),kernel-stack-lease)
FEATURES := --features kernel-stack-lease-smoke
else ifeq ($(FLAVOR),user-context)
FEATURES := --features user-context-smoke
else ifeq ($(FLAVOR),process-table)
FEATURES := --features process-table-smoke
else ifeq ($(FLAVOR),user-file-io)
FEATURES := --features user-file-io-smoke
else ifeq ($(FLAVOR),user-copy)
FEATURES := --features user-copy-smoke
else ifeq ($(FLAVOR),normal)
FEATURES :=
else
$(error FLAVOR must be normal or smoke)
endif

.PHONY: all iso kernel run run-graphics run-uefi smoke exception-smoke paging-fault-smoke topology-smoke timer-smoke apic-timer-smoke apic-calibration-smoke apic-preempt-smoke ap-ipi-smoke ap-local-timer-smoke ap-smp-preempt-smoke ap-remote-work-smoke ap-handoff-smoke ap-stack-migrate-smoke ap-irq-migrate-smoke ap-runqueue-smoke elf64-preflight-smoke user-vm-shadow-smoke user-ring-prep-smoke user-ring3-smoke user-ring3-isolation-smoke user-syscall-smoke user-elf-run-smoke user-process-smoke user-ramfs-smoke user-vfs-smoke user-copy-smoke user-file-io-smoke process-table-smoke user-context-smoke kernel-stack-lease-smoke kernel-stack-guard-smoke kernel-stack-guard-fault-smoke kernel-stack-guard-upper-fault-smoke high-half-stack-arena-smoke high-half-stack-arena-lower-fault-smoke high-half-stack-arena-upper-fault-smoke user-fx-smoke p2-handoff-preflight-smoke p2-ring3-yield-smoke p2-ring3-irq-ready-smoke p2-ring3-timer-observe-smoke p2-ring3-timer-preempt-smoke p2-ring3-timer-nonyield-smoke p3-ring3-four-elf-preflight-smoke p3-ring3-four-live-smoke check clean test doctor
all: iso

limine/limine:
	git clone --depth=1 --branch=$(LIMINE_BRANCH) $(LIMINE_REPO) limine
	$(MAKE) -C limine

kernel:
	cargo build --release --target $(TARGET) $(FEATURES)
	mkdir -p $(OUT)
	cp target/$(TARGET)/release/wolfos-kernel $(OUT)/wolfos-kernel-$(FLAVOR)

iso: limine/limine kernel
	mkdir -p $(OUT)
	rm -rf $(OUT)/iso-root-$(FLAVOR)
	mkdir -p $(OUT)/iso-root-$(FLAVOR)/boot/limine $(OUT)/iso-root-$(FLAVOR)/EFI/BOOT
	cp $(OUT)/wolfos-kernel-$(FLAVOR) $(OUT)/iso-root-$(FLAVOR)/boot/wolfos-kernel
	cp boot/limine.conf $(OUT)/iso-root-$(FLAVOR)/boot/limine/limine.conf
	cp limine/limine-bios.sys limine/limine-bios-cd.bin limine/limine-uefi-cd.bin $(OUT)/iso-root-$(FLAVOR)/boot/limine/
	cp limine/BOOTX64.EFI $(OUT)/iso-root-$(FLAVOR)/EFI/BOOT/
	xorriso -as mkisofs -b boot/limine/limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image --protective-msdos-label -o $(OUT)/wolfos-$(FLAVOR).iso $(OUT)/iso-root-$(FLAVOR)
	./limine/limine bios-install $(OUT)/wolfos-$(FLAVOR).iso

run: iso
	qemu-system-x86_64 -M q35 -m 512M -cdrom $(OUT)/wolfos-normal.iso -boot d -serial stdio -display none -no-reboot

run-graphics: iso
	qemu-system-x86_64 -M q35 -m 512M -cdrom $(OUT)/wolfos-normal.iso -boot d -serial stdio -display default -no-reboot

OVMF_CODE ?= /usr/share/OVMF/OVMF_CODE.fd
run-uefi: iso
	@test -f "$(OVMF_CODE)" || (echo 'Set OVMF_CODE=/path/to/OVMF_CODE.fd'; exit 2)
	qemu-system-x86_64 -M q35 -m 512M -drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) -cdrom $(OUT)/wolfos-normal.iso -serial stdio -display none -no-reboot

smoke:
	$(MAKE) iso FLAVOR=smoke
	python3 scripts/smoke.py $(OUT)/wolfos-smoke.iso

exception-smoke:
	$(MAKE) iso FLAVOR=exception
	python3 scripts/exception_smoke.py $(OUT)/wolfos-exception.iso

paging-fault-smoke:
	$(MAKE) iso FLAVOR=paging-fault
	python3 scripts/paging_fault_smoke.py $(OUT)/wolfos-paging-fault.iso

topology-smoke:
	$(MAKE) iso FLAVOR=smoke
	python3 scripts/topology_smoke.py $(OUT)/wolfos-smoke.iso

timer-smoke:
	$(MAKE) iso FLAVOR=timer
	python3 scripts/timer_smoke.py $(OUT)/wolfos-timer.iso

apic-timer-smoke:
	$(MAKE) iso FLAVOR=apic-timer
	python3 scripts/apic_timer_smoke.py $(OUT)/wolfos-apic-timer.iso

apic-calibration-smoke:
	$(MAKE) iso FLAVOR=apic-calibration
	python3 scripts/apic_timer_smoke.py $(OUT)/wolfos-apic-calibration.iso --calibrated

apic-preempt-smoke:
	$(MAKE) iso FLAVOR=apic-preempt
	python3 scripts/apic_timer_smoke.py $(OUT)/wolfos-apic-preempt.iso --preemptive

ap-ipi-smoke:
	$(MAKE) iso FLAVOR=ap-ipi
	python3 scripts/ap_ipi_smoke.py $(OUT)/wolfos-ap-ipi.iso

ap-local-timer-smoke:
	$(MAKE) iso FLAVOR=ap-local-timer
	python3 scripts/ap_local_timer_smoke.py $(OUT)/wolfos-ap-local-timer.iso

ap-smp-preempt-smoke:
	$(MAKE) iso FLAVOR=ap-smp-preempt
	python3 scripts/ap_smp_preempt_smoke.py $(OUT)/wolfos-ap-smp-preempt.iso

ap-remote-work-smoke:
	$(MAKE) iso FLAVOR=ap-remote-work
	python3 scripts/ap_remote_work_smoke.py $(OUT)/wolfos-ap-remote-work.iso

ap-handoff-smoke:
	$(MAKE) iso FLAVOR=ap-handoff
	python3 scripts/ap_handoff_smoke.py $(OUT)/wolfos-ap-handoff.iso

ap-stack-migrate-smoke:
	$(MAKE) iso FLAVOR=ap-stack-migrate
	python3 scripts/ap_stack_migrate_smoke.py $(OUT)/wolfos-ap-stack-migrate.iso

ap-irq-migrate-smoke:
	$(MAKE) iso FLAVOR=ap-irq-migrate
	python3 scripts/ap_irq_migrate_smoke.py $(OUT)/wolfos-ap-irq-migrate.iso

ap-runqueue-smoke:
	$(MAKE) iso FLAVOR=ap-runqueue
	python3 scripts/ap_runqueue_smoke.py $(OUT)/wolfos-ap-runqueue.iso

elf64-preflight-smoke:
	$(MAKE) iso FLAVOR=elf64-preflight
	python3 scripts/elf64_preflight_smoke.py $(OUT)/wolfos-elf64-preflight.iso

user-vm-shadow-smoke:
	$(MAKE) iso FLAVOR=user-vm-shadow
	python3 scripts/user_vm_shadow_smoke.py $(OUT)/wolfos-user-vm-shadow.iso

user-ring-prep-smoke:
	$(MAKE) iso FLAVOR=user-ring-prep
	python3 scripts/user_ring_prep_smoke.py $(OUT)/wolfos-user-ring-prep.iso

user-ring3-smoke:
	$(MAKE) iso FLAVOR=user-ring3
	python3 scripts/user_ring3_smoke.py $(OUT)/wolfos-user-ring3.iso

user-ring3-isolation-smoke:
	$(MAKE) iso FLAVOR=user-ring3-isolation
	python3 scripts/user_ring3_isolation_smoke.py $(OUT)/wolfos-user-ring3-isolation.iso

user-syscall-smoke:
	$(MAKE) iso FLAVOR=user-syscall
	python3 scripts/user_syscall_smoke.py $(OUT)/wolfos-user-syscall.iso

user-elf-run-smoke:
	$(MAKE) iso FLAVOR=user-elf-run
	python3 scripts/user_elf_run_smoke.py $(OUT)/wolfos-user-elf-run.iso

user-process-smoke:
	$(MAKE) iso FLAVOR=user-process
	python3 scripts/user_process_smoke.py $(OUT)/wolfos-user-process.iso

user-ramfs-smoke:
	$(MAKE) iso FLAVOR=user-ramfs
	python3 scripts/user_ramfs_smoke.py $(OUT)/wolfos-user-ramfs.iso

user-vfs-smoke:
	$(MAKE) iso FLAVOR=user-vfs
	python3 scripts/user_vfs_smoke.py $(OUT)/wolfos-user-vfs.iso

user-copy-smoke:
	$(MAKE) iso FLAVOR=user-copy
	python3 scripts/user_copy_smoke.py $(OUT)/wolfos-user-copy.iso

user-file-io-smoke:
	$(MAKE) iso FLAVOR=user-file-io
	python3 scripts/user_file_io_smoke.py $(OUT)/wolfos-user-file-io.iso

process-table-smoke:
	$(MAKE) iso FLAVOR=process-table
	python3 scripts/process_table_smoke.py $(OUT)/wolfos-process-table.iso

user-context-smoke:
	$(MAKE) iso FLAVOR=user-context
	python3 scripts/user_context_smoke.py $(OUT)/wolfos-user-context.iso

kernel-stack-lease-smoke:
	$(MAKE) iso FLAVOR=kernel-stack-lease
	python3 scripts/kernel_stack_lease_smoke.py $(OUT)/wolfos-kernel-stack-lease.iso

kernel-stack-guard-smoke:
	$(MAKE) iso FLAVOR=kernel-stack-guard
	python3 scripts/kernel_stack_guard_smoke.py $(OUT)/wolfos-kernel-stack-guard.iso map

kernel-stack-guard-fault-smoke:
	$(MAKE) iso FLAVOR=kernel-stack-guard-fault
	python3 scripts/kernel_stack_guard_smoke.py $(OUT)/wolfos-kernel-stack-guard-fault.iso lower

kernel-stack-guard-upper-fault-smoke:
	$(MAKE) iso FLAVOR=kernel-stack-guard-upper-fault
	python3 scripts/kernel_stack_guard_smoke.py $(OUT)/wolfos-kernel-stack-guard-upper-fault.iso upper

high-half-stack-arena-smoke:
	$(MAKE) iso FLAVOR=high-half-stack-arena
	python3 scripts/high_half_stack_arena_smoke.py $(OUT)/wolfos-high-half-stack-arena.iso map

high-half-stack-arena-lower-fault-smoke:
	$(MAKE) iso FLAVOR=high-half-stack-arena-lower-fault
	python3 scripts/high_half_stack_arena_smoke.py $(OUT)/wolfos-high-half-stack-arena-lower-fault.iso lower

high-half-stack-arena-upper-fault-smoke:
	$(MAKE) iso FLAVOR=high-half-stack-arena-upper-fault
	python3 scripts/high_half_stack_arena_smoke.py $(OUT)/wolfos-high-half-stack-arena-upper-fault.iso upper

user-fx-smoke:
	$(MAKE) iso FLAVOR=user-fx
	python3 scripts/user_fx_smoke.py $(OUT)/wolfos-user-fx.iso

p2-handoff-preflight-smoke:
	$(MAKE) iso FLAVOR=p2-handoff-preflight
	python3 scripts/handoff_preflight_smoke.py $(OUT)/wolfos-p2-handoff-preflight.iso

p2-ring3-yield-smoke:
	$(MAKE) iso FLAVOR=p2-ring3-yield
	python3 scripts/user_yield_switch_smoke.py $(OUT)/wolfos-p2-ring3-yield.iso

p2-ring3-irq-ready-smoke:
	$(MAKE) iso FLAVOR=p2-ring3-irq-ready
	python3 scripts/user_yield_switch_smoke.py $(OUT)/wolfos-p2-ring3-irq-ready.iso --irq-ready

p2-ring3-timer-observe-smoke:
	$(MAKE) iso FLAVOR=p2-ring3-timer-observe
	python3 scripts/user_yield_switch_smoke.py $(OUT)/wolfos-p2-ring3-timer-observe.iso --timer-observe

p2-ring3-timer-preempt-smoke:
	$(MAKE) iso FLAVOR=p2-ring3-timer-preempt
	python3 scripts/user_yield_switch_smoke.py $(OUT)/wolfos-p2-ring3-timer-preempt.iso --timer-preempt

p2-ring3-timer-nonyield-smoke:
	$(MAKE) iso FLAVOR=p2-ring3-timer-nonyield
	python3 scripts/user_timer_nonyield_smoke.py $(OUT)/wolfos-p2-ring3-timer-nonyield.iso

p3-ring3-four-elf-preflight-smoke:
	$(MAKE) iso FLAVOR=p3-ring3-four-elf-preflight
	python3 scripts/user_timer_nonyield_smoke.py $(OUT)/wolfos-p3-ring3-four-elf-preflight.iso --four-elf-preflight

test:
	python3 -m unittest discover -s tests -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_user_timer_nonyield_exit_evidence.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_ap_smp_preempt_evidence.py' -v
	mkdir -p $(OUT)
	rustc --edition=2024 --test kernel/src/ap_preempt_progress_budget.rs -o $(OUT)/ap_preempt_progress_budget_tests
	$(OUT)/ap_preempt_progress_budget_tests
	rustc --edition=2024 --test kernel/src/pmm_layout.rs -o $(OUT)/pmm_layout_tests
	rustc --edition=2024 --test kernel/src/acpi_layout.rs -o $(OUT)/acpi_layout_tests
	$(OUT)/acpi_layout_tests
	rustc --edition=2024 --test kernel/src/acpi_tables.rs -o $(OUT)/acpi_tables_tests
	$(OUT)/acpi_tables_tests
	$(OUT)/pmm_layout_tests
	rustc --edition=2024 --test kernel/src/lapic_layout.rs -o $(OUT)/lapic_layout_tests
	$(OUT)/lapic_layout_tests
	rustc --edition=2024 --test kernel/src/user_apic_mmio_shadow.rs -o $(OUT)/user_apic_mmio_shadow_tests
	$(OUT)/user_apic_mmio_shadow_tests
	rustc --edition=2024 --test kernel/src/lapic_mmio_layout.rs -o $(OUT)/lapic_mmio_layout_tests
	$(OUT)/lapic_mmio_layout_tests
	rustc --edition=2024 --test kernel/src/lapic_timer_layout.rs -o $(OUT)/lapic_timer_layout_tests
	$(OUT)/lapic_timer_layout_tests
	rustc --edition=2024 --test kernel/src/lapic_timer_calibration.rs -o $(OUT)/lapic_timer_calibration_tests
	$(OUT)/lapic_timer_calibration_tests
	rustc --edition=2024 --test kernel/src/lapic_timer_plan.rs -o $(OUT)/lapic_timer_plan_tests
	$(OUT)/lapic_timer_plan_tests
	rustc --edition=2024 --test kernel/src/lapic_irq_layout.rs -o $(OUT)/lapic_irq_layout_tests
	$(OUT)/lapic_irq_layout_tests
	rustc --edition=2024 --test kernel/src/ipi_layout.rs -o $(OUT)/ipi_layout_tests
	$(OUT)/ipi_layout_tests
	rustc --edition=2024 --test kernel/src/remote_runqueue.rs -o $(OUT)/remote_runqueue_tests
	$(OUT)/remote_runqueue_tests
	rustc --edition=2024 --test kernel/src/percpu_work_queue.rs -o $(OUT)/percpu_work_queue_tests
	$(OUT)/percpu_work_queue_tests
	rustc --edition=2024 --test kernel/src/ap_work_placement.rs -o $(OUT)/ap_work_placement_tests
	$(OUT)/ap_work_placement_tests
	rustc --edition=2024 --test tests/ap_streaming_dispatch.rs -o $(OUT)/ap_streaming_dispatch_tests
	$(OUT)/ap_streaming_dispatch_tests
	rustc --edition=2024 --test kernel/src/ap_handoff_validation.rs -o $(OUT)/ap_handoff_validation_tests
	$(OUT)/ap_handoff_validation_tests
	rustc --edition=2024 --test kernel/src/task_handoff.rs -o $(OUT)/task_handoff_tests
	$(OUT)/task_handoff_tests
	rustc --edition=2024 --test kernel/src/migrating_stack_contract.rs -o $(OUT)/migrating_stack_contract_tests
	$(OUT)/migrating_stack_contract_tests
	rustc --edition=2024 --test kernel/src/irq_frame_observation.rs -o $(OUT)/irq_frame_observation_tests
	$(OUT)/irq_frame_observation_tests
	rustc --edition=2024 --test kernel/src/kernel_trap_frame.rs -o $(OUT)/kernel_trap_frame_tests
	$(OUT)/kernel_trap_frame_tests
	# Host Rust tests use a REAL standalone independently linked ELF64 file.
	as --64 -o $(OUT)/wolfos-user-hello.o user/hello.S
	ld -m elf_x86_64 -nostdlib -static -T user/hello.ld -o $(OUT)/wolfos-user-hello.elf $(OUT)/wolfos-user-hello.o
	rustc --edition=2024 --test tests/elf_user_app.rs -o $(OUT)/elf_user_app_tests
	$(OUT)/elf_user_app_tests
	rustc --edition=2024 --test kernel/src/elf64_preflight.rs -o $(OUT)/elf64_preflight_tests
	$(OUT)/elf64_preflight_tests
	rustc --edition=2024 --test tests/user_vm_layout.rs -o $(OUT)/user_vm_layout_tests
	$(OUT)/user_vm_layout_tests
	rustc --edition=2024 --test kernel/src/kernel_half_shadow.rs -o $(OUT)/kernel_half_shadow_tests
	$(OUT)/kernel_half_shadow_tests
	rustc --edition=2024 --test kernel/src/user_ring_entry.rs -o $(OUT)/user_ring_entry_tests
	$(OUT)/user_ring_entry_tests
	rustc --edition=2024 --test kernel/src/vfs.rs -o $(OUT)/vfs_tests
	$(OUT)/vfs_tests
	rustc --edition=2024 --test kernel/src/ramfs.rs -o $(OUT)/ramfs_tests
	$(OUT)/ramfs_tests
	rustc --edition=2024 --test kernel/src/user_xapic_high.rs -o $(OUT)/user_xapic_high_tests
	$(OUT)/user_xapic_high_tests
	rustc --edition=2024 --test kernel/src/ring3_round_robin.rs -o $(OUT)/ring3_round_robin_tests
	$(OUT)/ring3_round_robin_tests
	rustc --edition=2024 --test kernel/src/ring3_runqueue.rs -o $(OUT)/ring3_runqueue_tests
	$(OUT)/ring3_runqueue_tests
	rustc --edition=2024 --test kernel/src/user_irq_preempt_contract.rs -o $(OUT)/user_irq_preempt_contract_tests
	$(OUT)/user_irq_preempt_contract_tests
	rustc --edition=2024 --test kernel/src/user_fx_bank.rs -o $(OUT)/user_fx_bank_tests
	$(OUT)/user_fx_bank_tests
	rustc --edition=2024 --test kernel/src/high_half_stack_arena.rs -o $(OUT)/high_half_stack_arena_tests
	$(OUT)/high_half_stack_arena_tests
	rustc --edition=2024 --test kernel/src/kernel_stack_guard.rs -o $(OUT)/kernel_stack_guard_tests
	$(OUT)/kernel_stack_guard_tests
	rustc --edition=2024 --test kernel/src/kernel_stack_lease.rs -o $(OUT)/kernel_stack_lease_tests
	$(OUT)/kernel_stack_lease_tests
	rustc --edition=2024 --test kernel/src/user_context_bank.rs -o $(OUT)/user_context_bank_tests
	$(OUT)/user_context_bank_tests
	rustc --edition=2024 --test kernel/src/process_table.rs -o $(OUT)/process_table_tests
	$(OUT)/process_table_tests
	rustc --edition=2024 --test kernel/src/process_lifecycle.rs -o $(OUT)/process_lifecycle_tests
	$(OUT)/process_lifecycle_tests
	rustc --edition=2024 --test kernel/src/user_copy.rs -o $(OUT)/user_copy_tests
	$(OUT)/user_copy_tests
	rustc --edition=2024 --test tests/user_file_io_contract.rs -o $(OUT)/user_file_io_contract_tests
	$(OUT)/user_file_io_contract_tests
	rustc --edition=2024 --test kernel/src/user_syscall_abi.rs -o $(OUT)/user_syscall_abi_tests
	$(OUT)/user_syscall_abi_tests
	rustc --edition=2024 --test tests/elf64_page_image.rs -o $(OUT)/elf64_page_image_tests
	$(OUT)/elf64_page_image_tests
	rustc --edition=2024 --test kernel/src/preempt_depth.rs -o $(OUT)/preempt_depth_tests
	$(OUT)/preempt_depth_tests
	rustc --edition=2024 --test kernel/src/fx_state.rs -o $(OUT)/fx_state_tests
	$(OUT)/fx_state_tests
	rustc --edition=2024 --test kernel/src/fx_bootstrap_image.rs -o $(OUT)/fx_bootstrap_image_tests
	$(OUT)/fx_bootstrap_image_tests
	rustc --edition=2024 --test kernel/src/rr_policy.rs -o $(OUT)/rr_policy_tests
	$(OUT)/rr_policy_tests
	rustc --edition=2024 --test kernel/src/task_slot.rs -o $(OUT)/task_slot_tests
	$(OUT)/task_slot_tests
	rustc --edition=2024 --test kernel/src/scheduler.rs -o $(OUT)/scheduler_tests
	$(OUT)/scheduler_tests
	rustc --edition=2024 --test kernel/src/thread_scheduler.rs -o $(OUT)/thread_scheduler_tests
	$(OUT)/thread_scheduler_tests

check: test
	@echo 'Source/config checks completed; actual QEMU boot is separate.'

doctor:
	@for t in cargo rustc git make xorriso qemu-system-x86_64 python3; do command -v $$t >/dev/null && echo "OK   $$t" || echo "MISS $$t"; done

clean:
	rm -rf out
	cargo clean
