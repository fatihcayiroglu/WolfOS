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
else ifeq ($(FLAVOR),normal)
FEATURES :=
else
$(error FLAVOR must be normal or smoke)
endif

.PHONY: all iso kernel run run-graphics run-uefi smoke exception-smoke paging-fault-smoke topology-smoke timer-smoke apic-timer-smoke apic-calibration-smoke apic-preempt-smoke ap-ipi-smoke ap-local-timer-smoke ap-smp-preempt-smoke ap-remote-work-smoke ap-handoff-smoke check clean test doctor
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

test:
	python3 -m unittest discover -s tests -v
	mkdir -p $(OUT)
	rustc --edition=2024 --test kernel/src/pmm_layout.rs -o $(OUT)/pmm_layout_tests
	rustc --edition=2024 --test kernel/src/acpi_layout.rs -o $(OUT)/acpi_layout_tests
	$(OUT)/acpi_layout_tests
	rustc --edition=2024 --test kernel/src/acpi_tables.rs -o $(OUT)/acpi_tables_tests
	$(OUT)/acpi_tables_tests
	$(OUT)/pmm_layout_tests
	rustc --edition=2024 --test kernel/src/lapic_layout.rs -o $(OUT)/lapic_layout_tests
	$(OUT)/lapic_layout_tests
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
	rustc --edition=2024 --test kernel/src/task_handoff.rs -o $(OUT)/task_handoff_tests
	$(OUT)/task_handoff_tests
	rustc --edition=2024 --test kernel/src/irq_frame_observation.rs -o $(OUT)/irq_frame_observation_tests
	$(OUT)/irq_frame_observation_tests
	rustc --edition=2024 --test kernel/src/kernel_trap_frame.rs -o $(OUT)/kernel_trap_frame_tests
	$(OUT)/kernel_trap_frame_tests
	rustc --edition=2024 --test kernel/src/preempt_depth.rs -o $(OUT)/preempt_depth_tests
	$(OUT)/preempt_depth_tests
	rustc --edition=2024 --test kernel/src/fx_state.rs -o $(OUT)/fx_state_tests
	$(OUT)/fx_state_tests
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
