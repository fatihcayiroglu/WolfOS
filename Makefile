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
else ifeq ($(FLAVOR),normal)
FEATURES :=
else
$(error FLAVOR must be normal or smoke)
endif

.PHONY: all iso kernel run run-graphics run-uefi smoke exception-smoke paging-fault-smoke topology-smoke timer-smoke check clean test doctor
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

test:
	python3 -m unittest discover -s tests -v
	mkdir -p $(OUT)
	rustc --edition=2024 --test kernel/src/pmm_layout.rs -o $(OUT)/pmm_layout_tests
	rustc --edition=2024 --test kernel/src/acpi_layout.rs -o $(OUT)/acpi_layout_tests
	$(OUT)/acpi_layout_tests
	rustc --edition=2024 --test kernel/src/acpi_tables.rs -o $(OUT)/acpi_tables_tests
	$(OUT)/acpi_tables_tests
	$(OUT)/pmm_layout_tests
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
