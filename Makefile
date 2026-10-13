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
else ifeq ($(FLAVOR),normal)
FEATURES :=
else
$(error FLAVOR must be normal or smoke)
endif

.PHONY: all iso kernel run run-graphics run-uefi smoke check clean test doctor
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

test:
	python3 -m unittest discover -s tests -v

check: test
	@echo 'Source/config checks completed; actual QEMU boot is separate.'

doctor:
	@for t in cargo rustc git make xorriso qemu-system-x86_64 python3; do command -v $$t >/dev/null && echo "OK   $$t" || echo "MISS $$t"; done

clean:
	rm -rf out
	cargo clean
