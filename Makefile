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
else ifeq ($(FLAVOR),qemu-stdvga-dispi)
FEATURES := --features qemu-stdvga-dispi-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-pci)
FEATURES := --features qemu-virtio-gpu-pci-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-bars)
FEATURES := --features qemu-virtio-gpu-bars-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-bar-size)
FEATURES := --features qemu-virtio-gpu-bar-size-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-common-mmio)
FEATURES := --features qemu-virtio-gpu-common-mmio-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-device-mmio)
FEATURES := --features qemu-virtio-gpu-device-mmio-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-transport-preflight)
FEATURES := --features qemu-virtio-gpu-transport-preflight-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-bank1-tx)
FEATURES := --features qemu-virtio-gpu-bank1-tx-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-negotiate)
FEATURES := --features qemu-virtio-gpu-negotiate-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-controlq-ro)
FEATURES := --features qemu-virtio-gpu-controlq-ro-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-controlq-pmm)
FEATURES := --features qemu-virtio-gpu-controlq-pmm-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-controlq-tx)
FEATURES := --features qemu-virtio-gpu-controlq-tx-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-notify-ro)
FEATURES := --features qemu-virtio-gpu-notify-ro-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-display-info)
FEATURES := --features qemu-virtio-gpu-display-info-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-edid-live)
FEATURES := --features qemu-virtio-gpu-edid-live-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-resource2d)
FEATURES := --features qemu-virtio-gpu-resource2d-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-attach-backing)
FEATURES := --features qemu-virtio-gpu-attach-backing-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-transfer2d)
FEATURES := --features qemu-virtio-gpu-transfer2d-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-scanout-live)
FEATURES := --features qemu-virtio-gpu-scanout-live-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-scanout-reset)
FEATURES := --features qemu-virtio-gpu-scanout-reset-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-native-rollback)
FEATURES := --features qemu-virtio-gpu-native-rollback-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-desktop-scanout)
FEATURES := --features qemu-virtio-gpu-desktop-scanout-smoke
else ifeq ($(FLAVOR),qemu-virtio-gpu-damage-live)
FEATURES := --features qemu-virtio-gpu-damage-live-smoke
else ifeq ($(FLAVOR),qemu-stdvga-enable-tx)
FEATURES := --features qemu-stdvga-enable-tx-smoke
else ifeq ($(FLAVOR),qemu-stdvga-full-state)
FEATURES := --features qemu-stdvga-full-state-smoke
else ifeq ($(FLAVOR),qemu-stdvga-mode-rollback)
FEATURES := --features qemu-stdvga-mode-rollback-smoke
else ifeq ($(FLAVOR),qemu-stdvga-software-queue)
FEATURES := --features qemu-stdvga-software-queue-smoke
else ifeq ($(FLAVOR),serial-shell)
FEATURES := --features serial-shell
else ifeq ($(FLAVOR),ps2-graphics-overflow)
FEATURES := --features ps2-graphics-overflow-smoke
else ifeq ($(FLAVOR),ps2-graphics-irq)
FEATURES := --features ps2-graphics-irq-smoke
else ifeq ($(FLAVOR),ps2-graphics-edit)
FEATURES := --features ps2-graphics-edit-smoke
else ifeq ($(FLAVOR),ps2-graphics-info)
FEATURES := --features ps2-graphics-info-smoke
else ifeq ($(FLAVOR),ps2-graphics-help)
FEATURES := --features ps2-graphics-help-smoke
else ifeq ($(FLAVOR),ps2-graphics)
FEATURES := --features ps2-graphics-demo
else ifeq ($(FLAVOR),framebuffer-console)
FEATURES := --features framebuffer-console-smoke
else ifeq ($(FLAVOR),exception)
FEATURES := --features exception-smoke
else ifeq ($(FLAVOR),address-space-retirement)
FEATURES := --features address-space-retirement-smoke
else ifeq ($(FLAVOR),smp-address-space-retirement)
FEATURES := --features smp-address-space-retirement-smoke
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
else ifeq ($(FLAVOR),tlb-shootdown-hardware)
FEATURES := --features tlb-shootdown-hardware-smoke
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
else ifeq ($(FLAVOR),user-elf-one-load-run)
FEATURES := --features user-elf-one-load-run-smoke
else ifeq ($(FLAVOR),user-elf-two-pt-run)
FEATURES := --features user-elf-two-pt-run-smoke
else ifeq ($(FLAVOR),user-elf-three-load-run)
FEATURES := --features user-elf-three-load-run-smoke
else ifeq ($(FLAVOR),user-exit-status)
FEATURES := --features user-exit-status-smoke
else ifeq ($(FLAVOR),user-invalid-opcode-retire)
FEATURES := --features user-invalid-opcode-retire-smoke
else ifeq ($(FLAVOR),user-page-fault-retire)
FEATURES := --features user-page-fault-retire-smoke
else ifeq ($(FLAVOR),user-process-fault-recovery)
FEATURES := --features user-process-fault-recovery-smoke
else ifeq ($(FLAVOR),user-process)
FEATURES := --features user-process-smoke
else ifeq ($(FLAVOR),user-ramfs)
FEATURES := --features user-ramfs-smoke
else ifeq ($(FLAVOR),user-vfs)
FEATURES := --features user-vfs-smoke
else ifeq ($(FLAVOR),p3-ring3-event-wait-hardware)
FEATURES := --features p3-ring3-event-wait-hardware-smoke
else ifeq ($(FLAVOR),p3-ring3-irq-event-wake)
FEATURES := --features p3-ring3-irq-event-wake-smoke
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

.PHONY: serial-shell-smoke run-shell tlb-shootdown-hardware-smoke all iso kernel run run-graphics run-uefi smoke exception-smoke paging-fault-smoke topology-smoke timer-smoke apic-timer-smoke apic-calibration-smoke apic-preempt-smoke ap-ipi-smoke ap-local-timer-smoke ap-smp-preempt-smoke ap-remote-work-smoke ap-handoff-smoke ap-stack-migrate-smoke ap-irq-migrate-smoke ap-runqueue-smoke elf64-preflight-smoke user-vm-shadow-smoke user-ring-prep-smoke user-ring3-smoke user-ring3-isolation-smoke user-syscall-smoke user-elf-run-smoke user-elf-one-load-run-smoke user-elf-two-pt-run-smoke user-elf-three-load-run-smoke user-exit-status-smoke user-invalid-opcode-retire-smoke user-page-fault-retire-smoke user-process-fault-recovery-smoke user-process-smoke user-ramfs-smoke user-vfs-smoke user-copy-smoke user-file-io-smoke process-table-smoke user-context-smoke kernel-stack-lease-smoke kernel-stack-guard-smoke kernel-stack-guard-fault-smoke kernel-stack-guard-upper-fault-smoke high-half-stack-arena-smoke high-half-stack-arena-lower-fault-smoke high-half-stack-arena-upper-fault-smoke user-fx-smoke p2-handoff-preflight-smoke p3-ring3-event-wait-hardware-smoke p3-ring3-irq-event-wake-smoke p2-ring3-yield-smoke p2-ring3-irq-ready-smoke p2-ring3-timer-observe-smoke p2-ring3-timer-preempt-smoke p2-ring3-timer-nonyield-smoke p3-ring3-four-elf-preflight-smoke p3-ring3-four-live-smoke check clean test doctor
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

run-shell:
	$(MAKE) iso FLAVOR=serial-shell
	qemu-system-x86_64 -M q35 -m 512M -cdrom $(OUT)/wolfos-serial-shell.iso -boot d -serial stdio -monitor none -display none -no-reboot

serial-shell-smoke:
	$(MAKE) iso FLAVOR=serial-shell
	python3 scripts/serial_shell_smoke.py $(OUT)/wolfos-serial-shell.iso

.PHONY: ps2-graphics-smoke
ps2-graphics-smoke:
	$(MAKE) iso FLAVOR=ps2-graphics
	python3 scripts/ps2_graphics_smoke.py $(OUT)/wolfos-ps2-graphics.iso

.PHONY: ps2-graphics-help-smoke
ps2-graphics-help-smoke:
	$(MAKE) iso FLAVOR=ps2-graphics-help
	python3 scripts/ps2_graphics_smoke.py $(OUT)/wolfos-ps2-graphics-help.iso --help-mode

.PHONY: ps2-graphics-info-smoke
ps2-graphics-info-smoke:
	$(MAKE) iso FLAVOR=ps2-graphics-info
	python3 scripts/ps2_graphics_smoke.py $(OUT)/wolfos-ps2-graphics-info.iso --info-mode mem
	python3 scripts/ps2_graphics_smoke.py $(OUT)/wolfos-ps2-graphics-info.iso --info-mode pci
	python3 scripts/ps2_graphics_smoke.py $(OUT)/wolfos-ps2-graphics-info.iso --info-mode cpu

.PHONY: ps2-graphics-edit-smoke
ps2-graphics-edit-smoke:
	$(MAKE) iso FLAVOR=ps2-graphics-edit
	python3 scripts/ps2_graphics_smoke.py $(OUT)/wolfos-ps2-graphics-edit.iso --edit-mode

.PHONY: ps2-graphics-irq-smoke
ps2-graphics-irq-smoke:
	$(MAKE) iso FLAVOR=ps2-graphics-irq
	python3 scripts/ps2_graphics_smoke.py $(OUT)/wolfos-ps2-graphics-irq.iso --irq-mode

.PHONY: ps2-graphics-overflow-smoke
ps2-graphics-overflow-smoke:
	$(MAKE) iso FLAVOR=ps2-graphics-overflow
	python3 scripts/ps2_graphics_smoke.py $(OUT)/wolfos-ps2-graphics-overflow.iso --overflow-mode

.PHONY: framebuffer-console-smoke
framebuffer-console-smoke:
	$(MAKE) iso FLAVOR=framebuffer-console
	python3 scripts/smoke.py $(OUT)/wolfos-framebuffer-console.iso --console-scroll

run-graphics: iso
	qemu-system-x86_64 -M q35 -m 512M -cdrom $(OUT)/wolfos-normal.iso -boot d -serial stdio -display default -no-reboot

OVMF_CODE ?= /usr/share/OVMF/OVMF_CODE.fd
run-uefi: iso
	@test -f "$(OVMF_CODE)" || (echo 'Set OVMF_CODE=/path/to/OVMF_CODE.fd'; exit 2)
	qemu-system-x86_64 -M q35 -m 512M -drive if=pflash,format=raw,readonly=on,file=$(OVMF_CODE) -cdrom $(OUT)/wolfos-normal.iso -serial stdio -display none -no-reboot

smoke:
	$(MAKE) iso FLAVOR=smoke
	python3 scripts/smoke.py $(OUT)/wolfos-smoke.iso

.PHONY: qemu-virtio-gpu-pci-smoke
qemu-virtio-gpu-pci-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-pci
	python3 scripts/qemu_virtio_gpu_pci_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-pci.iso

.PHONY: qemu-virtio-gpu-bars-smoke
qemu-virtio-gpu-bars-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-bars
	python3 scripts/qemu_virtio_gpu_pci_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-bars.iso --bars

.PHONY: qemu-virtio-gpu-bar-size-smoke
qemu-virtio-gpu-bar-size-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-bar-size
	python3 scripts/qemu_virtio_gpu_pci_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-bar-size.iso --size

.PHONY: qemu-virtio-gpu-common-mmio-smoke
qemu-virtio-gpu-common-mmio-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-common-mmio
	python3 scripts/qemu_virtio_gpu_pci_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-common-mmio.iso --mmio

.PHONY: qemu-virtio-gpu-device-mmio-smoke
qemu-virtio-gpu-device-mmio-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-device-mmio
	python3 scripts/qemu_virtio_gpu_pci_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-device-mmio.iso --device

.PHONY: qemu-virtio-gpu-transport-preflight-smoke
qemu-virtio-gpu-transport-preflight-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-transport-preflight
	python3 scripts/qemu_virtio_gpu_pci_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-transport-preflight.iso --preflight

.PHONY: qemu-virtio-gpu-bank1-tx-smoke
qemu-virtio-gpu-bank1-tx-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-bank1-tx
	python3 scripts/qemu_virtio_gpu_pci_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-bank1-tx.iso --bank1

.PHONY: qemu-virtio-gpu-negotiate-smoke
qemu-virtio-gpu-negotiate-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-negotiate
	python3 scripts/qemu_virtio_gpu_pci_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-negotiate.iso --negotiate

.PHONY: qemu-virtio-gpu-controlq-ro-smoke
qemu-virtio-gpu-controlq-ro-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-controlq-ro
	python3 scripts/qemu_virtio_gpu_pci_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-controlq-ro.iso --controlq-ro

.PHONY: qemu-virtio-gpu-controlq-pmm-smoke
qemu-virtio-gpu-controlq-pmm-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-controlq-pmm
	python3 scripts/qemu_virtio_gpu_pci_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-controlq-pmm.iso --controlq-pmm

.PHONY: qemu-virtio-gpu-controlq-tx-smoke
qemu-virtio-gpu-controlq-tx-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-controlq-tx
	python3 scripts/qemu_virtio_gpu_pci_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-controlq-tx.iso --controlq-tx

.PHONY: qemu-virtio-gpu-notify-ro-smoke
qemu-virtio-gpu-notify-ro-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-notify-ro
	python3 scripts/qemu_virtio_gpu_pci_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-notify-ro.iso --notify-ro

.PHONY: qemu-virtio-gpu-display-info-smoke
qemu-virtio-gpu-display-info-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-display-info
	python3 scripts/qemu_virtio_gpu_pci_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-display-info.iso --display-info

.PHONY: qemu-virtio-gpu-edid-live-smoke
qemu-virtio-gpu-edid-live-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-edid-live
	rustc --edition=2021 --test kernel/src/virtio_gpu_edid_live_contract.rs -o $(OUT)/edid_live_contract_test
	$(OUT)/edid_live_contract_test
	python3 -m unittest discover -s scripts -p test_qemu_virtio_gpu_edid_live_smoke.py
	python3 scripts/qemu_virtio_gpu_edid_live_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-edid-live.iso

.PHONY: qemu-virtio-gpu-resource2d-smoke
qemu-virtio-gpu-resource2d-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-resource2d
	rustc --edition=2024 --test kernel/src/virtio_gpu_resource2d_contract.rs -o $(OUT)/virtio_gpu_resource2d_contract_tests
	$(OUT)/virtio_gpu_resource2d_contract_tests
	python3 -m unittest discover -s scripts -p test_qemu_virtio_gpu_resource2d_smoke.py
	python3 scripts/qemu_virtio_gpu_resource2d_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-resource2d.iso

.PHONY: qemu-virtio-gpu-attach-backing-smoke
qemu-virtio-gpu-attach-backing-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-attach-backing
	rustc --edition=2024 --test kernel/src/virtio_gpu_backing_contract.rs -o $(OUT)/virtio_gpu_backing_contract_tests
	$(OUT)/virtio_gpu_backing_contract_tests
	python3 -m unittest discover -s scripts -p test_qemu_virtio_gpu_attach_backing_smoke.py
	python3 scripts/qemu_virtio_gpu_attach_backing_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-attach-backing.iso

.PHONY: qemu-virtio-gpu-transfer2d-smoke
qemu-virtio-gpu-transfer2d-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-transfer2d
	rustc --edition=2024 --test kernel/src/virtio_gpu_transfer2d_contract.rs -o $(OUT)/virtio_gpu_transfer2d_contract_tests
	$(OUT)/virtio_gpu_transfer2d_contract_tests
	python3 -m unittest discover -s scripts -p test_qemu_virtio_gpu_transfer2d_smoke.py
	python3 scripts/qemu_virtio_gpu_transfer2d_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-transfer2d.iso

.PHONY: qemu-virtio-gpu-scanout-live-smoke
qemu-virtio-gpu-scanout-live-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-scanout-live
	rustc --edition=2024 --test kernel/src/virtio_gpu_scanout_contract.rs -o $(OUT)/virtio_gpu_scanout_contract_tests
	$(OUT)/virtio_gpu_scanout_contract_tests
	python3 -m unittest discover -s scripts -p test_qemu_virtio_gpu_scanout_live_smoke.py
	python3 scripts/qemu_virtio_gpu_scanout_live_smoke.py $(OUT)/wolfos-qemu-virtio-gpu-scanout-live.iso

.PHONY: qemu-virtio-gpu-scanout-reset-smoke
qemu-virtio-gpu-scanout-reset-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-scanout-reset
	python3 -m unittest discover -s scripts -p test_qemu_virtio_gpu_scanout_reset_smoke.py
	python3 scripts/qemu_virtio_gpu_scanout_live_smoke.py --reset-restore $(OUT)/wolfos-qemu-virtio-gpu-scanout-reset.iso

.PHONY: qemu-virtio-gpu-native-rollback-smoke
qemu-virtio-gpu-native-rollback-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-native-rollback
	rustc --edition=2024 --test kernel/src/virtio_gpu_scanout_contract.rs -o $(OUT)/virtio_gpu_native_rollback_contract_tests
	$(OUT)/virtio_gpu_native_rollback_contract_tests
	python3 -m unittest discover -s scripts -p test_qemu_virtio_gpu_native_rollback_smoke.py
	python3 scripts/qemu_virtio_gpu_scanout_live_smoke.py --native-rollback $(OUT)/wolfos-qemu-virtio-gpu-native-rollback.iso

.PHONY: qemu-virtio-gpu-desktop-scanout-smoke
qemu-virtio-gpu-desktop-scanout-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-desktop-scanout
	rustc --edition=2024 --test kernel/src/virtio_gpu_desktop_wire.rs -o $(OUT)/virtio_gpu_desktop_wire_tests
	$(OUT)/virtio_gpu_desktop_wire_tests
	rustc --edition=2024 --test kernel/src/virtio_gpu_damage.rs -o $(OUT)/virtio_gpu_damage_tests
	$(OUT)/virtio_gpu_damage_tests
	python3 -m unittest discover -s scripts -p test_qemu_virtio_gpu_desktop_scanout.py
	python3 scripts/qemu_virtio_gpu_desktop_scanout.py $(OUT)/wolfos-qemu-virtio-gpu-desktop-scanout.iso


.PHONY: qemu-virtio-gpu-damage-live-smoke
qemu-virtio-gpu-damage-live-smoke:
	$(MAKE) iso FLAVOR=qemu-virtio-gpu-damage-live
	rustc --edition=2024 --test kernel/src/virtio_gpu_damage.rs -o $(OUT)/virtio_gpu_damage_tests
	$(OUT)/virtio_gpu_damage_tests
	PYTHONPATH=scripts WOLFOS_DAMAGE_LIVE=1 python3 -m unittest discover -s scripts -p test_qemu_virtio_gpu_damage_live_smoke.py
	WOLFOS_DAMAGE_LIVE=1 python3 scripts/qemu_virtio_gpu_desktop_scanout.py $(OUT)/wolfos-qemu-virtio-gpu-damage-live.iso

.PHONY: qemu-virtio-gpu-desktop-scanout-negative
# The desktop proof must be able to fail. Two independent classes:
#  * a lying host corrupted attestation field must abort the whole proof;
#  * a lying host verdict must be graded, not obeyed: an early "expired" claim
#    is refused outright, and a really elapsed window forces a verified
#    rollback to the previous mode;
#  * a peer that says nothing at all must not strand the guest: the guest ends
#    the window on its own HPET clock and rolls back.
# DESKTOP_ATTEST_FAULTS / DESKTOP_MODE_FAULTS may be narrowed locally.
DESKTOP_ATTEST_FAULTS ?= digest nonce geometry
DESKTOP_MODE_FAULTS ?= mode_early mode_expired mode_silent
qemu-virtio-gpu-desktop-scanout-negative:
	@for fault in $(DESKTOP_ATTEST_FAULTS); do \
	  if WOLFOS_DESKTOP_FAULT=$$fault python3 scripts/qemu_virtio_gpu_desktop_scanout.py \
	       --require-refusal $(OUT)/wolfos-qemu-virtio-gpu-desktop-scanout.iso \
	       > $(OUT)/desktop-$$fault.log 2>&1; then \
	    echo "OK: desktop attestation fault $$fault refused by the guest"; \
	  else \
	    echo "FAIL: desktop attestation fault $$fault was accepted"; exit 1; \
	  fi; \
	done
	@for fault in $(DESKTOP_MODE_FAULTS); do \
	  if WOLFOS_DESKTOP_FAULT=$$fault python3 scripts/qemu_virtio_gpu_desktop_scanout.py \
	       $(OUT)/wolfos-qemu-virtio-gpu-desktop-scanout.iso \
	       > $(OUT)/desktop-$$fault.log 2>&1; then \
	    echo "OK: desktop mode-transaction fault $$fault refused by the guest"; \
	  else \
	    echo "FAIL: desktop mode-transaction fault $$fault was accepted"; exit 1; \
	  fi; \
	done

.PHONY: qemu-virtio-gpu-attestation-negative
# The attestation gate must be able to fail: a host that lies about the digest,
# the nonce or the geometry has to be refused by the guest, loudly.
# ATTEST_FAULTS may be narrowed locally, e.g. ATT... "FAULTS=digest".
ATTEST_FAULTS ?= digest nonce geometry
qemu-virtio-gpu-attestation-negative:
	@for fault in $(ATTEST_FAULTS); do \
	  case "$$fault" in \
	    digest) reason=digest_mismatch ;; \
	    nonce) reason=bad_nonce ;; \
	    geometry) reason=wrong_geometry ;; \
	    *) echo "FAIL: unknown attestation fault $$fault"; exit 1 ;; \
	  esac; \
	  if WOLFOS_ATTEST_FAULT=$$fault python3 scripts/qemu_virtio_gpu_scanout_live_smoke.py \
	       --native-rollback $(OUT)/wolfos-qemu-virtio-gpu-native-rollback.iso \
	       > $(OUT)/attest-$$fault.log 2>&1; then \
	    echo "FAIL: attestation fault $$fault was not refused"; exit 1; \
	  elif ! grep -q "WOLFOS_GPU_ATTEST_FAIL stage=active reason=$$reason " $(OUT)/attest-$$fault.log; then \
	    echo "FAIL: attestation fault $$fault refused without matching kernel evidence"; exit 1; \
	  else \
	    echo "OK: attestation fault $$fault refused by the guest as $$reason"; \
	  fi; \
	done

.PHONY: qemu-stdvga-dispi-smoke
qemu-stdvga-dispi-smoke:
	$(MAKE) iso FLAVOR=qemu-stdvga-dispi
	python3 scripts/qemu_stdvga_dispi_smoke.py $(OUT)/wolfos-qemu-stdvga-dispi.iso

.PHONY: qemu-stdvga-enable-tx-smoke
qemu-stdvga-enable-tx-smoke:
	$(MAKE) iso FLAVOR=qemu-stdvga-enable-tx
	python3 scripts/qemu_vbe_enable_tx_smoke.py $(OUT)/wolfos-qemu-stdvga-enable-tx.iso

.PHONY: qemu-stdvga-full-state-smoke
qemu-stdvga-full-state-smoke:
	$(MAKE) iso FLAVOR=qemu-stdvga-full-state
	python3 scripts/qemu_vbe_full_state_smoke.py $(OUT)/wolfos-qemu-stdvga-full-state.iso

.PHONY: qemu-stdvga-mode-rollback-smoke
qemu-stdvga-mode-rollback-smoke:
	$(MAKE) iso FLAVOR=qemu-stdvga-mode-rollback
	python3 scripts/qemu_vbe_mode_rollback_smoke.py $(OUT)/wolfos-qemu-stdvga-mode-rollback.iso

.PHONY: qemu-stdvga-software-queue-smoke
qemu-stdvga-software-queue-smoke:
	$(MAKE) iso FLAVOR=qemu-stdvga-software-queue
	python3 scripts/qemu_gpu_sw_queue_smoke.py $(OUT)/wolfos-qemu-stdvga-software-queue.iso

.PHONY: address-space-retirement-smoke
address-space-retirement-smoke:
	$(MAKE) iso FLAVOR=address-space-retirement
	python3 scripts/address_space_retirement_smoke.py $(OUT)/wolfos-address-space-retirement.iso

.PHONY: smp-address-space-retirement-smoke
smp-address-space-retirement-smoke:
	$(MAKE) iso FLAVOR=smp-address-space-retirement
	python3 scripts/address_space_retirement_smoke.py $(OUT)/wolfos-smp-address-space-retirement.iso --smp

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

tlb-shootdown-hardware-smoke:
	$(MAKE) iso FLAVOR=tlb-shootdown-hardware
	python3 scripts/tlb_shootdown_hardware_smoke.py $(OUT)/wolfos-tlb-shootdown-hardware.iso

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

user-elf-two-pt-run-smoke:
	$(MAKE) iso FLAVOR=user-elf-two-pt-run
	python3 scripts/user_elf_run_smoke.py $(OUT)/wolfos-user-elf-two-pt-run.iso --two-pt

user-elf-one-load-run-smoke:
	$(MAKE) iso FLAVOR=user-elf-one-load-run
	python3 scripts/user_elf_run_smoke.py $(OUT)/wolfos-user-elf-one-load-run.iso --one-load

user-elf-three-load-run-smoke:
	$(MAKE) iso FLAVOR=user-elf-three-load-run
	python3 scripts/user_elf_run_smoke.py $(OUT)/wolfos-user-elf-three-load-run.iso --three-load

user-exit-status-smoke:
	$(MAKE) iso FLAVOR=user-exit-status
	python3 scripts/user_elf_run_smoke.py $(OUT)/wolfos-user-exit-status.iso --exit-status

user-invalid-opcode-retire-smoke:
	$(MAKE) iso FLAVOR=user-invalid-opcode-retire
	python3 scripts/user_elf_run_smoke.py $(OUT)/wolfos-user-invalid-opcode-retire.iso --user-ud-fault

user-page-fault-retire-smoke:
	$(MAKE) iso FLAVOR=user-page-fault-retire
	python3 scripts/user_elf_run_smoke.py $(OUT)/wolfos-user-page-fault-retire.iso --user-pf-fault

user-process-fault-recovery-smoke:
	$(MAKE) iso FLAVOR=user-process-fault-recovery
	python3 scripts/user_process_fault_recovery_smoke.py $(OUT)/wolfos-user-process-fault-recovery.iso

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

p3-ring3-event-wait-hardware-smoke:
	$(MAKE) iso FLAVOR=p3-ring3-event-wait-hardware
	python3 scripts/user_event_wait_smoke.py $(OUT)/wolfos-p3-ring3-event-wait-hardware.iso

p3-ring3-irq-event-wake-smoke:
	$(MAKE) iso FLAVOR=p3-ring3-irq-event-wake
	python3 scripts/user_event_irq_wake_smoke.py $(OUT)/wolfos-p3-ring3-irq-event-wake.iso

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

p3-ring3-four-live-smoke:
	$(MAKE) iso FLAVOR=p3-ring3-four-live
	python3 scripts/user_timer_four_live_smoke.py $(OUT)/wolfos-p3-ring3-four-live.iso

test:
	mkdir -p $(OUT)
	rustc --edition=2024 --test kernel/src/virtio_gpu_pci_caps.rs -o $(OUT)/virtio_gpu_pci_caps_tests
	$(OUT)/virtio_gpu_pci_caps_tests
	rustc --edition=2024 --test kernel/src/virtio_gpu_pci_bars.rs -o $(OUT)/virtio_gpu_pci_bars_tests
	$(OUT)/virtio_gpu_pci_bars_tests
	rustc --edition=2024 --test kernel/src/virtio_gpu_bar_size_contract.rs -o $(OUT)/virtio_gpu_bar_size_contract_tests
	$(OUT)/virtio_gpu_bar_size_contract_tests
	rustc --edition=2024 --test kernel/src/virtio_gpu_mmio_contract.rs -o $(OUT)/virtio_gpu_mmio_contract_tests
	$(OUT)/virtio_gpu_mmio_contract_tests
	rustc --edition=2024 --test kernel/src/virtio_gpu_device_mmio_contract.rs -o $(OUT)/virtio_gpu_device_mmio_contract_tests
	$(OUT)/virtio_gpu_device_mmio_contract_tests
	rustc --edition=2024 --test kernel/src/virtio_gpu_transport_preflight_contract.rs -o $(OUT)/virtio_gpu_transport_preflight_contract_tests
	$(OUT)/virtio_gpu_transport_preflight_contract_tests
	rustc --edition=2024 --test kernel/src/virtio_gpu_bank1_tx_contract.rs -o $(OUT)/virtio_gpu_bank1_tx_contract_tests
	$(OUT)/virtio_gpu_bank1_tx_contract_tests
	rustc --edition=2024 --test kernel/src/virtio_gpu_feature_neg_contract.rs -o $(OUT)/virtio_gpu_feature_neg_contract_tests
	$(OUT)/virtio_gpu_feature_neg_contract_tests
	rustc --edition=2024 --test kernel/src/virtio_gpu_controlq_ro_contract.rs -o $(OUT)/virtio_gpu_controlq_ro_contract_tests
	$(OUT)/virtio_gpu_controlq_ro_contract_tests
	rustc --edition=2024 --test kernel/src/virtio_gpu_controlq_tx_contract.rs -o $(OUT)/virtio_gpu_controlq_tx_contract_tests
	$(OUT)/virtio_gpu_controlq_tx_contract_tests
	rustc --edition=2024 --test kernel/src/virtio_gpu_notify_contract.rs -o $(OUT)/virtio_gpu_notify_contract_tests
	$(OUT)/virtio_gpu_notify_contract_tests
	rustc --edition=2024 --test kernel/src/virtio_gpu_display_info_contract.rs -o $(OUT)/virtio_gpu_display_info_contract_tests
	$(OUT)/virtio_gpu_display_info_contract_tests
	rustc --edition=2024 --test kernel/src/display_driver_policy.rs -o $(OUT)/display_driver_policy_tests
	$(OUT)/display_driver_policy_tests
	rustc --edition=2024 --test kernel/src/display_edid_host.rs -o $(OUT)/display_edid_policy_tests
	$(OUT)/display_edid_policy_tests
	rustc --edition=2024 --test kernel/src/gpu_sw_queue_contract.rs -o $(OUT)/gpu_sw_queue_contract_tests
	$(OUT)/gpu_sw_queue_contract_tests
	rustc --edition=2024 --test kernel/src/qemu_dispi_contract.rs -o $(OUT)/qemu_dispi_contract_tests
	$(OUT)/qemu_dispi_contract_tests
	rustc --edition=2024 --test kernel/src/qemu_display_attestation_host.rs -o $(OUT)/qemu_display_attestation_tests
	$(OUT)/qemu_display_attestation_tests
	rustc --edition=2024 --test kernel/src/ps2_scancode_queue.rs -o $(OUT)/ps2_scancode_queue_tests
	$(OUT)/ps2_scancode_queue_tests
	rustc --edition=2024 --test kernel/src/ps2_keyboard.rs -o $(OUT)/ps2_keyboard_tests
	$(OUT)/ps2_keyboard_tests
	rustc --edition=2024 --test kernel/src/framebuffer_text.rs -o $(OUT)/framebuffer_text_tests
	$(OUT)/framebuffer_text_tests
	rustc --edition=2024 --test tests/framebuffer_console.rs -o $(OUT)/framebuffer_console_tests
	$(OUT)/framebuffer_console_tests
	rustc --edition=2024 --test tests/graphical_line_editor.rs -o $(OUT)/graphical_line_editor_tests
	$(OUT)/graphical_line_editor_tests
	rustc --edition=2024 --test tests/graphical_diagnostics.rs -o $(OUT)/graphical_diagnostics_tests
	$(OUT)/graphical_diagnostics_tests
	rustc --edition=2024 --test tests/serial_shell.rs -o $(OUT)/serial_shell_tests
	$(OUT)/serial_shell_tests
	python3 -m unittest discover -s tests -v
	rustc --edition=2024 --test kernel/src/virtio_gpu_desktop_wire.rs -o $(OUT)/virtio_gpu_desktop_wire_tests
	$(OUT)/virtio_gpu_desktop_wire_tests
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_qemu_virtio_gpu_desktop_scanout.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_display_driver_evidence.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_qemu_virtio_gpu_pci_smoke.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_qemu_stdvga_dispi_smoke.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_qemu_vbe_enable_tx_smoke.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_qemu_vbe_full_state_smoke.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_qemu_vbe_mode_rollback_smoke.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_qemu_gpu_sw_queue_smoke.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_user_timer_nonyield_exit_evidence.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_user_timer_four_live_evidence.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_user_event_wait_evidence.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_user_event_irq_wake_evidence.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_user_ring_prep_evidence.py' -v
	PYTHONPATH=scripts python3 -m unittest discover -s scripts -p 'test_ap_smp_preempt_evidence.py' -v
	mkdir -p $(OUT)
	rustc --edition=2024 --test kernel/src/ap_preempt_progress_budget.rs -o $(OUT)/ap_preempt_progress_budget_tests
	$(OUT)/ap_preempt_progress_budget_tests
	rustc --edition=2024 --test kernel/src/pmm_layout.rs -o $(OUT)/pmm_layout_tests
	rustc --edition=2024 --test tests/pmm_frame_batch.rs -o $(OUT)/pmm_frame_batch_tests
	$(OUT)/pmm_frame_batch_tests
	rustc --edition=2024 --test kernel/src/address_space_retirement.rs -o $(OUT)/address_space_retirement_tests
	$(OUT)/address_space_retirement_tests
	rustc --edition=2024 --test kernel/src/tlb_shootdown.rs -o $(OUT)/tlb_shootdown_tests
	$(OUT)/tlb_shootdown_tests
	rustc --edition=2024 --test kernel/src/saved_context_retirement.rs -o $(OUT)/saved_context_retirement_tests
	$(OUT)/saved_context_retirement_tests
	rustc --edition=2024 --test tests/active_address_space.rs -o $(OUT)/active_address_space_tests
	$(OUT)/active_address_space_tests
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
	rustc --edition=2024 --test tests/user_elf_launch_layout.rs -o $(OUT)/user_elf_launch_layout_tests
	$(OUT)/user_elf_launch_layout_tests
	rustc --edition=2024 --test tests/user_elf_page_tables.rs -o $(OUT)/user_elf_page_tables_tests
	$(OUT)/user_elf_page_tables_tests
	rustc --edition=2024 --target x86_64-unknown-none --crate-type lib --crate-name wolfos_launch_contract tests/elf_launch_transaction_no_std.rs -o $(OUT)/libwolfos_launch_contract.rlib
	rustc --edition=2024 --test tests/elf_launch_transaction.rs -o $(OUT)/elf_launch_transaction_tests
	$(OUT)/elf_launch_transaction_tests
	rustc --edition=2024 --test tests/user_vm_layout.rs -o $(OUT)/user_vm_layout_tests
	$(OUT)/user_vm_layout_tests
	rustc --edition=2024 --test tests/user_vm_two_pt.rs -o $(OUT)/user_vm_two_pt_tests
	$(OUT)/user_vm_two_pt_tests
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
	rustc --edition=2024 --test kernel/src/ring3_event_wait_gate.rs -o $(OUT)/ring3_event_wait_gate_tests
	$(OUT)/ring3_event_wait_gate_tests
	rustc --edition=2024 --test kernel/src/ring3_irq_eoi_ledger.rs -o $(OUT)/ring3_irq_eoi_ledger_tests
	$(OUT)/ring3_irq_eoi_ledger_tests
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
	rustc --edition=2024 --test kernel/src/app_permissions.rs -o $(OUT)/app_permissions_tests
	$(OUT)/app_permissions_tests
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
