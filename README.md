# WolfOS — Independent Rust x86-64 Kernel

WolfOS is an original experimental x86-64 OS kernel written in Rust (`no_std`). It is **not Linux**. Limine is currently used as the bootloader, not as the WolfOS kernel.

**Current status (October 2026):** Boot, frame allocation, paging, CPU exceptions, PCI/ACPI discovery and cooperative per-CPU saved-context kernel threads have reproducible QEMU tests. Legacy PIT IRQ0 and genuine BSP-local xAPIC timer IRQ delivery with EOI have both been verified. PIT channel 2 can be used in an *isolated smoke test* to estimate the effective local APIC timer rate. **No kernel task preemption, system clocksource or AP-local timer scheduling yet.** Not ready to install on physical hardware.

## Requirements

Linux or WSL2 with internet; rustup (nightly + `x86_64-unknown-none` target), Git, GNU Make, xorriso, qemu-system-x86_64, Python 3.

On Ubuntu: `sudo apt install build-essential git make xorriso qemu-system-x86 ovmf python3`

## Build and tests

- `make doctor`: list missing tools
- `make test`: Python source/config tests plus Rust host unit tests
- `make smoke`: boot and serial assertions in QEMU
- `make exception-smoke`: CPU exception dispatch
- `make paging-fault-smoke`: mapping/unmapping and fault dispatch
- `make topology-smoke`: ACPI/MADT plus 1/4-vCPU SMP and saved-context checks
- `make timer-smoke`: isolated PIT IRQ0 and tick-gated *cooperative* context dispatch
- `make apic-timer-smoke`: real BSP xAPIC periodic IRQ delivery and matching EOI checks in QEMU with 1 and 4 vCPUs
- `make apic-calibration-smoke`: separate PIT-channel-2-referenced xAPIC calibration and real IRQ delivery checks in QEMU with 1 and 4 vCPUs
- `make run-graphics`: QEMU boot with framebuffer window
- `make run-uefi`: optional OVMF boot

All smoke targets build CD ISO files under `out/`. They do not write physical disks. Example serial markers include `WOLFOS_LIMINE_OK`, `WOLFOS_SMP_APS_OK`, `WOLFOS_APIC_TIMER_IRQ_OK`, `WOLFOS_APIC_CALIBRATION_OK` and `WOLFOS_BOOT_OK`.

## What is and is not implemented

The currently verified scope is an early kernel: Rust-owned boot execution, frame allocator, CPU tables/exceptions, basic paging, ACPI topology, kernel-only cooperative scheduling/context switches and BSP timer interrupt smoke tests. The reference-clock calibration runs only in a QEMU test variant; measured rate is not a validated clocksource for general scheduling or accurate wall-clock time.

WolfOS does **not** yet have Ring 3 user processes, ELF process loading, a shell, a usable filesystem, production drivers, network, GPU acceleration, a preemptive scheduler, or support for Windows programs, Steam and GTA V. Windows compatibility is a long-term goal, not a present feature. Physical-machine driver safety and cross-platform application compatibility require separate engineering and test gates.

See [the roadmap](docs/ROADMAP.md), [security guidance](docs/SECURITY.md) and [Turkish getting-started guide](docs/BASLANGIC_TR.md).

Copyright 2026 WolfOS Contributors. WolfOS project code is MIT-licensed. Limine and the external Rust crates have their own licenses.
