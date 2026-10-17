# WolfOS — Independent Rust x86-64 Kernel

WolfOS is an original experimental x86-64 OS kernel written in Rust (`no_std`). It is **not Linux**. Limine is currently used as the bootloader, not as the WolfOS kernel.

**Current status (October 2026):** WolfOS boots in QEMU and has reproducible tests for frame allocation, paging, CPU exceptions, PCI/ACPI discovery, and kernel saved-context threads. Two independently linked ELF64 programs execute at Ring 3 with distinct CR3 roots, guarded high-half TSS.RSP0 kernel stacks, and per-process FXSAVE64 state. Dedicated QEMU tests exercise genuine timer-origin Ring 3 scheduling, including bounded multi-process workloads and saved user-context validation. Recent changes add authenticated saved-trap refresh and block/wake bookkeeping, but do not yet establish a fully integrated, production-ready Block → Wake → Resume hardware path. These are controlled QEMU acceptance scenarios, not a general-purpose scheduler or consumer OS. Not ready to install on physical hardware.

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

The verified scope remains an experimental Rust-owned kernel: boot execution, frame allocation, CPU tables/exceptions, paging, ACPI topology, saved-context kernel threads, bounded Ring 3 ELF execution, address-space isolation and hardware-timer-driven scheduling experiments in QEMU. Recent work strengthens bounded multi-process scheduling metadata and authenticated saved Ring 3 context updates; an end-to-end hardware Block → Wake → Resume path is not yet demonstrated. The reference-clock calibration is a QEMU test variant, not a validated general scheduling or wall-clock source.

WolfOS does **not** yet have a shell, a consumer-ready filesystem, production drivers, network, GPU acceleration, a general-purpose preemptive scheduler, or support for Windows programs, Steam and GTA V. Its Ring 3/ELF support and VFS/RamFS experiments are currently bounded development milestones, not mature general-purpose services. Windows compatibility is a long-term goal, not a present feature. Physical-machine driver safety and cross-platform application compatibility require separate engineering and test gates.

See [the roadmap](docs/ROADMAP.md), [security guidance](docs/SECURITY.md) and [Turkish getting-started guide](docs/BASLANGIC_TR.md).

Copyright 2026 WolfOS Contributors. WolfOS project code is MIT-licensed. Limine and the external Rust crates have their own licenses.
