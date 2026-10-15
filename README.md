# WolfOS — Independent Rust x86-64 Kernel

WolfOS is an original experimental x86-64 OS kernel written in Rust (`no_std`). It is **not Linux**. Limine is currently used as the bootloader, not as the WolfOS kernel.

**Current status (October 2026):** WolfOS boots in QEMU and has reproducible tests for frame allocation, paging, CPU exceptions, PCI/ACPI discovery, and kernel saved-context threads. Two independently linked ELF64 programs execute at Ring 3 with distinct CR3 roots, guarded high-half TSS.RSP0 kernel stacks, and per-process FXSAVE64 state. An isolated single-BSP hardware test genuinely preempts each Ring 3 program once using the local xAPIC timer, switches to the other process through a saved GPR/IRET frame, and later completes eight cooperative yields and two exits. The post-merge `main` P0 CI is green for PR #95. **This is a bounded two-task acceptance test, not a production scheduler**: repeated all-timer-driven round-robin, AP-local scheduling, validated clocksource, general ELF/process semantics, and user SMP migration remain future work. Not ready to install on physical hardware.

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

The verified scope remains an experimental Rust-owned kernel: boot execution, frame allocator, CPU tables/exceptions, paging, ACPI topology, kernel saved-context switches, basic Ring 3 ELF execution, per-process address-space isolation, real user privilege transitions, cooperative cross-process yields and **two genuine timer-driven involuntary inter-process switches** in an isolated BSP QEMU test. Its xAPIC experiment has bounded switching, no production runqueue, and does not prove sustained non-yielding workloads. The reference-clock calibration runs only in a QEMU test variant; the measured rate is not a validated general scheduling clocksource or accurate wall-clock source.

WolfOS does **not** yet have a shell, a consumer-ready filesystem, production drivers, network, GPU acceleration, a general-purpose preemptive scheduler, or support for Windows programs, Steam and GTA V. Its Ring 3/ELF support and VFS/RamFS experiments are currently bounded development milestones, not mature general-purpose services. Windows compatibility is a long-term goal, not a present feature. Physical-machine driver safety and cross-platform application compatibility require separate engineering and test gates.

See [the roadmap](docs/ROADMAP.md), [security guidance](docs/SECURITY.md) and [Turkish getting-started guide](docs/BASLANGIC_TR.md).

Copyright 2026 WolfOS Contributors. WolfOS project code is MIT-licensed. Limine and the external Rust crates have their own licenses.
