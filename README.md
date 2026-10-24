# WolfOS — Independent Rust x86-64 Kernel

WolfOS is an original experimental x86-64 OS kernel written in Rust (`no_std`). It is **not Linux**. Limine is currently used as the bootloader, not as the WolfOS kernel.

**Current status (October 2026):** WolfOS boots in QEMU and has reproducible tests for physical-frame allocation, paging, CPU exceptions, PCI/ACPI discovery, and saved-context kernel threads. In a **bounded BSP-only QEMU acceptance scenario**, four independently linked ELF64 user programs run at Ring 3 with separate CR3 address spaces, guarded high-half TSS.RSP0 kernel stacks, per-process FXSAVE64 state, genuine xAPIC timer-driven switching without voluntary yields, four verified EXITs, and exact reclamation of 50 PMM frames. A **separate fixed two-user QEMU scenario** verifies a real xAPIC interrupt waking a blocked Ring 3 WAIT, with physical EOI, original saved IRET/GPR/FX context restoration, and zero PMM leakage. These are isolated 1/4-vCPU QEMU hardware tests (user scheduling still occurs on the BSP), **not** a general process scheduler, generalized wait/device integration, or a consumer-ready OS. WolfOS is not ready to install on physical hardware.

## Requirements

Linux or WSL2 with internet; rustup (nightly + `x86_64-unknown-none` target), Git, GNU Make, xorriso, qemu-system-x86_64, Python 3.

On Ubuntu: `sudo apt install build-essential git make xorriso qemu-system-x86 ovmf python3`

## Build and tests

- `make doctor`: list missing tools
- `make test`: Python source/config tests plus Rust host unit tests
- `make smoke`: boot and serial assertions in QEMU
- `make run-shell`: experimental **interactive COM1 kernel diagnostic console** in QEMU (type `help`, `about`, `mem`, `clear`, or `halt`; no physical-disk writes). This is not a Ring3 user shell or graphical desktop.
- `make serial-shell-smoke`: automated QEMU serial-input roundtrip and command/output markers
- `make run` and `make run-shell` skip disposable allocator/paging/context stress checks; all `smoke-exit` CI flavors still run and verify them. Core hardware detection and initialization remain mandatory.
- `make address-space-retirement-smoke`: BSP-only activation/retirement gate with real private CR3 loads, including a reservation racing retirement (1/4-vCPU QEMU; no Ring3 or SMP shootdown)
- `make smp-address-space-retirement-smoke`: explicit staged-to-active frame ownership, active Drop retention and four real CPU CR3 departures, with the last AP held active before exact root-frame cleanup (CPL0 only; no IPI shootdown)
- `make exception-smoke`: CPU exception dispatch
- `make paging-fault-smoke`: mapping/unmapping and fault dispatch
- `make topology-smoke`: ACPI/MADT plus 1/4-vCPU SMP and saved-context checks
- `make timer-smoke`: isolated PIT IRQ0 and tick-gated *cooperative* context dispatch
- `make apic-timer-smoke`: real BSP xAPIC periodic IRQ delivery and matching EOI checks in QEMU with 1 and 4 vCPUs
- `make apic-calibration-smoke`: separate PIT-channel-2-referenced xAPIC calibration and real IRQ delivery checks in QEMU with 1 and 4 vCPUs
- `make p3-ring3-four-live-smoke`: four independently executing no-yield Ring 3 ELFs, real xAPIC fairness, guarded context and exact PMM cleanup (QEMU)
- `make p3-ring3-irq-event-wake-smoke`: real xAPIC IRQ/EOI waking a blocked Ring 3 WAIT and resuming its saved IRET frame (QEMU, 1/4 vCPUs)
- `make run-graphics`: QEMU boot with framebuffer window
- `make run-uefi`: optional OVMF boot

All smoke targets build CD ISO files under `out/`. They do not write physical disks. Example serial markers include `WOLFOS_LIMINE_OK`, `WOLFOS_SMP_APS_OK`, `WOLFOS_APIC_TIMER_IRQ_OK`, `WOLFOS_APIC_CALIBRATION_OK` and `WOLFOS_BOOT_OK`.

## What is and is not implemented

The verified scope remains an experimental Rust-owned kernel: boot execution, frame allocation, CPU tables/exceptions, paging, ACPI topology, saved-context kernel threads, **four-process** Ring 3 ELF execution, address-space isolation, and timer-origin preemptive handoff in isolated QEMU scenarios. A genuine hardware IRQ → blocked WAIT wake → saved IRET resume **has been demonstrated for two fixed ELF processes**; generalized dynamic process creation, device-event registration, scheduling, and arbitrary workload-safe Block → Wake → Resume integration remain incomplete. Host-only queue, process/PMM lease and context-bank policy regressions are not substitutes for physical CPU/IRQ proof. The reference-clock calibration is a QEMU test variant, not a validated general scheduling or wall-clock source.

WolfOS has an opt-in interactive **kernel diagnostic console over QEMU COM1**, not a Ring3 user shell or terminal application. It still does **not** have a consumer-ready shell, filesystem, production drivers, network, GPU acceleration, a general-purpose preemptive scheduler, or support for Windows programs, Steam and GTA V. Its Ring 3/ELF support and VFS/RamFS experiments are currently bounded development milestones, not mature general-purpose services. Windows compatibility is a long-term goal, not a present feature. Physical-machine driver safety and cross-platform application compatibility require separate engineering and test gates.

See [the roadmap](docs/ROADMAP.md), [security guidance](docs/SECURITY.md) and [Turkish getting-started guide](docs/BASLANGIC_TR.md).

Copyright 2026 WolfOS Contributors. WolfOS project code is MIT-licensed. Limine and the external Rust crates have their own licenses.
