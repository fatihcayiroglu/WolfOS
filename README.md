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
- `make run-shell`: experimental **interactive COM1 kernel diagnostic console** in QEMU (type `help`, `about`, `cpu`, `pci`, `mem`, `clear`, or `halt`; no physical-disk writes). This is not a Ring3 user shell or graphical desktop. The `pci` command reports the **cached boot-time** device counts (display/network/storage) and does not rescan PCI configuration ports or install drivers.
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

The bounded single-process ELF execution path shares an ELF-derived one/two-PT
builder across its independently linked 6/7/8/9-frame QEMU cases. It derives
the exact table budget from LOAD leaves and the separate NX stack, validates
the complete physical lease, and populates/audits every private table entry
before kernel grafting and CR3 activation. Fixture-specific guest checks and
the three-LOAD-page limit remain; this is not yet an arbitrary ELF launcher.

Payload staging also uses the same frame-bound recipe across all four live
layouts. The two-PT QEMU controls first reject a deliberately wrong last-LOAD
frame without changing any payload/table byte or PMM ownership, then execute
the valid ELF using the retained frames and verify exact cleanup. Independent
ELF-byte, PTE and HHDM admission remains mandatory before user execution.

The counted preparation coordinator now drives the real bounded BSP Ring3
path: exact reservation, payload/table preparation, final complete byte/PTE
admission, then consuming transfer to one active frame owner before CR3 is
loaded. Every launch first proves rejection and exact PMM rollback using real
disconnected pages. EXIT and authenticated #UD/#PF close CPU admission, reject
retirement while the private CR3 is active, restore boot CR3 with PCID off,
revoke PID/return references and reclaim only through the retired owner.
PID2 preparation uses a separate checked supervisor stack after terminal reap;
it does not recursively consume the 16-KiB TSS exception stack. These paths
remain fixed ELF fixtures, BSP-only and IF=0. General multicore process
retirement, resumable-context cancellation and arbitrary ELF loading remain
unfinished; the separate four-vCPU retirement/TLB controls do not prove them.

The verified scope remains an experimental Rust-owned kernel: boot execution, frame allocation, CPU tables/exceptions, paging, ACPI topology, saved-context kernel threads, **four-process** Ring 3 ELF execution, address-space isolation, and timer-origin preemptive handoff in isolated QEMU scenarios. A genuine hardware IRQ → blocked WAIT wake → saved IRET resume **has been demonstrated for two fixed ELF processes**; generalized dynamic process creation, device-event registration, scheduling, and arbitrary workload-safe Block → Wake → Resume integration remain incomplete. Host-only queue, process/PMM lease and context-bank policy regressions are not substitutes for physical CPU/IRQ proof. The reference-clock calibration is a QEMU test variant, not a validated general scheduling or wall-clock source.

The no-heap PID lifecycle ledger preserves EXIT status and exact counted leases.
Real QEMU fixtures cover CPL3 EXIT(42), authenticated #UD/#PF retirement and
faulted PID1 followed by healthy PID2. A general parent wait/reap interface,
dynamic crash recovery and concurrent process retirement remain unfinished.

The opt-in `make ps2-graphics-smoke` exercises a real emulated 8042 PS/2 keyboard in QEMU, injecting A/B/C/Backspace/D/Enter through the QEMU monitor and verifying both decoded key events and the ABD text pixels. The independent `make ps2-graphics-overflow-smoke` test deliberately reduces the isolated IRQ1 queue to eight bytes, then injects real QEMU PS/2 keyboard events while the foreground consumer is paused. It demands at least nine real IRQ1 deliveries, matching PIC EOIs, nonzero discarded scan codes, a permanently poisoned queue, and an unchanged graphical prompt without any decoded or authorized commands. This is a controlled fail-closed stress test, **not** general keyboard recovery; normal 64-byte queue behavior is unchanged.

The isolated `make ps2-graphics-irq-smoke` test uses **real QEMU PS/2 IRQ1 hardware delivery** through a remapped legacy PIC (IRQ1 alone unmasked), a bounded atomic 64-byte raw-scancode queue, and a foreground-only decoder/renderer. The IRQ1 handler drains the i8042 output buffer and sends PIC EOI even on a rejected byte; queue saturation or a keyboard parity/timeout error poisons the input session instead of silently losing release events; AUX controller bytes remain ignored. The mandatory host tests cover corrupted Shift-break handling, but hardware error-bit injection is not yet a QEMU proof. QEMU HMP injects the edited `help` command and checks seven decoded keyboard events, matching IRQ/EOI counts, zero queue drops, and actual framebuffer pixels. This is an isolated BSP-only proof, **not** a production multi-core, hotplug, USB HID, or full keyboard driver. Normal boot and the polling keyboard flavors remain unchanged.

The opt-in `make ps2-graphics-edit-smoke` test proves in one real emulated keyboard session that a line longer than 12 characters is rejected without executing a truncated command, then a new valid `help` command works and draws verified framebuffer pixels. The graphical command editor remains a BSP-only experiment, not a Ring3 or IRQ-driven terminal. The `make ps2-graphics-info-smoke` gate runs three separate QEMU boots with emulated PS/2 keyboard input for `mem` (live read-only PMM free MiB), `pci` (immutable boot-cached display/network/storage counts), and `cpu` (real CPUID vendor/family/model). All three require graphical text and framebuffer pixel evidence; the CPU screen values must equal independent early-boot CPUID logs, and PCI is never rescanned during interaction. The same help smoke also sends `helx`, Backspace, `p`, Enter, uses the same exact command classifier as COM1, and verifies the graphical `HELP ABOUT` response through real framebuffer pixel readback. This remains a bounded, opt-in graphical diagnostic prototype: `help`/`about` are display-only; hardware-affecting COM1 commands are explicitly unavailable here. It does not implement a userspace terminal, IRQ-driven keyboard, general shell, or desktop. This mode polls the BSP only; it is **not** a generalized interrupt-driven keyboard or USB HID driver and does not accept privileged shell commands. The normal boot path is unchanged.

Early framebuffer output now includes a bounded static graphical text-console preview with uppercase glyphs, cursor position, line wrapping and scrollable RAM text cells. A separate QEMU smoke test proves a two-row scroll by framebuffer pixel readback. No keyboard or userspace process is attached to this preview. The existing early banner uses an allocation-free Rust 5×7 uppercase `WOLFOS`/`RUST KERNEL` banner using validated pitch and clipped coordinates. Real QEMU smoke checks a volatile framebuffer pixel readback; **this is not a desktop, window manager, GPU driver or interactive graphical terminal**.

WolfOS has an opt-in interactive **kernel diagnostic console over QEMU COM1**, not a Ring3 user shell or terminal application. It still does **not** have a consumer-ready shell, filesystem, production drivers, network, GPU acceleration, a general-purpose preemptive scheduler, or support for Windows programs, Steam and GTA V. Its Ring 3/ELF support and VFS/RamFS experiments are currently bounded development milestones, not mature general-purpose services. Windows compatibility is a long-term goal, not a present feature. Physical-machine driver safety and cross-platform application compatibility require separate engineering and test gates.

See [the roadmap](docs/ROADMAP.md), [security guidance](docs/SECURITY.md) and [Turkish getting-started guide](docs/BASLANGIC_TR.md).

Copyright 2026 WolfOS Contributors. WolfOS project code is MIT-licensed. Limine and the external Rust crates have their own licenses.
