# WolfOS roadmap and acceptance gates

P0: Rust no_std x86-64 kernel; QEMU serial, memory-map and framebuffer smoke checks.

P1: CPUID (merged); physical frame allocator (merged), scalable HHDM-backed bitmap (merged); GDT/IDT, CPU exceptions (merged), paging map/unmap and #PF (merged), PCI read-only discovery (merged), ACPI RSDP read-only validation (merged); RSDT/XSDT checksum validation and MADT CPU count (merged), Limine AP Rust handshake (merged); AP-local GDT/TSS/IST/IDT, WolfOS-owned AP stacks and verified SMP CPU work (merged); cooperative exactly-once kernel job queue (merged); per-CPU task queues and Ready/Running/Blocked/Finished lifecycle (merged); BSP-only cooperative assembly context-switch proof (merged); three stack-backed TCB execution contexts and yield/block/wake test (merged); generic indexed 16-TCB context batch (merged); 256 BSP-owned stack-backed TCB proof with strict 4 MiB stack bank (merged); real per-CPU context switching with private kernel stacks (merged).

P2: Ring 3 user mode, syscalls, ELF loader, init, scheduler and RAM-backed file system.

P3+: graphics, audio, networking, tested driver packages, secure updates with rollback.

Windows and Steam applications are aspirational milestones: Linux ABI / POSIX, Win32/NT API compatibility, Vulkan graphics, DRM and anti-cheat restrictions. No universal compatibility promise.

No milestone can be marked complete without reproducible build and run evidence.

P1 topology validation (merged): isolated QEMU MADT tests with 1 and 4 virtual CPUs. APs execute verified Rust work on dedicated stacks, with independent GDT/TSS/IST/IDT and real per-CPU cooperative kernel context switching. APs park with interrupts disabled after the boot proof. No preemptive or fully dynamic SMP scheduler yet.

P1 legacy timer (merged): isolated single-BSP PIT/8259 IRQ0 delivery, PIC EOI and tick-gated **safe-point/cooperative** dispatch between kernel contexts in QEMU. This is not asynchronous task preemption.

P1 local APIC discovery (merged): per-CPU read-only IA32_APIC_BASE MSR and CPUID APIC-ID validation for BSP/APs; temporary, read-only uncached BSP xAPIC MMIO mapping for ID/version observation. Normal kernel boot still does not enable APIC timer IRQs.

P1 xAPIC timer hardware proof (merged, PRs #26–#31): pure LVT/divisor/vector validation, masked timer programming plan and EOI/SVR validation, plus *isolated QEMU smoke-mode* writable MMIO, genuine periodic BSP APIC timer interrupts and matching EOIs. The IRQ path passed 1- and 4-vCPU QEMU tests; no AP timer delivery is claimed. Test tears down the temporary mapping, masks LVT and leaves CPU interrupts disabled.

P1 reference calibration proof (merged, PR #32): isolated BSP PIT channel 2 terminal-count polling (~20 ms) measures the decrement of a masked xAPIC one-shot timer, then uses checked integer arithmetic to estimate a 100 Hz periodic initial count. Full QEMU acceptance verifies both calibration results and actual IRQ/EOI delivery with 1 and 4 vCPUs (Actions #213, 14 October 2026). PIT2 does not establish general-purpose clock precision, drift bounds or cross-hardware portability.

P1 xAPIC tick-gated cooperative context proof (under review): reuse the two independent stack-backed Rust execution contexts from the PIT smoke test; each APIC timer epoch permits one voluntary yield on the BSP. Both calibrated and uncalibrated xAPIC timer QEMU smoke flavors require six strictly increasing IRQ epochs, six dispatches and twelve RSP switches on 1 and 4 vCPUs. The IRQ handler only publishes an atomic counter and EOI; **this is NOT IRQ-frame preemption**.

P1 **still pending**: monotonic production clocksource and validated calibration across hardware, safe interrupt-frame capture/restoration, IRQ-safe preemptive scheduler with real involuntary context switches, timer lifecycle/drivers, AP-local timer/EOI handling and IPIs, coordinated full SMP scheduling, real-device regression testing. These are acceptance-gated separately.

P2 remains unimplemented: ring-3 address-space isolation, syscalls, ELF user loader/init, process lifecycle, RAM filesystem and protection checks. Later Windows/Steam compatibility work must not be confused with current kernel smoke proofs.
