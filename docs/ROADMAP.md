# WolfOS roadmap and acceptance gates

P0: Rust no_std x86-64 kernel; QEMU serial, memory-map and framebuffer smoke checks.

P1: CPUID (merged); physical frame allocator (merged), scalable HHDM-backed bitmap (merged); GDT/IDT, CPU exceptions (merged), paging map/unmap and #PF (merged), PCI read-only discovery (merged), ACPI RSDP read-only validation (merged); RSDT/XSDT checksum validation and MADT CPU count (merged), Limine AP Rust handshake (merged); AP-local GDT/TSS/IST/IDT, WolfOS-owned AP stacks and verified SMP CPU work (merged); cooperative exactly-once kernel job queue (merged); per-CPU task queues and Ready/Running/Blocked/Finished lifecycle (merged); BSP-only cooperative assembly context-switch proof (merged); three stack-backed TCB execution contexts and yield/block/wake test (merged); generic indexed 16-TCB context batch (merged); 256 BSP-owned stack-backed TCB proof with strict 4 MiB stack bank (merged); real per-CPU context switching with private kernel stacks (merged).

P2: Ring 3 user mode, syscalls, ELF loader, init, scheduler and RAM-backed file system.

P3+: graphics, audio, networking, tested driver packages, secure updates with rollback.

Windows and Steam applications are aspirational milestones: Linux ABI / POSIX, Win32/NT API compatibility, Vulkan graphics, DRM and anti-cheat restrictions. No universal compatibility promise.

No milestone can be marked complete without reproducible build and run evidence.

P1 topology validation: isolated QEMU MADT tests with 1 and 4 virtual CPUs; APs now execute verified Rust work on dedicated stacks; task preemption, timers, IPIs and full SMP scheduling still pending.

P1 timer milestone: isolated single-BSP PIT/8259 IRQ0 delivery and EOI acceptance in QEMU (merged); tick-gated safe-point context dispatch on two kernel stacks (under review). APIC timer, clocksource calibration, genuine interrupt-driven preemption and IRQ-safe scheduler remain planned.
