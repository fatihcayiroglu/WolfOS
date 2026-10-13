# WolfOS roadmap and acceptance gates

P0: Rust no_std x86-64 kernel; QEMU serial, memory-map and framebuffer smoke checks.

P1: CPUID (merged); physical frame allocator (merged), scalable HHDM-backed bitmap (under review); GDT/IDT, CPU exceptions (under review), paging map/unmap and #PF (under review), PCI read-only discovery (merged), ACPI RSDP read-only validation (under review); RSDT/XSDT/MADT parsing (planned).

P2: Ring 3 user mode, syscalls, ELF loader, init, scheduler and RAM-backed file system.

P3+: graphics, audio, networking, tested driver packages, secure updates with rollback.

Windows and Steam applications are aspirational milestones: Linux ABI / POSIX, Win32/NT API compatibility, Vulkan graphics, DRM and anti-cheat restrictions. No universal compatibility promise.

No milestone can be marked complete without reproducible build and run evidence.
