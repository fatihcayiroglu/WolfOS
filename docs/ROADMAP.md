# WolfOS roadmap and acceptance gates

P0: Rust no_std x86-64 kernel; QEMU serial, memory-map and framebuffer smoke checks.

P1: IDT/GDT, exceptions, physical memory allocator, paging, CPUID and PCI/ACPI read-only discovery.

P2: Ring 3 user mode, syscalls, ELF loader, init, scheduler and RAM-backed file system.

P3+: graphics, audio, networking, tested driver packages, secure updates with rollback.

Windows and Steam applications are aspirational milestones: Linux ABI / POSIX, Win32/NT API compatibility, Vulkan graphics, DRM and anti-cheat restrictions. No universal compatibility promise.

No milestone can be marked complete without reproducible build and run evidence.
