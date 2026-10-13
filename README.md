# WolfOS P0 — Independent Rust Kernel

WolfOS is an original experimental x86-64 OS kernel written in Rust (no_std). It is **not Linux**. Limine is used only as an initial bootloader.

**Status:** source prepared; the QEMU boot must pass CI before claiming it works. Not for installation on real hardware.

## Requirements

Linux or WSL2 with internet; rustup (nightly target x86_64-unknown-none), Git, GNU Make, xorriso, qemu-system-x86_64, Python 3.

On Ubuntu: sudo apt install build-essential git make xorriso qemu-system-x86 ovmf python3

## Commands

- make doctor: list missing tools
- make test: offline Python source/config tests only
- make smoke: builds boot ISO and verifies QEMU serial markers plus exit code 33
- make run-graphics: boot in QEMU with framebuffer window
- make run-uefi: optional OVMF test

Boot markers: WOLFOS_LIMINE_OK, WOLFOS_MEMMAP_OK, WOLFOS_FRAMEBUFFER_OK, WOLFOS_BOOT_OK.

P0 shows colored screen bands and serial logs. It does NOT have a shell, network, GPU drivers, Windows program support, Steam, or filesystem.

Safety: builds CD ISO under out/ and boots a VM, never operates on real Windows drives or backups.

See docs/ROADMAP.md, docs/SECURITY.md and docs/BASLANGIC_TR.md.

Copyright 2026 WolfOS Contributors. MIT-licensed for the project code. The external Limine bootloader and limine crate have their own licenses.
