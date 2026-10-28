# Security status

P0 is experimental. It has no userspace isolation or secure driver model.
Unsafe Rust is limited to boot framebuffer memory and raw x86 port I/O.
The project only boots an ISO in QEMU and never targets physical host storage.
Source-contract tests are NOT a proof of Rust compilation, runtime safety, or successful boot.
Never install a P0 kernel on a real Windows or data disk.
