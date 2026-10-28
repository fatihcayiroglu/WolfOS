# ADR-0070 — First real QEMU virtio-vga PCI discovery, read-only

Status: draft, stacked after ADR-0069/PR #301.

## Decision
Introduce a feature-gated **real QEMU virtio-vga PCI capability-chain proof**.
A new no-heap Rust parser checks exactly 256 read-only PCI config bytes:
1af4:1050, class 03, Status Capability List flag, aligned bounded links,
no capability-chain loops, vendor capability ID 0x09, capacity and length
checks, BAR indexes 0..5, sane offset/length, and the four mandatory
VirtIO PCI capability kinds (common, notify, ISR, GPU device config).
Reject duplicate, malformed, truncated, absent or overlapping capabilities.

The QEMU-only gate starts the actual independent WolfOS kernel on an ISO:
`qemu-system-x86_64 -M q35 -vga none -device virtio-vga`. The kernel
reads real emulated PCI configuration dwords via 0xCF8/0xCFC, then emits a
typed attestation only if all required capabilities are present. Strict
Python proof requires actual PCI identity, policy, capability count,
boot/exit and disallows fake driver/DMA claims. There are host parser
and validator tests but these do not replace the genuine QEMU gate.

Primary design references:
- https://www.qemu.org/docs/master/system/devices/virtio/virtio-gpu.html
- https://www.qemu.org/docs/master/specs/pci-ids.html
- https://docs.oasis-open.org/virtio/virtio/v1.0/cs02/virtio-v1.0-cs02.html

## Safety / next
This is NOT EDID reading yet, and NOT GPU acceleration. It does not
negotiate VirtIO F_EDID, map BARs, allocate DMA, create the virtqueue,
send GET_EDID or SET_SCANOUT, or claim an actual Hz. It writes the shared
PCI 0xCF8 *selector* port only; device PCI configuration remains
read-only. Physical disks/GPUs are never used in the smoke gate.
Actual transport needs separately vetted BAR and bounded DMA ownership,
device reset/negotiation, control queue completion timeouts, then
GET_DISPLAY_INFO/GET_EDID and EDID parsing from #299-#301.
