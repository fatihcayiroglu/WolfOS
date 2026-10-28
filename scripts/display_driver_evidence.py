#!/usr/bin/env python3
"""Strict evidence that PCI identification NEVER masquerades as a GPU driver."""
import re

GPU = re.compile(
    r"WOLFOS_GPU_DRIVER_POLICY vendor=([0-9a-f]{4}) "
    r"device=([0-9a-f]{4}) family="
    r"(nvidia|amd|intel|qemu|virtio|other) native=none cfg_write=0"
)
FOUND = re.compile(
    r"WOLFOS_GPU_DETECTED vendor=([0-9a-f]{4}) "
    r"device=([0-9a-f]{4}) bus=([0-9a-f]{2}) slot=([0-9a-f]{2})"
)
BOOT = "WOLFOS_DISPLAY_BOOT_POLICY backend=limine-framebuffer native_accel=0 driver_loaded=0"
FORBIDDEN = (
    "WOLFOS_GPU_NATIVE_OK", "WOLFOS_GPU_DRIVER_LOADED",
    "native_accel=1", "driver_loaded=1", "cfg_write=1",
)

def validate_display_evidence(output: str) -> bool:
    rows = output.splitlines()
    policy_rows = [(index, row) for index, row in enumerate(rows)
                   if row.startswith("WOLFOS_GPU_DRIVER_POLICY ")]
    found_rows = [(index, row) for index, row in enumerate(rows)
                  if row.startswith("WOLFOS_GPU_DETECTED ")]
    boot_rows = [index for index, row in enumerate(rows)
                 if row.startswith("WOLFOS_DISPLAY_BOOT_POLICY ")]
    pci_rows = [index for index, row in enumerate(rows)
                if row.startswith("WOLFOS_PCI_OK ")]
    fb_rows = [index for index, row in enumerate(rows)
               if row.startswith("WOLFOS_FRAMEBUFFER_OK ")]
    if (not found_rows or len(policy_rows) != len(found_rows)
            or len(boot_rows) != 1 or len(pci_rows) != 1
            or len(fb_rows) != 1 or rows[boot_rows[0]] != BOOT):
        return False
    if any(token in output for token in FORBIDDEN):
        return False
    if not (max(i for i, _ in policy_rows) < pci_rows[0]
            < boot_rows[0] < fb_rows[0]):
        return False
    for (fi, found), (pi, policy) in zip(found_rows, policy_rows):
        f = FOUND.fullmatch(found)
        p = GPU.fullmatch(policy)
        if not f or not p or fi >= pi or f.group(1, 2) != p.group(1, 2):
            return False
    return True
