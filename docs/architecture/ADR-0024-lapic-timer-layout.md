# ADR-0024: xAPIC timer register layout and safety gates

Status: Proposed until tests pass.

## Scope
- Define xAPIC 32-bit timer register offsets (LVT at 0x320, initial count
  0x380, current count 0x390, divide configuration 0x3e0).
- Validate vectors (0x20..=0xfe), LVT timer modes, masking, delivery-status,
  reserved bits, nonzero initial counts and all eight legal divide factors.
- Perform pure no_std host Rust tests through make test / GitHub CI.
- Compile the module into the WolfOS kernel without touching hardware.

## Exclusions
- No APIC MMIO writes; no interrupt enabling; no timer EOI; no MSI,
  preemptive scheduling, cross-CPU rescheduling or TSC deadline activation.
- This is only prerequisite register math. It does not prove timer IRQs.
- Legacy PIT IRQ smoke remains separate and green.
- QEMU/ISO only: never touch real host drives.
