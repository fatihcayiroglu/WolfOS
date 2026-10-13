# ADR-0008: Four-vCPU MADT topology acceptance test

Status: Proposed until GitHub Actions tests pass.

- Run QEMU q35 with four vCPUs (one socket, four cores).
- Reuse the tested normal WolfOS kernel smoke image.
- Verify firmware MADT reports exactly four enabled local APIC/x2APIC
  processors and the kernel still reaches WOLFOS_BOOT_OK.
- Keep normal single-vCPU smoke, invalid-opcode, and paging-fault tests.
- Neither AP startup nor real parallel kernel execution occurs in this PR.
- This prevents silently treating the CPUID boot CPU as the only processor
  on a multi-core platform.

SMP scheduling, per-CPU kernel stacks, per-CPU GDT/TSS/IDT and interprocessor
interrupt handling remain separate, required engineering milestones.
