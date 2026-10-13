# ADR-0004: Initial PCI hardware discovery

Status: Under review until actual QEMU smoke CI passes.

## Decision
- Probe x86 PCI configuration mechanism #1 through CF8/CFC I/O.
- Scan all bus/device numbers and multifunction functions where declared.
- Read vendor ID, device ID and class code, then count display/network/storage
  controllers. Do not write device configuration registers.
- Require a QEMU standard VGA device in the boot smoke; verify at least one
  display-class PCI function is found and logged.
- No PCI BAR probing, memory mapping, DMA, driver installation or firmware use.

## Constraints
- Legacy 256-byte PCI configuration headers only; no PCIe ECAM extended space.
- Port I/O access is global and not safe for concurrent CPUs or interrupts.
- No hotplug, bridges topology accounting, or modern GPU acceleration yet.
- QEMU discovery demonstrates PCI identity only, not functional GPU support.
- No physical disk I/O and no real hardware tests.

## Acceptance
`make test` and `make smoke` pass. QEMU serial logs contain
WOLFOS_GPU_DETECTED, WOLFOS_PCI_OK and WOLFOS_PCI_TEST_OK.
