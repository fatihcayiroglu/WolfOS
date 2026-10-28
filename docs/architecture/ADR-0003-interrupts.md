# ADR-0003: Bootstrap GDT/IDT and CPU exceptions

Status: Under review, pending real QEMU CI acceptance.

## Decision
- x86-64 crate supplies descriptor-table and x86-interrupt ABI definitions.
- On one boot CPU, mask interrupts and load a permanent GDT with kernel code
  and an x86-64 TSS. Reserve a dedicated 20 KiB IST stack for double faults.
- Install IDT handlers for #DE, #BP, #UD, #GP, #PF and #DF.
- A breakpoint interrupt must return through IRETQ and execution must resume.
- Unexpected faults log CPU exception type, RIP, and error code as appropriate,
  then halt. Do not attempt to catch unwind, resume corrupted kernel state,
  or return from a page fault.
- A distinct exception-smoke build deliberately executes UD2 (#UD) and
  verifies that our Rust handler emits the marker and exits QEMU.

## Limits and security
- One boot CPU. No SMP/APIC/PIC IRQ routing or nested external IRQ handlers.
- Missing exception handlers can still triple-fault; remaining vectors are a
  separate milestone.
- IST stack is not yet protected by a guard page; paging comes later.
- Serial logging is a polling debug path, not fault-tolerant under any condition.
- The Rust x86-interrupt ABI remains a nightly feature.
- All code runs inside QEMU. No physical disks are modified.

## Acceptance
`make smoke` and `make exception-smoke` must both pass in GitHub Actions.
The exception test requires WOLFOS_GDT_OK, WOLFOS_IDT_OK,
WOLFOS_BREAKPOINT_RETURN_OK, and WOLFOS_EXCEPTION_UD vector=6.
