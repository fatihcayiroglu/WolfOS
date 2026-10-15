# ADR-0026 — Hardware verified native file syscalls (isolated BSP)

Date: 2026-10-15
Status: Implementation pending exact-head CI acceptance in PR #79

## Scope

The independent ELF fixture selected by `user-file-io-smoke` uses actual
CPU privilege level 3 and INT 0x80, with the pre-existing saved 15-GPR trap
frame, real 4-level page-table translation in the sanitized private CR3,
and exclusively PMM-owned frame allowlists. It never directly dereferences
a userspace virtual address from supervisor code.

Experimental register ABI, preserving #76:

- syscall 5: existing user-pointer WRITE (separate smoke flavor);
- 6 OPEN_RO: RDI=pathname user VA, RSI=exact length, RDX=0;
- 7 READ: RDI=opaque PID-owned descriptor, RSI=destination user VA,
  RDX=length (0..256);
- 8 CLOSE: RDI=descriptor, RSI=RDX=0.

All dispatch outcomes are nonnegative success values or negative errno
bits encoded in RAX. Other registers, including R12 descriptor storage,
must remain unchanged on IRETQ. Each trap checks CPL3 CS/SS/RIP/RSP,
RFLAGS, kernel TSS.RSP0 range and unchanged active CR3.

## Required positive/negative proof

The user fixture intentionally sends:
1. OPEN of supervisor high-half address -> -EFAULT, then OPEN of an RX
   user executable `/tmp/msg.txt` pathname -> first opaque descriptor 256;
2. READ into RX user executable code -> -EFAULT, with VFS cursor restored;
3. READ 8 bytes into RW+NX user stack -> `FILE_OK\n`, verified by guest
   instructions and separately by kernel through the same page walker;
4. READ again -> EOF 0; CLOSE -> 0; stale CLOSE -> -EBADF;
5. EXIT(0), zero open descriptors, genuine CR3 restoration and release of
   all 7 physical frames with no PMM leak.

The dedicated script requires exact ordered single-use serial markers,
no exceptions, no panic and QEMU isa-debug-exit 33. No previous hardware
or host test may be removed or skipped. Before merge, require TWO full
exact-head green workflow runs (push and pull_request) and post-merge
main validation.

## Limitations

This is intentionally BSP-only, interrupts disabled and one trusted
independently linked ET_EXEC fixture. Kernel-high-half page tables still
borrow bootloader-managed descendants; no generalized hardware driver,
disk persistence, input shell, arbitrary ELF loading, preemption of
user tasks, user fault recovery, thread-safe mappings, Windows ABI,
Steam or desktop is implied. The design is not yet a production API.
