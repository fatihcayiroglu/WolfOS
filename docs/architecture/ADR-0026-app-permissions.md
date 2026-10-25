# ADR-0026 — WolfOS Shield: default-deny per-PID FILE_READ gate

Date: 2026-10-26

## Decision

WolfOS must never infer filesystem permission solely from a valid virtual
address or a PID-owned descriptor. An explicit, kernel-controlled **FileRead**
permission is now checked before each experimental native CPL3 OPEN_RO or READ
operation. The VFS's existing PID+generation ownership and checked four-level
user memory walker remain independently mandatory.

The bounded, no-heap `AppPermissions<SLOTS>` ledger starts with **no grants**
for every newly enrolled ProcessTable-minted PID. A trusted kernel path alone
may grant/revoke a typed permission. A grant to one PID does not authorize
another PID, and a retired PID cannot be enrolled again. A running process
retains only an inert VFS handle if its FileRead privilege is revoked; the
next READ returns -EACCES without touching the user buffer or VFS cursor.
CLOSE remains allowed during revocation to let apps release handles.

The 2026-10-26 real-hardware-QEMU file syscall flavor proves:
1. A real CPL3 OPEN_RO of a valid user RX path is denied by default (-EACCES),
   before following the user pointer or allocating a descriptor.
2. An independently authenticated kernel test harness grants FileRead. A
   supervisor virtual pathname still fails safely (-EFAULT), while a
   valid guest path may open and READ to a user RW/NX buffer.
3. While the file descriptor remains open, the harness revokes FileRead.
   An actual Ring3 READ through that same descriptor is denied (-EACCES).
4. Following an explicit re-grant, EOF, CLOSE and stale-FD rejection work.
   EXIT retires the PID's permissions and returns all PMM frames.

## Threat model and limits

This feature is a **first working policy seam**, not a production sandbox.
The permission UI/prompt, app identity verification, filesystem path scopes,
persistent consent, delegation, and kernel-wide capability enforcement are
future work. The Microphone, Camera and Network enum cases reserve distinct
policy bits only; **they do not control hardware or network drivers yet**.
The QEMU grant/revoke calls simulate decisions from trusted kernel code after
verified hardware trap provenance; no user syscall grants itself a capability.

The demonstration remains single-BSP, IF=0, fixed ELF, bounded VFS and
seven-frame address space. Never infer that full Windows/Steam compatibility
or a daily-usable desktop exists. All previous QEMU and host safety tests
must remain mandatory.
