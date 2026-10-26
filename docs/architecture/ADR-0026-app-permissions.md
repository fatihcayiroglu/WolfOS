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

## Exact path-scoped FILE_READ leases (extension)

The FileRead policy is not a directory wildcard or a general filesystem
capability: a trusted kernel policy decision must bind it to exactly one
canonical, bounded absolute pathname. Invalid, ambiguous, traversing, or
non-ASCII paths cannot become grants. A generic `grant(FileRead)` call fails
with `PathRequired`, and there is no user syscall to choose its own path.

OPEN_RO first checks the process has a lease, then copies the filename through
its proven user CR3 and requires an **exact byte-for-byte scope match** before
opening any VFS descriptor. On each READ, the kernel resolves the opaque
PID-owned descriptor to its live canonical RamFS pathname, checks that the
scope **still matches**, and only then touches VFS data or the user buffer.
Changing the lease to a different file makes an already-open old descriptor
inaccessible. CLOSE remains possible without a lease. This is also exercised
with two real sealed files in the isolated CPL3/QEMU test: the ungranted file
cannot be opened, and an open descriptor cannot be read after the scope is
changed to the other file. Matching the old scope again permits EOF.

This is still not a user consent dialog, durable security-label provenance,
filesystem-wide mediation, or generalized multi-process hardware enforcement;
the fixed QEMU policy harness remains trusted. Real hardware security requires
app identity attestation, a kernel-wide broker, concurrency-safe revocation,
mount/rename protections, a policy UI, and persistent consent lifecycle.
