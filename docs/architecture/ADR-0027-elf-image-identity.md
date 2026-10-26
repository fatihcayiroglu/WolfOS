# ADR-0027 — Built-in exact ELF identity before WolfOS Shield grants

Date: 2026-10-26

## Decision

WolfOS Shield must not grant FILE_READ merely because a PID is registered
or a user process supplies a filename, PID, or claimed application name.
Each ProcessTable-minted process starts **unverified and default-deny**.
A privileged loader first validates the independent ELF, maps its image into
owned and isolated user pages, enters the authorized CR3 and confirms that
the same PID is RUNNING. Only then may the loader call
`AppPermissions::bind_verified_image` with the actual loaded ELF bytes and a
**separately kernel-controlled, immutable allowlist image**.

The first bounded identity comparison is full byte-for-byte equality,
not a truncated or collision-prone digest, filename, or process number.
Empty or oversized images are refused. Mismatched or truncated ELF bytes
must fail with no mutation to the policy ledger. Image binding cannot be
repeated on a live PID to switch identity. Rights (including the future
reserved Network/Camera/Microphone bits) cannot be granted before image
binding. The identity record is discarded on PID retirement; reused process
slots have distinct increasing generations and begin unverified.

## Hardware acceptance

The isolated single-BSP, IF=0 real Ring3 file I/O flavor binds the actual
independently linked ELF after the running ProcessTable/CR3 checks and
before IRETQ. It first verifies a shortened ELF is rejected, then accepts
the exact immutable kernel-embedded ELF. All subsequent QEMU INT80
OPEN_RO / READ / CLOSE tests still enforce one exact file path, live revoke,
re-scoping, stale descriptors, and safe PMM cleanup.

Host tests prove same-size tampering, truncation, empty and oversized
images, duplicate binding, stale PID identity, and grant-before-binding
fail closed.

## Non-goals and next steps

This is an **internal built-in allowlist seam**, not downloadable-program
identity, signing, PKI, certificate revocation, app store trust,
a user-consent prompt, persistent permissions, or a general loader.
Kernel code supplying the trusted allowlist is inside the trusted
computing base and must not use a user-selected manifest as the baseline.
As the loader becomes general-purpose, WolfOS needs a verified publisher
signature or trusted package manifest, audited image measurement, secure
updates, filesystem rename/link handling, revocation, multiple images and
robust SMP-safe enforcement. No physical disk is touched by this proof.
