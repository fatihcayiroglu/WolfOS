#!/usr/bin/env python3
"""Exercise the opt-in WolfOS COM1 console through genuine QEMU serial input."""
from __future__ import annotations

import pathlib
import select
import subprocess
import sys
import time

TIMEOUT = 40.0


def await_marker(proc: subprocess.Popen[bytes], output: bytearray, marker: bytes) -> None:
    deadline = time.monotonic() + TIMEOUT
    while marker not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"missing {marker.decode()}: {output[-3000:]!r}")
        ready, _, _ = select.select([proc.stdout], [], [], min(remaining, 0.5))
        if ready:
            chunk = proc.stdout.read(4096)
            if not chunk:
                raise RuntimeError(f"QEMU closed serial before {marker!r}: {output[-3000:]!r}")
            output.extend(chunk)
        elif proc.poll() is not None:
            raise RuntimeError(f"QEMU exited {proc.returncode} before {marker!r}")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: serial_shell_smoke.py path/to/wolfos-serial-shell.iso")
        return 2
    iso = pathlib.Path(sys.argv[1]).resolve()
    if not iso.is_file():
        print(f"missing ISO: {iso}")
        return 2

    command = [
        "qemu-system-x86_64", "-M", "q35", "-m", "512M",
        "-cdrom", str(iso), "-boot", "d",
        "-serial", "stdio", "-monitor", "none", "-display", "none",
        "-no-reboot",
    ]
    try:
        proc = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, bufsize=0,
        )
    except FileNotFoundError:
        print("missing qemu-system-x86_64")
        return 2
    output = bytearray()
    try:
        await_marker(proc, output, b"WOLFOS_BOOT_OK")
        await_marker(proc, output, b"WOLFOS_SHELL_READY")
        await_marker(proc, output, b"WOLFOS_BOOT_SELFTESTS_SKIPPED mode=non_smoke")
        forbidden = (
            b"WOLFOS_PMM_TEST_OK",
            b"WOLFOS_PAGING_MAP_OK",
            b"WOLFOS_CONTEXT_OK",
            b"WOLFOS_KTHREAD_OK",
            b"WOLFOS_CTX_BATCH_OK",
        )
        for marker in forbidden:
            if marker in output:
                raise RuntimeError(f"interactive boot unexpectedly ran stress check: {marker!r}")
        for typed, marker in [
            (b"help\r", b"WOLFOS_SHELL_HELP"),
            (b"mem\r", b"WOLFOS_SHELL_MEM"),
            (b"about\r", b"WOLFOS_SHELL_ABOUT"),
            (b"clear\r", b"WOLFOS_SHELL_CLEAR"),
            (b"somethingelse\r", b"WOLFOS_SHELL_UNKNOWN"),
            (b"halt\r", b"WOLFOS_SHELL_HALT"),
        ]:
            if proc.poll() is not None:
                raise RuntimeError(f"QEMU exited unexpectedly: {proc.returncode}")
            proc.stdin.write(typed)
            proc.stdin.flush()
            await_marker(proc, output, marker)
            print(f"PASS: {marker.decode()}")
        print("PASS: real COM1 input and bounded shell command roundtrips")
        return 0
    except (TimeoutError, RuntimeError, BrokenPipeError) as exc:
        print(f"FAIL: {exc}")
        return 1
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            _, err = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate(timeout=5)
        if err and b"error" in err.lower():
            print(f"QEMU stderr: {err[-1000:].decode(errors='replace')}")
        if b"WOLFOS_SHELL_HALT" not in output:
            print(output[-3000:].decode(errors="replace"))


if __name__ == "__main__":
    sys.exit(main())
