#!/usr/bin/env python3
"""Exercise the opt-in WolfOS COM1 console through genuine QEMU serial input."""
from __future__ import annotations

import pathlib
import re
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
        await_marker(proc, output, b"WOLFOS_FB_TEXT_OK glyph_pixels=")
        await_marker(proc, output, b"WOLFOS_FB_CONSOLE_OK cols=")
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
        # Deliver a real CRLF, followed by two more commands in the same
        # serial stream. By the ABOUT output, all prior prompts are emitted.
        # One extra prompt would prove that LF was treated as another Enter.
        proc.stdin.write(b"help\r\nmem\rabout\r")
        proc.stdin.flush()
        await_marker(proc, output, b"WOLFOS_SHELL_ABOUT")
        before_about = output.split(b"WOLFOS_SHELL_ABOUT", 1)[0]
        for marker in (b"WOLFOS_SHELL_HELP", b"WOLFOS_SHELL_MEM"):
            if marker not in before_about:
                raise RuntimeError(f"missing earlier command output: {marker!r}")
        prompts = before_about.count(b"wolfos> ")
        if prompts != 3:
            raise RuntimeError(f"CRLF caused duplicate/missing prompts: {prompts} (expected 3)")
        print("PASS: CRLF produced one command and one prompt")
        # CPUID already appears during boot. Require a NEW, command-scoped
        # identity record rather than accepting that earlier boot marker.
        proc.stdin.write(b"cpu\r")
        proc.stdin.flush()
        await_marker(proc, output, b"WOLFOS_SHELL_CPU_END")
        scoped = output.split(b"WOLFOS_SHELL_CPU_BEGIN", 1)
        if len(scoped) != 2:
            raise RuntimeError("CPU command never began")
        cpu_record = scoped[1].split(b"WOLFOS_SHELL_CPU_END", 1)[0]
        if b"WOLFOS_CPU_OK vendor=" not in cpu_record:
            raise RuntimeError(f"CPU command did not report CPUID: {cpu_record!r}")
        print("PASS: real COM1 cpu command reports live read-only CPUID")
        # Boot-only PCI enumeration is an immutable snapshot: the shell
        # must show that same snapshot, without a late CF8/CFC rescan.
        boot = re.search(
            rb"WOLFOS_PCI_OK devices=(\d+) displays=(\d+) networks=(\d+) storage=(\d+)",
            output,
        )
        if not boot:
            raise RuntimeError("missing boot-time PCI discovery snapshot")
        proc.stdin.write(b"pci\r")
        proc.stdin.flush()
        await_marker(proc, output, b"WOLFOS_SHELL_PCI_END")
        begin = output.split(b"WOLFOS_SHELL_PCI_BEGIN", 1)
        if len(begin) != 2:
            raise RuntimeError("PCI command never began")
        scoped_pci = begin[1].split(b"WOLFOS_SHELL_PCI_END", 1)[0]
        reported = re.search(
            rb"WOLFOS_SHELL_PCI devices=(\d+) displays=(\d+) networks=(\d+) storage=(\d+)",
            scoped_pci,
        )
        if not reported or reported.groups() != boot.groups():
            raise RuntimeError(f"PCI shell result differs from boot: {scoped_pci!r}")
        if int(reported.group(1)) < 1 or int(reported.group(2)) < 1:
            raise RuntimeError("QEMU PCI discovery did not detect a display device")
        print("PASS: real COM1 pci command matches immutable boot-time device counts")
        for typed, marker in [
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
