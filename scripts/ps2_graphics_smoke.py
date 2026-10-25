#!/usr/bin/env python3
"""Inject real QEMU i8042 key events and verify WolfOS graphics pixel readback."""
from __future__ import annotations

import os
import pathlib
import re
import select
import socket
import subprocess
import sys
import tempfile
import time

TIMEOUT = 40


def wait_for(proc: subprocess.Popen[bytes], output: bytearray, marker: bytes) -> None:
    deadline = time.monotonic() + TIMEOUT
    while marker not in output:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"missing {marker!r}; tail={output[-1200:]!r}")
        ready, _, _ = select.select([proc.stdout], [], [], min(remaining, 0.2))
        if ready:
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError(f"QEMU serial EOF before {marker!r}")
            output.extend(chunk)
        elif proc.poll() is not None:
            raise RuntimeError(f"QEMU exited {proc.returncode} before {marker!r}")


def connect_monitor(path: pathlib.Path) -> socket.socket:
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        try:
            monitor = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            monitor.connect(str(path))
            monitor.settimeout(3)
            return monitor
        except (FileNotFoundError, ConnectionRefusedError):
            monitor.close()
            time.sleep(0.1)
    raise TimeoutError("QEMU HMP monitor did not appear")


def main() -> int:
    help_mode = len(sys.argv) == 3 and sys.argv[2] == "--help-mode"
    info_mode = len(sys.argv) == 4 and sys.argv[2] == "--info-mode" and sys.argv[3] in ("mem", "pci")
    if not (len(sys.argv) == 2 or help_mode or info_mode):
        print("usage: ps2_graphics_smoke.py image.iso [--help-mode | --info-mode mem|pci]")
        return 2
    iso = pathlib.Path(sys.argv[1]).resolve()
    if not iso.is_file():
        print(f"missing ISO: {iso}")
        return 2
    with tempfile.TemporaryDirectory(prefix="wolfos-ps2-") as tmp:
        monitor_path = pathlib.Path(tmp) / "monitor.sock"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M",
            "-cdrom", str(iso), "-boot", "d", "-vga", "std",
            "-serial", "stdio", "-monitor",
            f"unix:{monitor_path},server,nowait",
            "-display", "none", "-no-reboot",
        ]
        try:
            proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, bufsize=0,
            )
        except FileNotFoundError:
            print("missing qemu-system-x86_64")
            return 2
        output = bytearray()
        try:
            wait_for(proc, output, b"WOLFOS_BOOT_OK")
            wait_for(proc, output, b"WOLFOS_PS2_READY")
            monitor = connect_monitor(monitor_path)
            try:
                # Real emulated i8042 scan codes, never serial input.
                if help_mode or info_mode:
                    wait_for(proc, output, b"WOLFOS_PS2_PROMPT_READY")
                if help_mode:
                    keys = ("h", "e", "l", "x", "backspace", "p", "ret")
                elif info_mode:
                    keys = tuple(sys.argv[3]) + ("ret",)
                else:
                    keys = ("a", "b", "c", "backspace", "d", "ret")
                for i, key in enumerate(keys, 1):
                    monitor.sendall(f"sendkey {key}\n".encode("ascii"))
                    wait_for(proc, output, f"WOLFOS_PS2_EVENT accepted={i}\r\n".encode())
                    print(f"PASS: emulated keyboard key={key} accepted={i}")
                if info_mode:
                    kind = sys.argv[3]
                    if kind == "pci":
                        wait_for(proc, output, b"WOLFOS_PS2_PCI_OK ")
                        wait_for(proc, output, b"pixels=verified\r\n")
                        boot = re.search(
                            rb"WOLFOS_PCI_OK devices=(\d+) displays=(\d+) networks=(\d+) storage=(\d+)", output
                        )
                        live = re.search(
                            rb"WOLFOS_PS2_PCI_OK displays=(\d+) networks=(\d+) storage=(\d+) pixels=verified", output
                        )
                        if not boot or not live or live.groups() != boot.groups()[1:]:
                            raise RuntimeError("graphical PCI counts do not equal early immutable discovery")
                        print("PASS: PS/2 PCI matches boot PCI counts and real framebuffer pixels")
                    else:
                        wait_for(proc, output, b"WOLFOS_PS2_MEM_OK ")
                        wait_for(proc, output, b"pixels=verified\r\n")
                        boot = re.search(
                            rb"WOLFOS_PMM_OK [^\r\n]*free_frames=(\d+)", output
                        )
                        live = re.search(
                            rb"WOLFOS_PS2_MEM_OK free_frames=(\d+) mib=(\d+) pixels=verified", output
                        )
                        if not boot or not live:
                            raise RuntimeError("missing boot PMM or graphical memory measurement")
                        boot_free = int(boot.group(1))
                        free = int(live.group(1))
                        mib = int(live.group(2))
                        if free <= 0 or free > boot_free or mib != free // 256:
                            raise RuntimeError(f"bad graphical memory data: boot={boot_free} free={free} MiB={mib}")
                        print("PASS: PS/2 MEM reports live free MiB with framebuffer pixels")
                elif help_mode:
                    wait_for(
                        proc, output,
                        b"WOLFOS_PS2_HELP_OK source=keyboard edit=backspace output=framebuffer pixels=verified",
                    )
                    print("PASS: independent keyboard HELP command and framebuffer text")
                else:
                    wait_for(
                        proc, output,
                        b"WOLFOS_PS2_GRAPHICS_OK keys=6 text=ABD backspace=1 enter=1 pixels=verified",
                    )
                    print("PASS: original PS/2 ABD edit and framebuffer pixel proof")
                return 0
            finally:
                monitor.close()
        except (RuntimeError, TimeoutError, OSError, BrokenPipeError) as exc:
            print(f"FAIL: {exc}")
            print(output[-2500:].decode(errors="replace"))
            return 1
        finally:
            if proc.poll() is None:
                proc.terminate()
            try:
                _, err = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, err = proc.communicate(timeout=5)
            if err:
                print(f"QEMU stderr: {err[-1400:].decode(errors='replace')}")


if __name__ == "__main__":
    sys.exit(main())
