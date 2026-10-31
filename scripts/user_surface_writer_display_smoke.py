#!/usr/bin/env python3
"""Real QMP screenshots of guest-authored CPL3 pixels on Limine std-VGA.

This opt-in QEMU acceptance independently verifies all displayed RGB bytes,
including the pixels outside the 5x3 patch and exact framebuffer restoration.
The genuine linked ELF writes two pixel buffers to private RW/NX CPL3 stack
pages, and the kernel copies them through a PMM-owner-checked user PTE walk.

The final presenter writes the *kernel-owned* CPU snapshot to the existing
Limine framebuffer with volatile stores. This is standard VGA scanout, NOT
VirtIO-GPU DMA, a production GUI driver or an on-hardware GPU claim.
"""
from pathlib import Path
import json
import socket
import subprocess
import sys
import tempfile
import time

from elf_launch_evidence import valid_launch_transactions
from qemu_virtio_gpu_scanout_live_smoke import (
    ProofError, connect_unix, ppm, qmp_call,
)
from user_copy_smoke import ENTER, PROOFS, WRITER_PROOF

STAGES = ("baseline", "active", "restored")
REPLIES = {"baseline": b"B", "active": b"A", "restored": b"R"}
PREFIX = "WOLFOS_CPL3_DISPLAY_CAPTURE stage="
DISPLAY_OK = (
    "WOLFOS_CPL3_DISPLAY_OK source=real_cpl3_stack "
    "copied_via_4level_pte=1 stdvga_framebuffer=1 host_qmp_captures=3 "
    "changed_pixels=15 restored=1 real_virtio_dma=0"
)
X, Y, W, H = 200, 150, 5, 3
BACKGROUND = (0x12, 0x34, 0x56)
PIXELS = {
    (1, 1): (0xE2, 0x14, 0x09),
    (2, 1): (0x0C, 0x1E, 0xDA),
    (3, 1): (0xAB, 0xCD, 0xEF),
}


def expect_active(image: tuple[int, int, bytes],
                  baseline: tuple[int, int, bytes]) -> None:
    width, height, rgb = image
    if (width, height) != baseline[:2] or width < X + W or height < Y + H:
        raise ProofError(f"QMP active display geometry {width}x{height} invalid")
    wanted = bytearray(baseline[2])
    for y in range(H):
        for x in range(W):
            at = 3 * ((Y + y) * width + X + x)
            wanted[at:at + 3] = bytes(PIXELS.get((x, y), BACKGROUND))
    if rgb != wanted:
        mismatches = (at for at, (actual, target) in
                      enumerate(zip(rgb, wanted)) if actual != target)
        first = next(mismatches, -1)
        if first < 0 and len(rgb) != len(wanted):
            raise ProofError("QMP screen has truncated RGB payload")
        raise ProofError(
            f"QMP screenshot differs outside expected precise CPL3 pixel patch "
            f"at x={(first//3)%width}, y={(first//3)//width}, channel={first%3}"
        )


def read_image(qmp, reader, path: Path) -> tuple[int, int, bytes]:
    qmp_call(qmp, reader, "screendump", {"filename": str(path)})
    return ppm(path)


def capture(stage: str, qmp, reader, directory: Path,
            baseline: tuple[int, int, bytes] | None
            ) -> tuple[int, int, bytes]:
    target = directory / f"{stage}.ppm"
    # Poll the *host-observed display* rather than trusting the serial claim
    # that a framebuffer update was presented. VGA may refresh asynchronously.
    deadline = time.monotonic() + 8
    last_error = "host display never updated"
    while time.monotonic() < deadline:
        image = read_image(qmp, reader, target)
        try:
            if stage == "baseline":
                if image[0] < X + W or image[1] < Y + H:
                    raise ProofError("QMP VGA framebuffer is too small")
                if len(image[2]) != image[0] * image[1] * 3:
                    raise ProofError("QMP VGA pixel buffer truncated")
            elif stage == "active":
                if baseline is None:
                    raise ProofError("active frame without baseline")
                expect_active(image, baseline)
            else:
                if baseline is None or image != baseline:
                    raise ProofError("restored QMP screen is NOT the original full frame")
            return image
        except ProofError as exc:
            last_error = str(exc)
            time.sleep(0.08)
    raise ProofError(f"Host QMP stage {stage} failed: {last_error}")


def validate_serial(output: str, code: int) -> None:
    if code != 33:
        raise ProofError(f"QEMU expected clean ISA-debug-exit 33, got {code}")
    if not valid_launch_transactions(output, 7, (1,)):
        raise ProofError("real counted ELF launch, CR3 and terminal PMM retirement invalid")
    entry = ENTER.search(output)
    if entry is None or not 1 <= int(entry.group(1)) <= 255:
        raise ProofError("genuine CPL3 ELF entry missing")
    markers = [
        "WOLFOS_BOOT_OK", entry.group(0),
        *PROOFS[:4],
        *(PREFIX + stage for stage in STAGES),
        DISPLAY_OK,
        WRITER_PROOF,
        *PROOFS[4:],
    ]
    cursor = 0
    for marker in markers:
        at = output.find(marker, cursor)
        if at < 0:
            raise ProofError(f"Missing/out-of-order genuine guest proof: {marker}")
        cursor = at + len(marker)
        if output.count(marker) != 1:
            raise ProofError(f"Duplicate proof: {marker}")
    forbidden = (
        "WOLFOS_ELF_RUN_ERROR", "WOLFOS_PANIC",
        "WOLFOS_EXCEPTION_PF", "WOLFOS_EXCEPTION_GP",
        "WOLFOS_EXCEPTION_UD", "WOLFOS_EXCEPTION_DF",
        "WOLFOS_CPL3_DISPLAY_FAIL", "WOLFOS_RING_PREP_ERROR",
        "WOLFOS_ELF_HELLO_OK",
    )
    for fragment in forbidden:
        if fragment in output:
            raise ProofError(f"Forbidden failure/old behavior marker: {fragment}")


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print("Usage: user_surface_writer_display_smoke.py path/to/ISO")
        return 2
    iso = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="wolfos-cpl3-qmp-vga-") as root:
        temp = Path(root)
        serial_socket = temp / "serial.sock"
        qmp_socket = temp / "qmp.sock"
        command = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "std", "-cdrom", str(iso), "-boot", "d",
            "-chardev", f"socket,id=wolfcom,path={serial_socket},server=on,wait=on",
            "-serial", "chardev:wolfcom",
            "-qmp", f"unix:{qmp_socket},server=on,wait=off",
            "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        process = None
        received = bytearray()
        stages = []
        images = {}
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            deadline = time.monotonic() + 65
            with connect_unix(serial_socket, process, deadline) as serial:
                with connect_unix(qmp_socket, process, deadline) as qmp:
                    reader = qmp.makefile("rb")
                    if "QMP" not in json.loads(reader.readline()):
                        raise ProofError("Missing genuine QMP handshake")
                    qmp_call(qmp, reader, "qmp_capabilities")
                    serial.settimeout(0.25)
                    pending = b""
                    while time.monotonic() < deadline:
                        try:
                            chunk = serial.recv(65536)
                        except socket.timeout:
                            chunk = None
                        if chunk == b"":
                            break
                        if chunk:
                            received.extend(chunk)
                            pending += chunk
                            while b"\n" in pending:
                                line, pending = pending.split(b"\n", 1)
                                row = line.decode("ascii", errors="replace").strip()
                                if row.startswith(PREFIX):
                                    stage = row[len(PREFIX):]
                                    if len(stages) >= len(STAGES) or stage != STAGES[len(stages)]:
                                        raise ProofError(f"Unexpected QMP screenshot stage: {stage}")
                                    images[stage] = capture(
                                        stage, qmp, reader, temp, images.get("baseline"))
                                    serial.sendall(REPLIES[stage])
                                    stages.append(stage)
                        if process.poll() is not None and not chunk:
                            break
                    if stages != list(STAGES):
                        raise ProofError(f"Only {stages!r} screenshot stages received")
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                raise ProofError("QEMU never returned after guest PMM cleanup")
            output = received.decode("ascii", errors="replace").replace("\r\n", "\n")
            print(output)
            validate_serial(output, process.returncode)
            print(
                "PASS: real guest-written CPL3 pixels -> owner-validated four-level "
                "user copy -> exact standard VGA host QMP RGB; baseline restored "
                "byte-for-byte; real CR3/7-frame PMM retirement, no VirtIO DMA")
            return 0
        except (ProofError, OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"FAIL: CPL3 QMP std-VGA visual acceptance: {exc}")
            print(received.decode("ascii", errors="replace"))
            return 1
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
