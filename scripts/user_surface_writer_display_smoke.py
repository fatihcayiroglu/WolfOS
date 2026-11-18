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

from elf_launch_evidence import transaction_rows, valid_launch_transactions
from qemu_virtio_gpu_scanout_live_smoke import (
    ProofError, connect_unix, ppm, qmp_call,
)
from user_copy_smoke import ENTER, PROOFS, WRITER_PROOF

MAX_QEMU_STDERR_TAIL = 8192


def qemu_stderr_tail(path: Path) -> str:
    """Keep runner diagnostics bounded, including noisy QEMU error output."""
    try:
        with path.open("rb") as source:
            source.seek(0, 2)
            source.seek(max(0, source.tell() - MAX_QEMU_STDERR_TAIL))
            return source.read(MAX_QEMU_STDERR_TAIL).decode("utf-8", errors="replace")
    except FileNotFoundError:
        return ""


# Serial evidence is untrusted until both the host QMP pixels and the real
# guest lifecycle have been independently checked. Bound hostile/malformed
# serial output before keeping it in memory or scanning for stage messages.
MAX_SERIAL_BYTES = 1 << 20
MAX_SERIAL_LINE_BYTES = 16 << 10


def decode_serial_evidence(raw: bytes) -> str:
    """Decode real COM1 bytes losslessly; do not turn corrupt octets into proof."""
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProofError("Non-ASCII byte in QEMU serial evidence") from exc


def append_serial_chunk(received: bytearray, pending: bytes,
                        chunk: bytes) -> tuple[bytes, list[bytes]]:
    """Return complete serial lines; reject oversized output before buffering."""
    if len(chunk) > MAX_SERIAL_BYTES - len(received):
        raise ProofError("QEMU serial evidence exceeds bounded size")
    parts = (pending + chunk).split(b"\n")
    if any(len(line) > MAX_SERIAL_LINE_BYTES for line in parts):
        raise ProofError("QEMU serial evidence line exceeds bounded size")
    received.extend(chunk)
    return parts[-1], parts[:-1]


STAGES = ("baseline", "active", "restored")
REPLIES = {"baseline": b"B", "active": b"A", "restored": b"R"}
PREFIX = "WOLFOS_CPL3_DISPLAY_CAPTURE stage="
def parse_capture_stage_line(line: bytes, expected: str | None) -> str | None:
    """Require exact raw COM1 stage bytes before any screenshot ACK is sent.

    A forged log line may contain a plausible capture substring. It must not
    cause the host to send B/A/R or be treated as a real guest stage.
    CRLF framing from the serial transport is the only allowed suffix.
    """
    marker = PREFIX.encode("ascii")
    if marker not in line:
        return None
    if expected is None or line.removesuffix(b"\r") != marker + expected.encode("ascii"):
        raise ProofError("Malformed, unexpected or out-of-order QMP capture stage")
    return expected


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
    # A matching post-write color is not evidence that the pixel changed.
    # Independently verify the claim "changed_pixels=15" against the host
    # baseline, rather than accepting a previously identical rectangle.
    expected_len = width * height * 3
    if len(rgb) != expected_len or len(baseline[2]) != expected_len:
        raise ProofError("QMP active or baseline RGB payload length invalid")
    wanted = bytearray(baseline[2])
    for y in range(H):
        for x in range(W):
            at = 3 * ((Y + y) * width + X + x)
            color = bytes(PIXELS.get((x, y), BACKGROUND))
            if baseline[2][at:at + 3] == color:
                raise ProofError(
                    f"QMP patch pixel x={X+x}, y={Y+y} did not change from baseline"
                )
            wanted[at:at + 3] = color
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


MAX_QMP_PPM_BYTES = 64 << 20


def checked_qmp_ppm(path: Path) -> tuple[int, int, bytes]:
    """Bound QMP screenshot memory use before the shared PPM decoder reads it.

    Even a nominally supported 8192x8192 RGB frame can consume ~192 MiB.
    The isolated std-VGA acceptance needs nowhere near that much RAM.
    """
    size = path.stat().st_size
    if not 14 <= size <= MAX_QMP_PPM_BYTES:
        raise ProofError("QMP screenshot PPM file size outside safe range")
    return ppm(path)


def read_image(qmp, reader, path: Path) -> tuple[int, int, bytes]:
    # Repeated stage polling must not reuse the previous capture as evidence.
    # Delete the old file *before* requesting another genuine QMP screenshot.
    path.unlink(missing_ok=True)
    qmp_call(qmp, reader, "screendump", {"filename": str(path)})
    try:
        return checked_qmp_ppm(path)
    except FileNotFoundError as exc:
        raise ProofError("QMP screendump returned without a fresh screenshot") from exc


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
    if not output.isascii():
        raise ProofError("Non-ASCII text in QEMU serial evidence")
    # A proof is one complete raw COM1 line, not a Unicode splitlines() token.
    # CRLF is normal framing; reject bare CR and an unterminated final record.
    if not output.endswith("\n"):
        raise ProofError("QEMU serial evidence has an unterminated final record")
    output = output.replace("\r\n", "\n")
    if "\r" in output:
        raise ProofError("QEMU serial evidence contains a bare carriage return")
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
    # Each mandatory marker must be an exact, independent serial line.
    # Substring hits in other logs (including fabricated prefixes/suffixes)
    # are not evidence that the real guest executed that stage.
    lines = output.split("\n")
    # The transaction helper validates lifecycle ordering; additionally require
    # exact newline-delimited TX records, not embedded control-character lines.
    tx_lines = [line for line in lines if "WOLFOS_ELF_TX_" in line]
    if tx_lines != transaction_rows(1, 7):
        raise ProofError("Counted transaction records are not exact serial lines")
    cursor = 0
    for marker in markers:
        canonical = marker.removesuffix("\n")
        matches = [i for i, line in enumerate(lines) if line == canonical]
        if len(matches) != 1 or matches[0] < cursor:
            raise ProofError(
                f"Missing, duplicate or out-of-order guest proof: {canonical}"
            )
        cursor = matches[0] + 1
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
    # Substring-only matching accepts log injections such as
    # "prefixWOLFOS_CPL3_DISPLAY_OK ...", or extra capture stages.
    # Host screenshot evidence must be complete, standalone serial lines.
    lines = output.split("\n")
    expected_stages = [PREFIX + stage for stage in STAGES]
    actual_stages = [line for line in lines if line.startswith(PREFIX)]
    if actual_stages != expected_stages:
        raise ProofError("Missing, duplicated, or malformed QMP capture stage line")
    if lines.count(DISPLAY_OK) != 1 or lines.count(WRITER_PROOF) != 1:
        raise ProofError("Missing or embedded CPL3 display/writer proof line")


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
            # Never leave PIPE descriptors unread while waiting for QEMU.
            # A noisy emulator can fill a pipe and deadlock before exit.
            # Its serial evidence is captured independently via COM1.
            with (temp / "qemu.stderr").open("wb") as qemu_stderr:
                process = subprocess.Popen(
                    command, stdout=subprocess.DEVNULL, stderr=qemu_stderr
                )
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
                            pending, serial_lines = append_serial_chunk(
                                received, pending, chunk)
                            for line in serial_lines:
                                expected = STAGES[len(stages)] if len(stages) < len(STAGES) else None
                                stage = parse_capture_stage_line(line, expected)
                                if stage is not None:
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
            output = decode_serial_evidence(received).replace("\r\n", "\n")
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
            stderr = qemu_stderr_tail(temp / "qemu.stderr")
            if stderr:
                print("QEMU stderr (bounded tail):\n" + stderr)
            return 1
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
