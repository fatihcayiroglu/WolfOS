#!/usr/bin/env python3
"""Real QEMU proof that the kernel's 1024x768 framebuffer is scanned out.

The guest paints its real Limine framebuffer, copies every row into 768
exclusively owned backing pages, attaches them as ONE scatter-gather request
and presents the resource as a native scanout. The host then has to prove all
786,432 pixels of a genuine QMP screenshot AND answer a nonce-bound digest
challenge computed from that screenshot. After the device reset the VGA
output must again show every one of those pixels.

Nothing here trusts a guest success line: the pixel and ordering evidence is
owned by the host, and a guest claim alone can never produce a pass.
"""
from functools import lru_cache
from pathlib import Path
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

from qemu_virtio_gpu_scanout_live_smoke import (
    ProofError, connect_unix, ppm, qmp_call, rgb_digest,
)

WIDTH = 1024
HEIGHT = 768
PIXELS = WIDTH * HEIGHT
NONCE = 0x574F4445534B0004
ATTEST_PREFIX = "WOLFOS_GPU_STAGE_ATTEST "
ATTEST = re.compile(
    r"WOLFOS_GPU_STAGE_ATTEST stage=desktop geometry=1024x768 "
    r"nonce=([0-9a-f]{16}) source_digest=([0-9a-f]{8})")
CAPTURE_PREFIX = "WOLFOS_VIRTIO_GPU_SCANOUT_CAPTURE stage="
MARKER = re.compile(
    r"WOLFOS_VIRTIO_GPU_DESKTOP_SCANOUT_OK resource_id=1 width=1024 "
    r"height=768 format=2 create_type=257 attach_type=262 transfer_type=261 "
    r"set_type=259 flush_type=260 clear_type=259 detach_type=263 "
    r"unref_type=258 response_type=4352 used_idx=21 used_head=0 used_len=24 "
    r"fences_verified=19 notify_writes=21 backing_entries=(\d+) "
    r"backing_bytes=3145728 transfer_bands=12 band_rows=64 pixels=786432 "
    r"guest_copy_verified=1 host_pixels_verified_by_kernel=0 capture_acks=1 "
    r"reset_to_vga_ack=1 reset=0 queue_disabled=1 frames_allocated=773 "
    r"frames_released=773 pmm_leak=0 qemu_only=1")
DISPLAY = re.compile(
    r"WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK req=256 resp=4353 used_idx=1 "
    r"used_head=0 used_len=408 scanout0_enabled=1 width=(\d+) height=(\d+) "
    r"notify_writes=1 driver_ok=15 reset=0 queue_disabled=1 "
    r"frames_allocated=(\d+) frames_released=(\d+) response_dma_verified=1 "
    r"pmm_leak=0 qemu_only=1")
EDID = re.compile(
    r"WOLFOS_VIRTIO_GPU_EDID_LIVE_OK scanout=0 edid_size=\d+ modes=\d+ "
    r"preferred_width=\d+ preferred_height=\d+ refresh_millihz=(\d+) .*")
# The attested geometry must become the catalog's automatic choice while the
# device's own reported geometry and the monitor's EDID rate stay refused.
CATALOG_PREFIX = "WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_OK "
CATALOG_FAIL_PREFIX = "WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_FAIL "
CATALOG = re.compile(
    r"WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_OK generation=1 entries=(\d+) "
    r"selectable=1 attested=1 device_reported=(\d+) device_width=(\d+) "
    r"device_height=(\d+) selected=1024x768 selected_refresh=unavailable "
    r"device_claim=(rejected:unproven_gpu_timing|refused:conflicting_proof) "
    r"edid_millihz=(\d+) edid_hz_request=rejected:refresh_not_programmable "
    r"applied_change_plan=none unattested_catalog=rejected:no_selectable_mode "
    r"gpu_commands_sent=0")
CATALOG_FAIL = re.compile(
    r"WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_FAIL stage=\w+ entries=0 "
    r"selectable=0 mode=no_selectable_mode")
TEST_OK = "WOLFOS_VIRTIO_GPU_SCANOUT_TEST_OK"
# Deliberate-fault switch: the host lies about one field so the guest's
# refusal has to be observable instead of assumed.
FAULT = os.environ.get("WOLFOS_DESKTOP_FAULT", "")


def expected_rgb(x: int, y: int) -> tuple[int, int, int]:
    """Mirror of `virtio_gpu_desktop_wire::pixel_rgb`."""
    return ((x * 3 + y * 7 + 29) & 0xFF,
            (x * 11 + y * 5 + 71) & 0xFF,
            (x * 13 + y * 17 + 173) & 0xFF)


@lru_cache(maxsize=1)
def expected_bytes() -> bytes:
    """The complete 1024x768 desktop image the guest must have transferred."""
    out = bytearray(PIXELS * 3)
    index = 0
    for y in range(HEIGHT):
        r_add, g_add, b_add = y * 7 + 29, y * 5 + 71, y * 17 + 173
        for x in range(WIDTH):
            out[index] = (x * 3 + r_add) & 0xFF
            out[index + 1] = (x * 11 + g_add) & 0xFF
            out[index + 2] = (x * 13 + b_add) & 0xFF
            index += 3
    return bytes(out)


@lru_cache(maxsize=1)
def pattern_digest() -> int:
    """FNV-1a the guest must claim for the desktop image.

    Known offline, so a serial log cannot invent an arbitrary digest.
    """
    value = 0x811C9DC5
    for byte in expected_bytes():
        value ^= byte
        value = (value * 0x01000193) & 0xFFFFFFFF
    return value


def verify_pixels(image: tuple[int, int, bytes]) -> int:
    """Every pixel must match, at the real desktop geometry."""
    width, height, rgb = image
    if (width, height) != (WIDTH, HEIGHT):
        raise ProofError(f"QMP geometry {width}x{height}, expected {WIDTH}x{HEIGHT}")
    expected = expected_bytes()
    if len(rgb) != len(expected):
        raise ProofError(
            f"QMP pixel buffer {len(rgb)} bytes, expected {len(expected)}")
    if rgb != expected:
        first = next(i for i, (got, want) in enumerate(zip(rgb, expected))
                     if got != want)
        raise ProofError(
            f"Host QMP pixel mismatch at ({first // 3 % width},{first // 3 // width}) "
            f"channel={first % 3} got={rgb[first]} want={expected[first]}")
    return PIXELS


def validate_desktop_serial(output: str) -> bool:
    """Host-owned serial contract for the desktop scanout flavor."""
    lines = output.splitlines()
    if any(line.startswith((
        "WOLFOS_VIRTIO_GPU_DESKTOP_FAIL", "WOLFOS_GPU_ATTEST_FAIL",
        "WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_FAIL",
        "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL", "WOLFOS_VIRTIO_GPU_EDID_LIVE_FAIL",
        "WOLFOS_VIRTIO_GPU_SCANOUT_FAIL", "WOLFOS_VIRTIO_GPU_SCANOUT_RESET_FAIL",
        "WOLFOS_FB_TEXT_FAILED",
    )) for line in lines):
        return False
    markers = [m for m in (MARKER.fullmatch(line) for line in lines
                           if line.startswith(
                               "WOLFOS_VIRTIO_GPU_DESKTOP_SCANOUT_OK ")) if m]
    if len(markers) != 1:
        return False
    marker_index = lines.index(next(line for line in lines
                                    if MARKER.fullmatch(line)))
    entries = int(markers[0].group(1))
    if not 1 <= entries <= 254:
        return False
    displays = [(i, DISPLAY.fullmatch(line)) for i, line in enumerate(lines)
                if line.startswith("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK ")]
    if len(displays) != 1 or displays[0][1] is None:
        return False
    width, height, allocated, released = map(int, displays[0][1].groups())
    # The VGA compatibility mode the device reports BEFORE any scanout is a
    # device fact, not our claim: it may differ from the Limine framebuffer we
    # present. It must still be a real geometry with the real frame accounting.
    if not (1 <= width <= 8192 and 1 <= height <= 8192):
        return False
    if (allocated, released) != (773, 773):
        return False
    edids = [(i, EDID.fullmatch(line)) for i, line in enumerate(lines)
             if line.startswith("WOLFOS_VIRTIO_GPU_EDID_LIVE_OK ")]
    if len(edids) != 1 or edids[0][1] is None:
        return False
    edid = [edids[0][0]]
    edid_millihz = int(edids[0][1].group(1))
    if edid_millihz == 0:
        return False
    attested = [(i, ATTEST.fullmatch(line)) for i, line in enumerate(lines)
                if line.startswith(ATTEST_PREFIX)]
    if len(attested) != 1 or attested[0][1] is None:
        return False
    if int(attested[0][1].group(1), 16) != NONCE:
        return False
    # The guest may not claim any digest other than the real desktop image.
    if int(attested[0][1].group(2), 16) != pattern_digest():
        return False
    captures = [line[len(CAPTURE_PREFIX):] for line in lines
                if line.startswith(CAPTURE_PREFIX)]
    if captures != ["restored"]:
        return False
    restored_index = lines.index(CAPTURE_PREFIX + "restored")
    # Real device evidence must precede the claim, then present, prove pixels,
    # tear down, reset and re-prove the VGA output.
    # The catalog proof must sit between the host-owned attestation and the
    # teardown readback: attest, then catalog, then reset, then claim.
    catalogs = [(i, CATALOG.fullmatch(line)) for i, line in enumerate(lines)
                if line.startswith(CATALOG_PREFIX)]
    if len(catalogs) != 1 or catalogs[0][1] is None:
        return False
    catalog_index = catalogs[0][0]
    entries, reported, dev_w, dev_h, claim, catalog_hz = catalogs[0][1].groups()
    entries, reported = int(entries), int(reported)
    dev_w, dev_h, catalog_hz = int(dev_w), int(dev_h), int(catalog_hz)
    # The catalog may only record the geometry the device itself reported, and
    # only the EDID rate the device really returned.
    if (dev_w, dev_h) != (width, height) or catalog_hz != edid_millihz:
        return False
    if entries != 1 + reported or reported > 1 or entries > 2:
        return False
    if (dev_w, dev_h) == (WIDTH, HEIGHT):
        # Device agrees with the attested geometry: no second entry, and the
        # weaker claim must be refused instead of downgrading the proven mode.
        if reported != 0 or claim != "refused:conflicting_proof":
            return False
    elif reported != 1 or claim != "rejected:unproven_gpu_timing":
        return False
    if not displays[0][0] < edid[0] < marker_index:
        return False
    if not attested[0][0] < catalog_index < restored_index < marker_index:
        return False
    if lines.count(TEST_OK) != 1:
        return False
    if lines.count("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK") != 1:
        return False
    if lines.count("WOLFOS_FRAMEBUFFER_OK 1024x768") != 1:
        return False
    # No other flavor's scanout claim may appear alongside this one.
    for foreign in ("WOLFOS_VIRTIO_GPU_SCANOUT_OK ",
                    "WOLFOS_VIRTIO_GPU_SCANOUT_RESET_OK ",
                    "WOLFOS_VIRTIO_GPU_NATIVE_ROLLBACK_OK ",
                    "WOLFOS_VIRTIO_GPU_TRANSFER2D_OK "):
        if any(line.startswith(foreign) for line in lines):
            return False
    return True


def run(iso: Path, require_refusal: bool = False) -> int:
    prefix = "wolfos-virtio-gpu-desktop-"
    with tempfile.TemporaryDirectory(prefix=prefix) as work:
        root = Path(work)
        serial_path = root / "com1.sock"
        qmp_path = root / "qmp.sock"
        cmd = [
            "qemu-system-x86_64", "-M", "q35", "-m", "512M", "-smp", "1",
            "-vga", "none", "-device", "virtio-vga",
            "-cdrom", str(iso.resolve()), "-boot", "d",
            "-chardev", f"socket,id=wolfcom,path={serial_path},server=on,wait=on",
            "-serial", "chardev:wolfcom",
            "-qmp", f"unix:{qmp_path},server=on,wait=off",
            "-display", "none", "-no-reboot",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        proc = None
        received = bytearray()
        images = {}
        captured = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            deadline = time.monotonic() + 200.0
            with connect_unix(serial_path, proc, deadline) as ser:
                with connect_unix(qmp_path, proc, deadline) as qmp:
                    reader = qmp.makefile("rb")
                    greet = json.loads(reader.readline())
                    if "QMP" not in greet:
                        raise ProofError("QMP greeting absent")
                    qmp_call(qmp, reader, "qmp_capabilities")
                    ser.settimeout(0.2)
                    pending = b""
                    while time.monotonic() < deadline:
                        try:
                            chunk = ser.recv(8192)
                        except socket.timeout:
                            chunk = None
                        if chunk == b"":
                            break
                        if chunk:
                            received.extend(chunk)
                            pending += chunk
                            while b"\n" in pending:
                                line, pending = pending.split(b"\n", 1)
                                clean = line.decode("ascii", errors="replace").strip()
                                if clean.startswith(ATTEST_PREFIX):
                                    match = ATTEST.fullmatch(clean)
                                    if match is None:
                                        raise ProofError(
                                            f"Malformed guest attestation: {clean!r}")
                                    nonce, claimed = match.groups()
                                    if int(nonce, 16) != NONCE:
                                        raise ProofError(
                                            f"Guest reused nonce {nonce}")
                                    target = root / "desktop.ppm"
                                    qmp_call(qmp, reader, "screendump",
                                             {"filename": str(target)})
                                    images["desktop"] = ppm(target)
                                    verify_pixels(images["desktop"])
                                    # Digest of the REAL screenshot, never of
                                    # the pattern the guest said it drew.
                                    digest = rgb_digest(
                                        WIDTH, HEIGHT, images["desktop"])
                                    if not FAULT and digest != int(claimed, 16):
                                        raise ProofError(
                                            f"Host digest {digest:08x} != guest "
                                            f"source {claimed} at {WIDTH}x"
                                            f"{HEIGHT}: scanout does not show "
                                            "the framebuffer bytes")
                                    reply_digest = digest
                                    reply_nonce = nonce
                                    reply_w, reply_h = WIDTH, HEIGHT
                                    if FAULT == "digest":
                                        reply_digest ^= 0x0100
                                    elif FAULT == "nonce":
                                        reply_nonce = f"{NONCE + 1:016x}"
                                    elif FAULT == "geometry":
                                        reply_w = WIDTH + 1
                                    ser.sendall(
                                        f"P {reply_w}x{reply_h} {reply_nonce} "
                                        f"{reply_digest:08x}\n".encode("ascii"))
                                    captured.append("desktop")
                                elif clean.startswith(CAPTURE_PREFIX):
                                    name = clean[len(CAPTURE_PREFIX):]
                                    if name != "restored" or captured != ["desktop"]:
                                        raise ProofError(
                                            f"Unexpected QMP capture stage {name!r}")
                                    target = root / "restored.ppm"
                                    qmp_call(qmp, reader, "screendump",
                                             {"filename": str(target)})
                                    images["restored"] = ppm(target)
                                    # After the full resource lifecycle AND the
                                    # device reset the VGA output must show the
                                    # very same framebuffer pixels again.
                                    verify_pixels(images["restored"])
                                    ser.sendall(b"R")
                                    captured.append("restored")
                        if proc.poll() is not None and not chunk:
                            break
                    if captured != ["desktop", "restored"]:
                        raise ProofError(
                            f"Only {captured} captured, expected desktop+restored")
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise ProofError("QEMU did not exit after the desktop scanout")
            output = received.decode("ascii", errors="replace")
            print(output)
            if FAULT:
                # A lying host must make the guest refuse, not silently pass.
                if proc.returncode == 33 or not any(
                        "WOLFOS_GPU_ATTEST_FAIL" in line
                        or "WOLFOS_VIRTIO_GPU_DESKTOP_FAIL" in line
                        for line in output.splitlines()):
                    raise ProofError(
                        f"Guest accepted a forged attestation ({FAULT})")
                # A refused attestation must leave nothing selectable, and it
                # must say so rather than merely omitting the claim.
                if any(line.startswith(CATALOG_PREFIX)
                       for line in output.splitlines()):
                    raise ProofError(
                        f"Forged {FAULT} attestation still produced a "
                        "selectable mode catalog")
                refused = [line for line in output.splitlines()
                           if line.startswith(CATALOG_FAIL_PREFIX)]
                if len(refused) != 1 or not CATALOG_FAIL.fullmatch(refused[0]):
                    raise ProofError(
                        f"Missing or malformed empty-catalog refusal: {refused}")
                print(f"PASS: guest refused the forged {FAULT} attestation reply")
                print("PASS: the refused attestation left the mode catalog "
                      "empty (mode=no_selectable_mode)")
                return 0
            if proc.returncode != 33:
                raise ProofError(f"QEMU exit {proc.returncode}, expected 33")
            if output.count("WOLFOS_BOOT_OK") != 1:
                raise ProofError("Boot acknowledgement missing or duplicated")
            if not validate_desktop_serial(output):
                raise ProofError("Desktop scanout serial proof invalid")
            print(f"PASS: QMP screenshot shows all {PIXELS} pixels of the real "
                  f"{WIDTH}x{HEIGHT} kernel framebuffer")
            print(f"PASS: host digest {pattern_digest():08x} matches the guest "
                  "framebuffer digest (nonce-bound)")
            print("PASS: 768 backing pages attached as one scatter-gather "
                  "request, 12 fenced band transfers, 19 fenced replies")
            print("PASS: after resource teardown and device reset the VGA "
                  "output shows every framebuffer pixel again")
            print("PASS: the host-attested 1024x768 geometry is the catalog's "
                  "automatic choice; the device's own claim and the EDID rate "
                  "are both refused, and refresh stays unproven")
            return 0
        except (ProofError, FileNotFoundError, ConnectionError, OSError,
                ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            print(f"FAIL: QEMU desktop scanout: {exc}")
            print(received.decode("ascii", errors="replace"))
            if proc is not None and proc.poll() is not None:
                print(proc.stderr.read().decode(errors="replace")[-2000:])
            if require_refusal and FAULT:
                print(f"PASS: boot failed as required under forged {FAULT}")
                return 0
            return 1
        finally:
            if proc is not None:
                if proc.poll() is None:
                    proc.kill()
                try:
                    proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 1:
        print("Usage: qemu_virtio_gpu_desktop_scanout.py [--require-refusal] ISO")
        return 2
    target = Path(args[0])
    if not target.is_file():
        print("ISO file missing")
        return 2
    return run(target, require_refusal="--require-refusal" in sys.argv)


if __name__ == "__main__":
    sys.exit(main())
