#!/usr/bin/env python3
"""Real QEMU proof of a transactional, host-attested display mode change.

The guest paints its real Limine framebuffer, copies every row into 768
exclusively owned backing pages, attaches them as ONE scatter-gather request
and presents the resource as a native scanout. It then discovers a *second*
real geometry (1024x384) from the same resource and runs one transactional
mode change back to 1024x768: plan, apply, device readback, and the user's
verdict.

The host owns every pixel claim:

* each stage is a nonce-bound digest challenge answered from a real QMP
  screenshot, never from a pattern the guest only says it drew;
* the applied-mode stage answers `X <elapsed_ms>` when the user confirmed or
  `E <elapsed_ms>` when they did not, so the guest's own state machine grades
  the elapsed time instead of trusting the verdict;
* a refused or expired change must really restore the previous mode, and that
  restoration must again match a host screenshot byte for byte.

`WOLFOS_DESKTOP_FAULT` selects a deliberate lie:

* `digest`, `nonce`, `geometry` corrupt one field of the FIRST reply;
* `mode_early` claims the window expired after 1 s (it did not);
* `mode_expired` really waits past the 15 s window and then reports it, so the
  change must be rolled back and the restored frame re-verified.
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
ALT_WIDTH = 1024
ALT_HEIGHT = 384
PIXELS = WIDTH * HEIGHT
ALT_PIXELS = ALT_WIDTH * ALT_HEIGHT
WINDOW_MS = 15_000
# The real wait must exceed the window by a margin a scheduler cannot fake.
EXPIRED_WAIT_S = 15.2

# stage token -> (serial stage name, geometry, nonce)
STAGES = {
    "P": ("desktop", (WIDTH, HEIGHT), 0x574F4445534B0004),
    "S": ("reduced", (ALT_WIDTH, ALT_HEIGHT), 0x574F4445534B0005),
    "T": ("applied", (WIDTH, HEIGHT), 0x574F4445534B0006),
    "R": ("rollback", (ALT_WIDTH, ALT_HEIGHT), 0x574F4445534B0007),
}
BY_NAME = {name: (token, geometry, nonce)
           for token, (name, geometry, nonce) in STAGES.items()}
ATTEST_PREFIX = "WOLFOS_GPU_STAGE_ATTEST "
ATTEST = re.compile(
    r"WOLFOS_GPU_STAGE_ATTEST stage=(desktop|reduced|applied|rollback) "
    r"geometry=(\d+)x(\d+) nonce=([0-9a-f]{16}) source_digest=([0-9a-f]{8})")
CAPTURE_PREFIX = "WOLFOS_VIRTIO_GPU_SCANOUT_CAPTURE stage="
CATALOG_PREFIX = "WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_OK "
CATALOG_FAIL_PREFIX = "WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_FAIL "
CATALOG = re.compile(
    r"WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_OK generation=1 entries=3 "
    r"selectable=2 attested=2 device_reported=(\d+) device_width=(\d+) "
    r"device_height=(\d+) selected=1024x768 selected_refresh=unavailable "
    r"second=1024x384 "
    r"device_claim=(rejected:unproven_gpu_timing|refused:conflicting_proof) "
    r"edid_millihz=(\d+) edid_hz_request=rejected:refresh_not_programmable "
    r"applied_change_plan=none unattested_catalog=rejected:no_selectable_mode "
    r"gpu_commands_sent=0")
CATALOG_FAIL = re.compile(
    r"WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_FAIL stage=\w+ entries=0 "
    r"selectable=0 mode=no_selectable_mode")
TX_PREFIX = "WOLFOS_VIRTIO_GPU_MODE_TX_OK "
TX = re.compile(
    r"WOLFOS_VIRTIO_GPU_MODE_TX_OK generation=1 token=574f4c4654580001 "
    r"from=1024x384 to=1024x768 deadline_ms=(\d+) verdict_elapsed_ms=(\d+) "
    r"readback=console_enabled state=(confirmed|rolled_back) "
    r"outcome=(confirmed|rolled_back) "
    r"restore=(unused|verified) window_enforced_by=host "
    r"host_pixels_verified_by_kernel=0")
TX_FAIL = re.compile(
    r"WOLFOS_VIRTIO_GPU_MODE_TX_FAIL stage=(deadline_not_reached|"
    r"confirmation_expired|device_did_not_apply|confirmation_unverified) "
    r"state=(pending|rolling_back)( elapsed_ms=\d+)?")
MARKER = re.compile(
    r"WOLFOS_VIRTIO_GPU_DESKTOP_SCANOUT_OK resource_id=1 width=1024 "
    r"height=768 format=2 create_type=257 attach_type=262 transfer_type=261 "
    r"set_type=259 flush_type=260 clear_type=259 detach_type=263 "
    r"unref_type=258 response_type=4352 used_idx=(\d+) used_head=0 used_len=24 "
    r"fences_verified=(\d+) notify_writes=(\d+) backing_entries=(\d+) "
    r"backing_bytes=3145728 transfer_bands=12 band_rows=64 alt=1024x384 "
    r"alt_bands=6 pixels=786432 guest_copy_verified=1 "
    r"host_pixels_verified_by_kernel=0 capture_acks=(\d+) reset_to_vga_ack=1 "
    r"reset=0 queue_disabled=1 frames_allocated=773 frames_released=773 "
    r"pmm_leak=0 qemu_only=1")
DISPLAY = re.compile(
    r"WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK req=256 resp=4353 used_idx=1 "
    r"used_head=0 used_len=408 scanout0_enabled=1 width=(\d+) height=(\d+) "
    r"notify_writes=1 driver_ok=15 reset=0 queue_disabled=1 "
    r"frames_allocated=(\d+) frames_released=(\d+) response_dma_verified=1 "
    r"pmm_leak=0 qemu_only=1")
EDID = re.compile(
    r"WOLFOS_VIRTIO_GPU_EDID_LIVE_OK scanout=0 edid_size=\d+ modes=\d+ "
    r"preferred_width=\d+ preferred_height=\d+ refresh_millihz=(\d+) .*")
TEST_OK = "WOLFOS_VIRTIO_GPU_SCANOUT_TEST_OK"
FAULT = os.environ.get("WOLFOS_DESKTOP_FAULT", "")
ATTEST_FAULTS = ("digest", "nonce", "geometry")


def expected_rgb(x: int, y: int) -> tuple[int, int, int]:
    """Mirror of `virtio_gpu_desktop_wire::pixel_rgb`."""
    return ((x * 3 + y * 7 + 29) & 0xFF,
            (x * 11 + y * 5 + 71) & 0xFF,
            (x * 13 + y * 17 + 173) & 0xFF)


def alt_rgb(x: int, y: int) -> tuple[int, int, int]:
    """Mirror of `virtio_gpu_desktop_wire::alt_pixel_rgb`."""
    return (255 - ((x * 5 + y * 3 + 11) & 0xFF),
            ((x * 7 + y * 9 + 53) & 0xFF) ^ 0x5A,
            ((x ^ y) * 3 + 97) & 0xFF)


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
def restored_bytes_expired() -> bytes:
    """What VRAM holds after a verified rollback to 1024x384.

    Only rows 0..383 were repainted by the reduced mode, so the post-reset VGA
    output shows the reduced image on top and the untouched desktop rows below.
    """
    desktop = bytearray(expected_bytes())
    alt = alt_bytes()
    desktop[:len(alt)] = alt
    return bytes(desktop)


@lru_cache(maxsize=1)
def alt_bytes() -> bytes:
    """The complete 1024x384 image of the second geometry."""
    out = bytearray(ALT_PIXELS * 3)
    index = 0
    for y in range(ALT_HEIGHT):
        for x in range(ALT_WIDTH):
            r, g, b = alt_rgb(x, y)
            out[index] = r
            out[index + 1] = g
            out[index + 2] = b
            index += 3
    return bytes(out)


def _digest(payload: bytes) -> int:
    value = 0x811C9DC5
    for byte in payload:
        value ^= byte
        value = (value * 0x01000193) & 0xFFFFFFFF
    return value


@lru_cache(maxsize=1)
def pattern_digest() -> int:
    """FNV-1a the guest must claim for the desktop image (known offline)."""
    return _digest(expected_bytes())


@lru_cache(maxsize=1)
def alt_pattern_digest() -> int:
    return _digest(alt_bytes())


def _verify(image: tuple[int, int, bytes], geometry: tuple[int, int],
            payload: bytes, label: str) -> int:
    width, height, rgb = image
    if (width, height) != geometry:
        raise ProofError(
            f"QMP geometry {width}x{height} at {label}, expected "
            f"{geometry[0]}x{geometry[1]}")
    if len(rgb) != len(payload):
        raise ProofError(
            f"QMP pixel buffer {len(rgb)} bytes at {label}, expected {len(payload)}")
    if rgb != payload:
        first = next(i for i, (got, want) in enumerate(zip(rgb, payload))
                     if got != want)
        px = first // 3
        raise ProofError(
            f"Host QMP pixel mismatch at {label} "
            f"({px % width},{px // width}) channel={first % 3} "
            f"got={rgb[first]} want={payload[first]}")
    return width * height


def verify_pixels(image: tuple[int, int, bytes]) -> int:
    """Every pixel of the real 1024x768 desktop image must match."""
    return _verify(image, (WIDTH, HEIGHT), expected_bytes(), "desktop")


def verify_restored_pixels(image: tuple[int, int, bytes],
                           expired: bool) -> int:
    """The post-reset frame must be exactly what the driver last painted."""
    payload = restored_bytes_expired() if expired else expected_bytes()
    return _verify(image, (WIDTH, HEIGHT), payload, "restored")


def verify_alt_pixels(image: tuple[int, int, bytes]) -> int:
    """Every pixel of the real 1024x384 image must match."""
    return _verify(image, (ALT_WIDTH, ALT_HEIGHT), alt_bytes(), "reduced")


def validate_desktop_serial(output: str, expired: bool = False) -> bool:
    """Host-owned serial contract for the desktop scanout flavor."""
    lines = output.splitlines()
    if any(line.startswith((
        "WOLFOS_VIRTIO_GPU_DESKTOP_FAIL", "WOLFOS_GPU_ATTEST_FAIL",
        "WOLFOS_VIRTIO_GPU_DESKTOP_CATALOG_FAIL",
        "WOLFOS_VIRTIO_GPU_MODE_TX_FAIL",
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
    used_idx, fences, writes, entries, capture_acks = map(int, markers[0].groups())
    # 1 x GET_DISPLAY_INFO, 1 x GET_EDID, then the desktop resource work. The
    # expired path adds one extra switch+restore cycle of exactly 8 commands.
    expected_idx = 46 if expired else 38
    if (used_idx, writes) != (expected_idx, expected_idx) or fences != expected_idx - 2:
        return False
    if not 1 <= entries <= 254:
        return False
    if capture_acks != (4 if expired else 3):
        return False
    displays = [(i, DISPLAY.fullmatch(line)) for i, line in enumerate(lines)
                if line.startswith("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK ")]
    if len(displays) != 1 or displays[0][1] is None:
        return False
    width, height, allocated, released = map(int, displays[0][1].groups())
    if not (1 <= width <= 8192 and 1 <= height <= 8192):
        return False
    if (allocated, released) != (773, 773):
        return False
    edids = [(i, EDID.fullmatch(line)) for i, line in enumerate(lines)
             if line.startswith("WOLFOS_VIRTIO_GPU_EDID_LIVE_OK ")]
    if len(edids) != 1 or edids[0][1] is None:
        return False
    edid_index = edids[0][0]
    edid_millihz = int(edids[0][1].group(1))
    if edid_millihz == 0:
        return False
    # Exactly one challenge per real stage, in the order the driver performs
    # them: present desktop, discover the second geometry, then act on the
    # user's verdict (plus the verified restoration when the window elapsed).
    attested = []
    for index, line in enumerate(lines):
        if not line.startswith(ATTEST_PREFIX):
            continue
        match = ATTEST.fullmatch(line)
        if match is None:
            return False
        attested.append((index, match))
    wanted = ["desktop", "reduced", "applied", "rollback"] if expired else \
             ["desktop", "reduced", "applied"]
    if [match.group(1) for _, match in attested] != wanted:
        return False
    for _, match in attested:
        stage = match.group(1)
        token, geometry, nonce = BY_NAME[stage]
        if (int(match.group(2)), int(match.group(3))) != geometry:
            return False
        if int(match.group(4), 16) != nonce:
            return False
        digest = int(match.group(5), 16)
        if digest != (alt_pattern_digest() if stage in ("reduced", "rollback")
                      else pattern_digest()):
            return False
    captures = [line[len(CAPTURE_PREFIX):] for line in lines
                if line.startswith(CAPTURE_PREFIX)]
    if captures != ["restored"]:
        return False
    restored_index = lines.index(CAPTURE_PREFIX + "restored")
    catalogs = [(i, CATALOG.fullmatch(line)) for i, line in enumerate(lines)
                if line.startswith(CATALOG_PREFIX)]
    if len(catalogs) != 1 or catalogs[0][1] is None:
        return False
    catalog_index = catalogs[0][0]
    (reported, dev_w, dev_h, claim, catalog_hz) = catalogs[0][1].groups()
    reported, dev_w, dev_h, catalog_hz = (int(reported), int(dev_w),
                                          int(dev_h), int(catalog_hz))
    if (dev_w, dev_h) != (width, height) or catalog_hz != edid_millihz:
        return False
    # Two proven geometries, one device-reported claim that must stay refused.
    if (dev_w, dev_h) == (WIDTH, HEIGHT):
        if reported != 0 or claim != "refused:conflicting_proof":
            return False
    elif reported != 1 or claim != "rejected:unproven_gpu_timing":
        return False
    txs = [(i, TX.fullmatch(line)) for i, line in enumerate(lines)
           if line.startswith(TX_PREFIX)]
    if len(txs) != 1 or txs[0][1] is None:
        return False
    tx_index = txs[0][0]
    deadline, elapsed, state, outcome, restore = txs[0][1].groups()
    deadline, elapsed = int(deadline), int(elapsed)
    if deadline != WINDOW_MS:
        return False
    if expired:
        if (state, outcome, restore) != ("rolled_back", "rolled_back", "verified"):
            return False
        # The guest may only roll back on a real elapsed window.
        if elapsed < WINDOW_MS or elapsed > 60_000:
            return False
    else:
        if (state, outcome, restore) != ("confirmed", "confirmed", "unused"):
            return False
        if elapsed >= WINDOW_MS:
            return False
    # The display/EDID summary lines are printed at the end of the boot, so the
    # ordering that matters is the proof chain itself: the catalog may only
    # follow the attestations it consumes, the verdict only the catalog, and the
    # post-reset capture only the last attestation.
    if not attested[0][0] < catalog_index < tx_index:
        return False
    if len(attested) > 1 and not attested[1][0] < catalog_index:
        return False
    if not attested[-1][0] < restored_index < marker_index:
        return False
    if not displays[0][0] < edid_index < marker_index:
        return False
    if lines.count(TEST_OK) != 1:
        return False
    if lines.count("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK") != 1:
        return False
    if lines.count("WOLFOS_FRAMEBUFFER_OK 1024x768") != 1:
        return False
    for foreign in ("WOLFOS_VIRTIO_GPU_SCANOUT_OK ",
                    "WOLFOS_VIRTIO_GPU_SCANOUT_RESET_OK ",
                    "WOLFOS_VIRTIO_GPU_NATIVE_ROLLBACK_OK ",
                    "WOLFOS_VIRTIO_GPU_TRANSFER2D_OK "):
        if any(line.startswith(foreign) for line in lines):
            return False
    return True


def _capture(qmp, reader, root: Path, name: str):
    target = root / f"{name}.ppm"
    qmp_call(qmp, reader, "screendump", {"filename": str(target)})
    return ppm(target)


def _reply(ser, token: str, geometry: tuple[int, int], nonce: int, digest: int,
           fault: str) -> None:
    """Answer one stage. Only the FIRST stage can be corrupted by the
    attestation faults, so later stages still exercise the honest path."""
    w, h = geometry
    reply_nonce, reply_digest, reply_w, reply_h = nonce, digest, w, h
    if token == "P":
        if fault == "digest":
            reply_digest ^= 0x0100
        elif fault == "nonce":
            reply_nonce = nonce + 1
        elif fault == "geometry":
            reply_w = w + 1
    ser.sendall(f"{token} {reply_w}x{reply_h} {reply_nonce:016x} "
                f"{reply_digest:08x}\n".encode("ascii"))


def run(iso: Path, require_refusal: bool = False) -> int:
    prefix = "wolfos-virtio-gpu-desktop-"
    expired = FAULT == "mode_expired"
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
        measured = {}
        saw_refusal = False
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            deadline = time.monotonic() + 420.0
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
                                if clean.startswith(
                                        "WOLFOS_VIRTIO_GPU_MODE_TX_FAIL"):
                                    saw_refusal = True
                                if clean.startswith(ATTEST_PREFIX):
                                    match = ATTEST.fullmatch(clean)
                                    if match is None:
                                        raise ProofError(
                                            f"Malformed guest attestation: {clean!r}")
                                    stage = match.group(1)
                                    token, geometry, nonce = BY_NAME[stage]
                                    if (int(match.group(2)), int(match.group(3))) != geometry:
                                        raise ProofError(
                                            f"Stage {stage} geometry mismatch")
                                    if int(match.group(4), 16) != nonce:
                                        raise ProofError(
                                            f"Stage {stage} reused a nonce")
                                    claimed = int(match.group(5), 16)
                                    image = _capture(qmp, reader, root, stage)
                                    if stage in ("reduced", "rollback"):
                                        verify_alt_pixels(image)
                                    else:
                                        verify_pixels(image)
                                    images[stage] = image
                                    digest = rgb_digest(*geometry, image)
                                    if not FAULT and digest != claimed:
                                        raise ProofError(
                                            f"Host digest {digest:08x} != guest "
                                            f"source {claimed} at stage {stage}")
                                    if stage == "applied":
                                        start = time.monotonic()
                                        if FAULT == "mode_early":
                                            # A peer may not shorten the window.
                                            ser.sendall(b"E 1000\n")
                                        elif expired:
                                            time.sleep(max(
                                                0.0, EXPIRED_WAIT_S -
                                                (time.monotonic() - start)))
                                            measured["window_s"] = (
                                                time.monotonic() - start)
                                            ser.sendall(
                                                f"E {int(measured['window_s']*1000)}\n"
                                                .encode("ascii"))
                                        else:
                                            elapsed = int(
                                                (time.monotonic() - start) * 1000)
                                            measured["window_s"] = elapsed / 1000.0
                                            ser.sendall(f"X {elapsed}\n".encode("ascii"))
                                            _reply(ser, token, geometry, nonce,
                                                   digest, FAULT)
                                    else:
                                        _reply(ser, token, geometry, nonce, digest,
                                               FAULT)
                                    captured.append(stage)
                                elif clean.startswith(CAPTURE_PREFIX):
                                    name = clean[len(CAPTURE_PREFIX):]
                                    if name != "restored" or captured[-1:] != ["applied"] \
                                            and captured[-1:] != ["rollback"]:
                                        raise ProofError(
                                            f"Unexpected QMP capture stage {name!r} "
                                            f"after {captured}")
                                    image = _capture(qmp, reader, root, "restored")
                                    images["restored"] = image
                                    # After the full resource lifecycle AND the
                                    # device reset the VGA output must show the
                                    # very framebuffer bytes the driver last
                                    # painted -- which is the reduced frame on
                                    # top when the change was rolled back.
                                    verify_restored_pixels(image, expired)
                                    ser.sendall(b"R")
                                    captured.append("restored")
                        if proc.poll() is not None and not chunk:
                            break
                        if FAULT == "mode_early" and len(captured) == 3 and saw_refusal:
                            # The refused change halts the guest without a
                            # teardown, so there is nothing left to observe --
                            # but only after the refusal itself was read.
                            break
                    if expired:
                        expected = ["desktop", "reduced", "applied", "rollback",
                                    "restored"]
                    elif FAULT == "mode_early":
                        # The refused change never settles, so no teardown and
                        # no post-reset capture may appear.
                        expected = ["desktop", "reduced", "applied"]
                    else:
                        expected = ["desktop", "reduced", "applied", "restored"]
                    if FAULT not in ATTEST_FAULTS and captured != expected:
                        raise ProofError(
                            f"Stages {captured} captured, expected {expected}")
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if FAULT == "mode_early":
                    # The guest refuses the shortened window, prints the refusal
                    # and halts instead of claiming success, so QEMU stays up.
                    proc.kill()
                    proc.wait(timeout=5)
                else:
                    raise ProofError("QEMU did not exit after the desktop scanout")
            output = received.decode("ascii", errors="replace")
            print(output)
            if FAULT in ATTEST_FAULTS:
                if proc.returncode == 33 or not any(
                        "WOLFOS_GPU_ATTEST_FAIL" in line
                        or "WOLFOS_VIRTIO_GPU_DESKTOP_FAIL" in line
                        for line in output.splitlines()):
                    raise ProofError(
                        f"Guest accepted a forged attestation ({FAULT})")
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
            if FAULT == "mode_early":
                # A peer may not shorten the window: the guest must keep the
                # transaction open and say so.
                fails = [line for line in output.splitlines()
                         if line.startswith("WOLFOS_VIRTIO_GPU_MODE_TX_FAIL")]
                if len(fails) != 1 or not TX_FAIL.fullmatch(fails[0]):
                    raise ProofError(f"Early expiry not refused: {fails}")
                if "deadline_not_reached" not in fails[0]:
                    raise ProofError(f"Wrong early-expiry refusal: {fails}")
                if any(line.startswith(TX_PREFIX) for line in output.splitlines()):
                    raise ProofError("An early expiry still settled the change")
                print("PASS: the guest refused a claimed 1 s expiry "
                      "(deadline_not_reached) and left the change pending")
                return 0
            if proc.returncode != 33:
                raise ProofError(f"QEMU exit {proc.returncode}, expected 33")
            if output.count("WOLFOS_BOOT_OK") != 1:
                raise ProofError("Boot acknowledgement missing or duplicated")
            if not validate_desktop_serial(output, expired):
                raise ProofError("Desktop scanout serial proof invalid")
            print(f"PASS: QMP screenshots show all {PIXELS} pixels of the real "
                  f"{WIDTH}x{HEIGHT} framebuffer and all {ALT_PIXELS} pixels of "
                  f"the {ALT_WIDTH}x{ALT_HEIGHT} scanout")
            print(f"PASS: host digests {pattern_digest():08x} and "
                  f"{alt_pattern_digest():08x} match the guest's own framebuffer "
                  "digests (nonce-bound)")
            if expired:
                print(f"PASS: after a real {measured.get('window_s', 0):.2f} s "
                      "window the guest rolled back, and the restored "
                      f"{ALT_WIDTH}x{ALT_HEIGHT} image matches the host capture "
                      "byte for byte")
            else:
                print("PASS: the host-attested 1024x768 observation confirmed "
                      "the change inside the window; the catalog keeps both "
                      "proven geometries and refuses the device claim")
            print("PASS: after resource teardown and device reset the VGA "
                  "output shows every framebuffer pixel again")
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
