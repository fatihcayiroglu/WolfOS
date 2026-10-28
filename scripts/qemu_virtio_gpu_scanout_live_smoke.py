#!/usr/bin/env python3
"""Real QEMU VirtIO-GPU SET_SCANOUT/FLUSH pixel screenshot and rollback gate.

QMP screenshots are taken only on guest COM1 stage handshakes. The guest
cannot finish unless the host captures baseline, active and restored screens.
No physical GPU, guest disk image writes or GUI backend.
"""
from pathlib import Path
import json
import socket
import subprocess
import sys
import tempfile
import time

from qemu_virtio_gpu_pci_smoke import validate as validate_gpu, DISPLAY_INFO_NINE
from qemu_virtio_gpu_edid_live_smoke import validate_edid_marker

MARKER = (
    "WOLFOS_VIRTIO_GPU_SCANOUT_OK resource_id=1 format=2 width=64 height=64 "
    "create_type=257 attach_type=262 transfer_type=261 set_type=259 "
    "flush_type=260 clear_type=259 detach_type=263 unref_type=258 "
    "response_type=4352 used_idx=10 used_head=0 used_len=24 "
    "fences_verified=8 notify_writes=10 backing_entries=4 backing_bytes=16384 "
    "guest_pattern_verified=2 set_ack=1 flush_ack=1 clear_ack=1 "
    "detach_ack=1 unref_ack=1 capture_acks=3 host_pixels_verified_by_kernel=0 "
    "reset=0 queue_disabled=1 frames_allocated=9 frames_released=9 "
    "pmm_leak=0 qemu_only=1"
)
PREFIX="WOLFOS_VIRTIO_GPU_SCANOUT_CAPTURE stage="
STAGES=("baseline","active","restored")
RELEASE={"baseline":b"B","active":b"A","restored":b"R"}
TEST_OK="WOLFOS_VIRTIO_GPU_SCANOUT_TEST_OK"

class ProofError(Exception):
    pass

def validate_serial(output: str) -> bool:
    lines=output.splitlines()
    if any("WOLFOS_VIRTIO_GPU_SCANOUT_FAIL" in l
           or "WOLFOS_VIRTIO_GPU_RESOURCE2D_FAIL" in l
           or "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL" in l for l in lines):
        return False
    if not validate_edid_marker(output,frame_count=9):
        return False
    displays=[DISPLAY_INFO_NINE.fullmatch(l) for l in lines
              if l.startswith("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK ")]
    if len(displays)!=1 or displays[0] is None:
        return False
    marker=[i for i,l in enumerate(lines) if l.startswith("WOLFOS_VIRTIO_GPU_SCANOUT_OK ")]
    if len(marker)!=1 or lines[marker[0]]!=MARKER or lines.count(TEST_OK)!=1:
        return False
    stages=[(i,l[len(PREFIX):]) for i,l in enumerate(lines) if l.startswith(PREFIX)]
    if [x[1] for x in stages]!=list(STAGES):
        return False
    edid=[i for i,l in enumerate(lines)
          if l.startswith("WOLFOS_VIRTIO_GPU_EDID_LIVE_OK ")]
    display_ack=[i for i,l in enumerate(lines)
                 if l=="WOLFOS_VIRTIO_GPU_DISPLAY_INFO_TEST_OK"]
    edid_ack=[i for i,l in enumerate(lines)
              if l=="WOLFOS_VIRTIO_GPU_EDID_LIVE_TEST_OK"]
    if len(edid)!=1 or len(display_ack)!=1 or len(edid_ack)!=1:
        return False
    forbidden=("WOLFOS_VIRTIO_GPU_RESOURCE2D_OK ",
               "WOLFOS_VIRTIO_GPU_ATTACH_BACKING_OK ",
               "WOLFOS_VIRTIO_GPU_TRANSFER2D_OK ")
    if any(l.startswith(forbidden) or l in (
        "WOLFOS_VIRTIO_GPU_RESOURCE2D_TEST_OK",
        "WOLFOS_VIRTIO_GPU_ATTACH_BACKING_TEST_OK",
        "WOLFOS_VIRTIO_GPU_TRANSFER2D_TEST_OK") for l in lines):
        return False
    return (stages[0][0]<stages[1][0]<stages[2][0]<
            lines.index(next(l for l in lines if l.startswith("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK ")))<
            edid[0]<marker[0]<display_ack[0]<edid_ack[0]<lines.index(TEST_OK))

def connect_unix(path:Path,proc:subprocess.Popen,deadline:float)->socket.socket:
    while time.monotonic()<deadline:
        if proc.poll() is not None:
            raise ProofError("QEMU exited before Unix monitor/COM1 handshake")
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        try:
            sock.connect(str(path))
            sock.settimeout(5.0)
            return sock
        except (FileNotFoundError,ConnectionRefusedError,OSError):
            sock.close()
            time.sleep(0.05)
    raise ProofError("QEMU Unix socket connection timeout")

def qmp_call(sock:socket.socket,reader,command:str,args=None)->None:
    req={"execute":command}
    if args is not None:
        req["arguments"]=args
    sock.sendall((json.dumps(req)+"\n").encode("ascii"))
    for _ in range(40):
        line=reader.readline()
        if not line:
            raise ProofError("QMP disconnected during "+command)
        reply=json.loads(line)
        if "error" in reply:
            raise ProofError("QMP "+command+" rejected: "+str(reply["error"]))
        if "return" in reply:
            return
    raise ProofError("QMP did not return for "+command)

def ppm(path:Path)->tuple[int,int,bytes]:
    with path.open("rb") as f:
        if f.readline().strip()!=b"P6":
            raise ProofError("QMP screenshot is not binary PPM/P6")
        def header():
            line=f.readline()
            while line.startswith(b"#"):
                line=f.readline()
            return line
        parts=header().split()
        if len(parts)!=2:
            raise ProofError("Invalid PPM dimensions")
        width,height=map(int,parts)
        if not (1<=width<=8192 and 1<=height<=8192):
            raise ProofError("Unsafe PPM dimensions")
        if header().strip()!=b"255":
            raise ProofError("Unexpected PPM sample depth")
        pixels=f.read()
    if len(pixels)!=3*width*height:
        raise ProofError("PPM pixel length mismatch")
    return width,height,pixels

def expected_rgb(x:int,y:int)->tuple[int,int,int]:
    start=(y*64+x)*4
    vals=[]
    for channel in range(3):
        page,at=divmod(start+channel,4096)
        vals.append(((page*37+at*17+1)%251)+1)
    # VirtIO B8G8R8X8_UNORM: backing B,G,R,X -> QMP RGB PPM.
    return vals[2],vals[1],vals[0]

def verify_active(image:tuple[int,int,bytes])->None:
    width,height,rgb=image
    if (width,height)!=(64,64):
        raise ProofError(f"QMP active screen geometry {width}x{height}, expected 64x64")
    for y in range(64):
        for x in range(64):
            at=(y*64+x)*3
            got=tuple(rgb[at:at+3])
            expected=expected_rgb(x,y)
            if got!=expected:
                raise ProofError(
                    f"Host QMP pixel mismatch at ({x},{y}): {got} != {expected}"
                )

def verify_rollback(before:tuple[int,int,bytes],after:tuple[int,int,bytes])->None:
    if before!=after:
        raise ProofError(
            f"QMP rollback differs from baseline: "
            f"{before[:2]} vs {after[:2]} pixels_equal={before[2]==after[2]}"
        )

def run(iso:Path)->int:
    with tempfile.TemporaryDirectory(prefix="wolfos-virtio-gpu-scanout-") as work:
        root=Path(work)
        serial_path=root/"com1.sock"
        qmp_path=root/"qmp.sock"
        cmd=[
            "qemu-system-x86_64","-M","q35","-m","512M","-smp","1",
            "-vga","none","-device","virtio-vga",
            "-cdrom",str(iso.resolve()),"-boot","d",
            "-chardev",f"socket,id=wolfcom,path={serial_path},server=on,wait=on",
            "-serial","chardev:wolfcom",
            "-qmp",f"unix:{qmp_path},server=on,wait=off",
            "-display","none","-no-reboot",
            "-device","isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]
        proc=None
        received=bytearray()
        images={}
        try:
            proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            deadline=time.monotonic()+125.0
            with connect_unix(serial_path,proc,deadline) as ser:
                with connect_unix(qmp_path,proc,deadline) as qmp:
                    qmp_reader=qmp.makefile("rb")
                    greet=json.loads(qmp_reader.readline())
                    if "QMP" not in greet:
                        raise ProofError("QMP greeting absent")
                    qmp_call(qmp,qmp_reader,"qmp_capabilities")
                    ser.settimeout(0.2)
                    pending=b""
                    stages=0
                    while time.monotonic()<deadline:
                        try:
                            chunk=ser.recv(8192)
                        except socket.timeout:
                            chunk=None
                        if chunk==b"":
                            break
                        if chunk:
                            received.extend(chunk)
                            pending+=chunk
                            while b"\n" in pending:
                                line,pending=pending.split(b"\n",1)
                                clean=line.decode("ascii",errors="replace").strip()
                                if clean.startswith(PREFIX):
                                    name=clean[len(PREFIX):]
                                    if stages>=3 or name!=STAGES[stages]:
                                        raise ProofError("Unexpected QEMU scanout capture stage")
                                    target=root/(name+".ppm")
                                    qmp_call(qmp,qmp_reader,"screendump",{"filename":str(target)})
                                    images[name]=ppm(target)
                                    if name=="active":
                                        verify_active(images[name])
                                    elif name=="restored":
                                        verify_rollback(images["baseline"],images["restored"])
                                    ser.sendall(RELEASE[name])
                                    stages+=1
                        if proc.poll() is not None and not chunk:
                            break
                    if stages!=3:
                        raise ProofError(f"Only {stages}/3 QMP screenshots captured")
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise ProofError("QEMU did not exit after rollback")
            output=received.decode("ascii",errors="replace")
            print(output)
            if not validate_gpu(output,proc.returncode,require_display_info=True,
                                display_frames=9):
                raise ProofError(f"Transport/display proof or QEMU exit failed: {proc.returncode}")
            if not validate_serial(output):
                raise ProofError("Genuine ten-command/rollback serial proof invalid")
            print("PASS: QMP 4096 RGB pixels match the guest pattern, "
                  "baseline equals restored PPM, 8 fenced replies and reset")
            return 0
        except (ProofError,FileNotFoundError,ConnectionError,OSError,ValueError,
                json.JSONDecodeError,subprocess.TimeoutExpired) as exc:
            print(f"FAIL: QEMU pixel screendump/rollback: {exc}")
            print(received.decode("ascii",errors="replace"))
            if proc is not None and proc.poll() is not None:
                print(proc.stderr.read().decode(errors="replace")[-2000:])
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

def main()->int:
    if len(sys.argv)!=2 or not Path(sys.argv[1]).is_file():
        print("Usage: qemu_virtio_gpu_scanout_live_smoke.py ISO")
        return 2
    return run(Path(sys.argv[1]))

if __name__=="__main__":
    sys.exit(main())
