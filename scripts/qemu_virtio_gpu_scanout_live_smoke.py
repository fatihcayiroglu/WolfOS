#!/usr/bin/env python3
"""Real QEMU VirtIO-GPU SET_SCANOUT/FLUSH pixel and disable evidence.

QMP screenshots are taken only on guest COM1 stage handshakes. The guest
cannot finish unless the host captures baseline, active and disabled screens.
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
STAGES=("baseline","active","disabled")
RELEASE={"baseline":b"B","active":b"A","disabled":b"D"}
RESTORE_STAGES=STAGES+("restored",)
RESTORE_RELEASE={**RELEASE,"restored":b"R"}
NATIVE_STAGES=("baseline","active","reduced","reexpanded","disabled","restored")
NATIVE_RELEASE={**RESTORE_RELEASE,"reduced":b"M","reexpanded":b"E"}
NATIVE_MARKER=(
    "WOLFOS_VIRTIO_GPU_NATIVE_ROLLBACK_OK resource_id=1 "
    "width_before=64 width_changed=32 width_restored=64 "
    "height_before=64 height_changed=32 height_restored=64 "
    "set_type=259 flush_type=260 response_type=4352 "
    "used_idx=14 used_head=0 used_len=24 fences_verified=12 notify_writes=14 "
    "guest_pattern_verified=2 native_switch_acks=4 reset_to_vga_ack=1 "
    "capture_acks=6 host_pixels_verified_by_kernel=0 reset=0 queue_disabled=1 "
    "frames_allocated=9 frames_released=9 pmm_leak=0 qemu_only=1"
)
RESET_MARKER=(
    "WOLFOS_VIRTIO_GPU_SCANOUT_RESET_OK reset_to_vga_ack=1 capture_acks=4 "
    "geometry_and_pixels_verified_by_kernel=0 reset=0 queue_disabled=1 "
    "frames_allocated=9 frames_released=9 pmm_leak=0 qemu_only=1"
)
TEST_OK="WOLFOS_VIRTIO_GPU_SCANOUT_TEST_OK"

class ProofError(Exception):
    pass

def validate_serial(output: str, reset_restore:bool=False,
                    native_rollback:bool=False) -> bool:
    if native_rollback:
        reset_restore=True
    lines=output.splitlines()
    if any("WOLFOS_VIRTIO_GPU_SCANOUT_FAIL" in l
           or "WOLFOS_VIRTIO_GPU_SCANOUT_RESET_FAIL" in l
           or "WOLFOS_VIRTIO_GPU_NATIVE_ROLLBACK_FAIL" in l
           or "WOLFOS_VIRTIO_GPU_RESOURCE2D_FAIL" in l
           or "WOLFOS_VIRTIO_GPU_DISPLAY_INFO_FAIL" in l for l in lines):
        return False
    if not validate_edid_marker(output,frame_count=9):
        return False
    displays=[DISPLAY_INFO_NINE.fullmatch(l) for l in lines
              if l.startswith("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK ")]
    if len(displays)!=1 or displays[0] is None:
        return False
    wanted=NATIVE_MARKER if native_rollback else MARKER
    marker=[i for i,l in enumerate(lines) if l.startswith(
        "WOLFOS_VIRTIO_GPU_NATIVE_ROLLBACK_OK " if native_rollback
        else "WOLFOS_VIRTIO_GPU_SCANOUT_OK "
    )]
    if len(marker)!=1 or lines[marker[0]]!=wanted or lines.count(TEST_OK)!=1:
        return False
    if any(l.startswith(
        "WOLFOS_VIRTIO_GPU_SCANOUT_OK " if native_rollback
        else "WOLFOS_VIRTIO_GPU_NATIVE_ROLLBACK_OK "
    ) for l in lines):
        return False
    stages=[(i,l[len(PREFIX):]) for i,l in enumerate(lines) if l.startswith(PREFIX)]
    expected_stages=(NATIVE_STAGES if native_rollback else
                     RESTORE_STAGES if reset_restore else STAGES)
    if [x[1] for x in stages]!=list(expected_stages):
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
    reset_marker=[i for i,l in enumerate(lines)
                  if l.startswith("WOLFOS_VIRTIO_GPU_SCANOUT_RESET_OK ")]
    if reset_restore and not native_rollback:
        if len(reset_marker)!=1 or lines[reset_marker[0]]!=RESET_MARKER:
            return False
    elif reset_marker:
        return False
    return (all(stages[i][0]<stages[i+1][0] for i in range(len(stages)-1)) and
            stages[-1][0]<
            lines.index(next(l for l in lines if l.startswith("WOLFOS_VIRTIO_GPU_DISPLAY_INFO_OK ")))<
            edid[0]<marker[0]<display_ack[0]<edid_ack[0]<lines.index(TEST_OK) and
            (not reset_restore or native_rollback or
             marker[0]<reset_marker[0]<display_ack[0]))

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

def verify_reduced(image:tuple[int,int,bytes])->None:
    width,height,rgb=image
    if (width,height)!=(32,32):
        raise ProofError(f"QMP reduced screen geometry {width}x{height}, expected 32x32")
    for y in range(32):
        for x in range(32):
            at=(y*32+x)*3
            if tuple(rgb[at:at+3])!=expected_rgb(x,y):
                raise ProofError(f"Reduced QMP pixel mismatch at ({x},{y})")

def verify_reexpanded(active:tuple[int,int,bytes],reexpanded:tuple[int,int,bytes])->None:
    verify_active(reexpanded)
    if reexpanded!=active:
        raise ProofError("Native 64x64 scanout rollback differs from original active image")

def verify_disabled(active:tuple[int,int,bytes],disabled:tuple[int,int,bytes])->None:
    # VirtIO resource_id=0 detaches output but does NOT restore the
    # original pre-driver (often 1024x768) console geometry in QEMU.
    # Require a fresh 64x64 screenshot and near-total disappearance of
    # the 4096 known transferred pixels. No rollback-to-baseline claim.
    if active[:2]!=(64,64) or disabled[:2]!=(64,64):
        raise ProofError("Unexpected scanout-disable geometry")
    if active==disabled:
        raise ProofError("Disabled scanout still shows all active pixels")
    rgb=disabled[2]
    matches=0
    for y in range(64):
        for x in range(64):
            at=3*(y*64+x)
            if tuple(rgb[at:at+3])==expected_rgb(x,y):
                matches+=1
    if matches>8:
        raise ProofError(f"Disabled QEMU screen retains {matches}/4096 active pixels")


def verify_restored(baseline:tuple[int,int,bytes],active:tuple[int,int,bytes],
                    disabled:tuple[int,int,bytes],restored:tuple[int,int,bytes])->None:
    # This is host-visible pixel equality, not a guest-supplied success claim.
    if baseline[:2] in (active[:2],disabled[:2]):
        raise ProofError("VGA baseline was never a distinct geometry")
    if restored[:2]!=baseline[:2]:
        raise ProofError(
            f"VGA reset geometry {restored[0]}x{restored[1]} "
            f"does not match baseline {baseline[0]}x{baseline[1]}"
        )
    if restored[2]!=baseline[2]:
        first=next(i for i,(a,b) in enumerate(zip(baseline[2],restored[2])) if a!=b)
        raise ProofError(
            f"VGA reset pixel mismatch at ({first//3%baseline[0]},"
            f"{first//3//baseline[0]}) channel={first%3} "
            f"baseline={baseline[2][first]} restored={restored[2][first]}"
        )

def run(iso:Path, reset_restore:bool=False, native_rollback:bool=False)->int:
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
        if native_rollback:
            reset_restore=True
        stages_expected=(NATIVE_STAGES if native_rollback else
                         RESTORE_STAGES if reset_restore else STAGES)
        releases=(NATIVE_RELEASE if native_rollback else
                  RESTORE_RELEASE if reset_restore else RELEASE)
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
                                    if stages>=len(stages_expected) or name!=stages_expected[stages]:
                                        raise ProofError("Unexpected QEMU scanout capture stage")
                                    target=root/(name+".ppm")
                                    qmp_call(qmp,qmp_reader,"screendump",{"filename":str(target)})
                                    images[name]=ppm(target)
                                    if name=="active":
                                        verify_active(images[name])
                                    elif name=="reduced":
                                        verify_reduced(images[name])
                                    elif name=="reexpanded":
                                        verify_reexpanded(images["active"],images[name])
                                    elif name=="disabled":
                                        verify_disabled(images["active"],images["disabled"])
                                    elif name=="restored":
                                        verify_restored(images["baseline"],images["active"],
                                                        images["disabled"],images["restored"])
                                    ser.sendall(releases[name])
                                    stages+=1
                        if proc.poll() is not None and not chunk:
                            break
                    if stages!=len(stages_expected):
                        raise ProofError(f"Only {stages}/{len(stages_expected)} QMP screenshots captured")
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise ProofError("QEMU did not exit after rollback")
            output=received.decode("ascii",errors="replace")
            print(output)
            if not validate_gpu(output,proc.returncode,require_display_info=True,
                                display_frames=9):
                raise ProofError(f"Transport/display proof or QEMU exit failed: {proc.returncode}")
            if not validate_serial(output,reset_restore=reset_restore,
                                   native_rollback=native_rollback):
                raise ProofError("Genuine GPU command or reset serial proof invalid")
            count=12 if native_rollback else 8
            print(f"PASS: QMP 4096 RGB pixels match the guest pattern; "
                  f"disabled screenshot loses the pattern; {count} fenced replies and reset")
            if native_rollback:
                print("PASS: QEMU native 64x64 -> 32x32 -> 64x64, "
                      "every pixel restored WITHOUT device reset during the transition")
            if reset_restore:
                print("PASS: post-reset VGA geometry and EVERY baseline RGB pixel restored")
                print(f"Restored geometry={images['restored'][0]}x{images['restored'][1]}; "
                      "host QMP baseline and restored images identical")
            else:
                print(f"Baseline geometry={images['baseline'][0]}x{images['baseline'][1]}, "
                      f"disabled geometry={images['disabled'][0]}x{images['disabled'][1]}; "
                      "original screen geometry rollback NOT proven")
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
    reset_restore=len(sys.argv)==3 and sys.argv[1]=="--reset-restore"
    native_rollback=len(sys.argv)==3 and sys.argv[1]=="--native-rollback"
    if reset_restore or native_rollback:
        target=sys.argv[2]
    elif len(sys.argv)==2:
        target=sys.argv[1]
    else:
        print("Usage: qemu_virtio_gpu_scanout_live_smoke.py "
              "[--reset-restore|--native-rollback] ISO")
        return 2
    if not Path(target).is_file():
        print("ISO file missing")
        return 2
    return run(Path(target),reset_restore=reset_restore,
               native_rollback=native_rollback)

if __name__=="__main__":
    sys.exit(main())
