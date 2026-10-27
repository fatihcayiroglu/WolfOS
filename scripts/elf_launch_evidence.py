"""Strict hardware evidence for counted ownership on the bounded BSP ELF path."""
import re

RELAUNCH_STACK_PROOF = (
    "WOLFOS_ELF_RELAUNCH_STACK_OK pid=2 preparation_stack_kib=64 "
    "rsp0_stack_kib=16 canary=1 terminal_handoff=1"
)


def transaction_rows(pid: int, frames: int) -> list[str]:
    return [
        f"WOLFOS_ELF_TX_ROLLBACK_OK frames={frames} rejected=1 bytes_unchanged=1 "
        "pid_unpublished=1 pmm_no_leak=1",
        f"WOLFOS_ELF_TX_ACTIVE_OK pid={pid} frames={frames} transferred_before_cr3=1 "
        "cpu_reserved=1 actual_cr3=1 full_bytes=1 pcid_off=1 bsp_only=1",
        f"WOLFOS_ELF_TX_RETIRE_BLOCKED_OK pid={pid} cpu_outstanding=1 "
        "active_ack_denied=1 frames_pinned=1",
        f"WOLFOS_ELF_TX_TLB_OK pid={pid} cpus=1 real_cpl3=1 "
        "post_publish_cr3_reload=1 owner_round_complete=1 frames_pinned=1",
        f"WOLFOS_ELF_TX_RECLAIM_OK pid={pid} frames={frames} actual_boot_cr3=1 "
        "cpu_drained=1 pid_revoked=1 returns_revoked=1 failed=0",
    ]


def valid_launch_transactions(output: str, frames: int, pids: tuple[int, ...]) -> bool:
    """Each rollback precedes activation; a real TLB round gates reclamation.

    This validates mandatory observations, not their truth in isolation. The
    caller also requires actual guest syscalls/faults and QEMU debug-exit 33.
    """
    if frames not in (6, 7, 8, 9) or pids not in ((1,), (1, 2)):
        return False
    expected = [row for pid in pids for row in transaction_rows(pid, frames)]
    found = [row for row in output.splitlines() if "WOLFOS_ELF_TX_" in row]
    if found != expected:
        return False
    stack_rows = [row for row in output.splitlines() if "WOLFOS_ELF_RELAUNCH_STACK_OK" in row]
    if stack_rows != ([RELAUNCH_STACK_PROOF] if len(pids) == 2 else []):
        return False
    entries = list(re.finditer(r"(?m)^WOLFOS_ELF_RUN_ENTER .+$", output))
    cleanup = f"WOLFOS_ELF_CLEANUP_OK restored_cr3=1 frames_freed={frames} pmm_no_leak=1"
    cleanups = list(re.finditer(r"(?m)^" + re.escape(cleanup) + r"$", output))
    if len(entries) != len(pids) or len(cleanups) != len(pids):
        return False
    cursor = output.find("WOLFOS_BOOT_OK")
    if cursor < 0:
        return False
    for i, pid in enumerate(pids):
        places = []
        for row in transaction_rows(pid, frames):
            place = output.find(row, cursor)
            if place < 0:
                return False
            places.append(place)
            cursor = place + len(row)
        if not (places[0] < places[1] < entries[i].start()
                < places[2] < places[3] < places[4] < cleanups[i].start()):
            return False
        if i == 1 and not places[0] < output.find(RELAUNCH_STACK_PROOF) < places[1]:
            return False
        cursor = cleanups[i].end()
    return True
