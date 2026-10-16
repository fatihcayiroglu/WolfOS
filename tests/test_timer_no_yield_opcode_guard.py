"""Fail-closed host-only machine-code audit for the two no-yield ELF fixtures.

This verifies instruction bytes after assembly/linking; it does NOT prove
that QEMU delivered timer IRQs or performed any Ring3 context switches.
"""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASM = ROOT / "user" / "timer_no_yield.S"
LINKER = ROOT / "user" / "hello.ld"


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode:
        raise AssertionError(f"failed {args!r}:\n{result.stdout}\n{result.stderr}")
    return result.stdout


def symbol_map(elf):
    result = {}
    for line in run("nm", "-n", str(elf)).splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in {
            "_start", "_work_begin", "_work_end", "_exit_return"
        }:
            if parts[2] in result:
                raise AssertionError(f"duplicate symbol: {parts[2]}")
            result[parts[2]] = int(parts[0], 16)
    if set(result) != {"_start", "_work_begin", "_work_end", "_exit_return"}:
        raise AssertionError(f"missing workload symbols: {result!r}")
    return result


def decoded_instructions(disassembly):
    for line in disassembly.splitlines():
        match = re.match(r"^\s*([0-9a-f]+):\s+([a-z][a-z0-9.]*)\b(.*)$", line)
        if match:
            yield int(match.group(1), 16), match.group(2), match.group(3).strip()


class NoYieldOpcodeGuard(unittest.TestCase):
    def test_no_hidden_software_interrupt_or_trap_before_exit(self):
        forbidden = {
            "syscall", "sysenter", "int3", "into", "ud2", "hlt",
            "cli", "sti", "iret", "iretq", "out", "outb", "outw",
            "in", "inb", "inw", "inl",
        }
        with tempfile.TemporaryDirectory(prefix="wolfos-nonyield-opguard-") as tmp:
            for pid in (1, 2):
                obj = Path(tmp) / f"pid{pid}.o"
                elf = Path(tmp) / f"pid{pid}.elf"
                run("as", "--64", "--defsym", f"WOLFOS_PID={pid}",
                    "-o", str(obj), str(ASM))
                run("ld", "-m", "elf_x86_64", "-nostdlib", "-static",
                    "-T", str(LINKER), "-o", str(elf), str(obj))
                sym = symbol_map(elf)
                self.assertLess(sym["_start"], sym["_work_begin"])
                self.assertLess(sym["_work_begin"], sym["_work_end"])
                self.assertLess(sym["_work_end"], sym["_exit_return"])
                instructions = [
                    (addr, op, args) for addr, op, args in decoded_instructions(
                        run("objdump", "-d", "--no-show-raw-insn", str(elf)))
                    if sym["_start"] <= addr < sym["_exit_return"]
                ]
                self.assertGreater(len(instructions), 10,
                                   "workload machine code must be decoded")
                interrupts = []
                for addr, opcode, operands in instructions:
                    self.assertNotIn(opcode, forbidden,
                                     f"PID {pid}: forbidden {opcode} at {addr:#x}")
                    if opcode == "int":
                        interrupts.append((addr, operands))
                self.assertEqual(len(interrupts), 1,
                                 f"PID {pid}: exactly one software INT for EXIT")
                addr, operands = interrupts[0]
                self.assertEqual(operands, "$0x80")
                self.assertGreater(addr, sym["_work_end"],
                                   "INT80 must occur only after CPU-bound work")
                self.assertLess(addr, sym["_exit_return"])


if __name__ == "__main__":
    unittest.main()
