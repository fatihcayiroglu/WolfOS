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


def decoded_instructions(disassembly, start, end):
    """Decode and account for *every* byte in the executable workload span.

    A truncated/malformed objdump line must never silently remove a trap from
    the audit. x86 instructions are at most 15 bytes; --insn-width=16 keeps
    the entire encoding on one line.
    """
    cursor = start
    for line in disassembly.splitlines():
        match = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(.*)$", line)
        if not match:
            continue
        addr = int(match.group(1), 16)
        if not start <= addr < end:
            continue
        raw = match.group(2).split()
        mnemonic = match.group(3).strip().split(maxsplit=1)
        if addr != cursor or not mnemonic or len(raw) > 15:
            raise AssertionError(f"incomplete/invalid disassembly at {cursor:#x}")
        if mnemonic[0] in {"(bad)", ".byte"}:
            raise AssertionError(f"undecodable instruction at {addr:#x}")
        cursor += len(raw)
        if cursor > end:
            raise AssertionError(f"instruction crosses workload boundary {end:#x}")
        yield addr, mnemonic[0], mnemonic[1] if len(mnemonic) > 1 else ""
    if cursor != end:
        raise AssertionError(f"missing instruction bytes from {cursor:#x} to {end:#x}")


FORBIDDEN_TRAPS = frozenset({
    "syscall", "sysenter", "sysret", "sysretq", "sysexit", "sysexitq",
    "int3", "int1", "icebp", "into", "ud2", "hlt",
    "cli", "sti", "iret", "iretq", "out", "outb", "outw",
    "in", "inb", "inw", "inl",
})


class NoYieldOpcodeGuard(unittest.TestCase):
    def test_decoder_rejects_missing_bytes(self):
        sample = "401000: 90 nop\n401002: cd 80 int $0x80"
        with self.assertRaisesRegex(AssertionError, "incomplete/invalid"):
            list(decoded_instructions(sample, 0x401000, 0x401004))

    def test_decoder_rejects_undecodable_bytes(self):
        sample = "401000: 0f 0b (bad)"
        with self.assertRaisesRegex(AssertionError, "undecodable"):
            list(decoded_instructions(sample, 0x401000, 0x401002))

    def test_decoder_rejects_overlap(self):
        sample = "401000: 90 nop\n401000: 90 nop"
        with self.assertRaisesRegex(AssertionError, "incomplete/invalid"):
            list(decoded_instructions(sample, 0x401000, 0x401002))

    def test_decoder_rejects_instruction_crossing_end(self):
        sample = "401000: cd 80 int $0x80"
        with self.assertRaisesRegex(AssertionError, "crosses workload boundary"):
            list(decoded_instructions(sample, 0x401000, 0x401001))

    def test_icebp_opcode_is_forbidden(self):
        with tempfile.TemporaryDirectory(prefix="wolfos-icebp-") as tmp:
            raw = Path(tmp) / "icebp.bin"
            raw.write_bytes(b"\xf1")
            disasm = run("objdump", "-D", "-b", "binary", "-m",
                         "i386:x86-64", "--insn-width=16", str(raw))
            instructions = list(decoded_instructions(disasm, 0, 1))
            self.assertEqual([op for _, op, _ in instructions], ["int1"])
            self.assertIn(instructions[0][1], FORBIDDEN_TRAPS)

    def test_no_hidden_software_interrupt_or_trap_before_exit(self):
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
                        run("objdump", "-d", "--insn-width=16", str(elf)),
                        sym["_start"], sym["_exit_return"])
                ]
                self.assertGreater(len(instructions), 10,
                                   "workload machine code must be decoded")
                interrupts = []
                for addr, opcode, operands in instructions:
                    self.assertNotIn(opcode, FORBIDDEN_TRAPS,
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
