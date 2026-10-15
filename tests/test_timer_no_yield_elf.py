"""Host gates for the independent no-yield ELF64 Ring3 workload fixtures.

These prove ELF/object and user instruction properties ONLY, not actual timer
delivery or any hardware scheduling outcome. GNU binutils are mandatory.
"""
import re
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASM = ROOT / "user" / "timer_no_yield.S"
LINKER = ROOT / "user" / "hello.ld"


def invoke(*args):
    p = subprocess.run(args, capture_output=True, text=True, check=False)
    if p.returncode:
        raise AssertionError(f"command failed: {args!r}\n{p.stdout}\n{p.stderr}")
    return p.stdout


def symbols(binary):
    result = {}
    for line in invoke("nm", "-n", str(binary)).splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in {
            "_start", "_work_begin", "_work_end", "_exit_return", "progress"
        }:
            assert parts[2] not in result
            result[parts[2]] = int(parts[0], 16)
    return result


class NativeNoYieldFixtures(unittest.TestCase):
    def test_two_real_independent_no_yield_elf64_images(self):
        binaries = []
        with tempfile.TemporaryDirectory(prefix="wolfos-nonyield-") as tmp:
            for pid in (1, 2):
                obj = Path(tmp) / f"pid{pid}.o"
                elf = Path(tmp) / f"pid{pid}.elf"
                invoke("as", "--64", "--defsym", f"WOLFOS_PID={pid}",
                       "-o", str(obj), str(ASM))
                invoke("ld", "-m", "elf_x86_64", "-nostdlib", "-static",
                       "-T", str(LINKER), "-o", str(elf), str(obj))
                raw = elf.read_bytes()
                binaries.append(raw)
                self.assertEqual(raw[:4], b"\x7fELF")
                self.assertEqual(raw[4], 2, "ELF64 required")
                self.assertEqual(raw[5], 1, "little-endian required")
                self.assertEqual(struct.unpack_from("<H", raw, 16)[0], 2, "ET_EXEC required")
                self.assertEqual(struct.unpack_from("<H", raw, 18)[0], 62, "x86_64 required")
                sym = symbols(elf)
                self.assertEqual(len(sym), 5, "all workload symbols must exist")
                self.assertEqual(sym["_start"], 0x401000)
                self.assertTrue(sym["_start"] < sym["_work_begin"] <
                                sym["_work_end"] < sym["_exit_return"] < 0x402000)
                self.assertTrue(0x403000 <= sym["progress"] < 0x404000)
                listing = invoke("objdump", "-d", str(elf))
                # Exactly one user software interrupt, and it belongs to EXIT.
                interrupts = re.findall(
                    r"^\s*([0-9a-f]+):[^\n]*\bint\s+\$0x80\b",
                    listing, flags=re.MULTILINE)
                self.assertEqual(len(interrupts), 1)
                irq_addr = int(interrupts[0], 16)
                self.assertTrue(sym["_work_end"] < irq_addr < sym["_exit_return"])
                self.assertNotIn("syscall", listing.lower())
                self.assertLess(len(raw), 32768)
            self.assertNotEqual(binaries[0], binaries[1],
                                "the two PID-specific executables must differ")


if __name__ == "__main__":
    unittest.main()
