"""Offline source-contract checks. Not a replacement for QEMU boot tests."""
from pathlib import Path
import unittest
import tomllib

ROOT = Path(__file__).resolve().parent.parent

class WolfP0ContractTests(unittest.TestCase):
    def test_rust_kernel_no_std(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        self.assertIn("#![no_std]", main)
        self.assertIn("#![no_main]", main)
        self.assertIn('extern "C" fn kmain()', main)
        self.assertIn("#[panic_handler]", main)

    def test_limine_request_markers_not_garbage_collected(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        linker = (ROOT / "kernel/arch/x86_64/linker.ld").read_text()
        for section in (".requests_start_marker", ".requests", ".requests_end_marker"):
            self.assertIn(section, main)
            self.assertIn(f"KEEP(*({section}))", linker)
        self.assertIn("ENTRY(kmain)", linker)

    def test_expected_boot_markers(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        for marker in ("WOLFOS_LIMINE_OK", "WOLFOS_MEMMAP_OK", "WOLFOS_FRAMEBUFFER_OK", "WOLFOS_BOOT_OK"):
            self.assertIn(marker, main)
        self.assertIn("returncode != 33", (ROOT / "scripts/smoke.py").read_text())

    def test_reproducible_manifest(self):
        m = tomllib.loads((ROOT / "Cargo.toml").read_text())
        self.assertEqual(m["package"]["edition"], "2024")
        self.assertEqual(m["bin"][0]["path"], "kernel/src/main.rs")
        self.assertEqual(m["dependencies"]["limine"], "=0.6.5")
        self.assertEqual(m["profile"]["release"]["panic"], "abort")
        self.assertIn("smoke-exit", m["features"])

    def test_never_targets_real_disks(self):
        make = (ROOT / "Makefile").read_text()
        for forbidden in ("dd if=", "sgdisk ", "wipefs ", "mkfs.", "of=/dev/"):
            self.assertNotIn(forbidden, make)
        self.assertIn("xorriso", make)
        self.assertIn("-cdrom", make)

    def test_boot_path_matches_iso(self):
        conf = (ROOT / "boot/limine.conf").read_text()
        make = (ROOT / "Makefile").read_text()
        self.assertIn("kernel_path: boot():/boot/wolfos-kernel", conf)
        self.assertIn("/boot/wolfos-kernel", make)
        self.assertIn("wolfos-smoke.iso", (ROOT / "scripts/smoke.py").read_text())

if __name__ == "__main__":
    unittest.main()
