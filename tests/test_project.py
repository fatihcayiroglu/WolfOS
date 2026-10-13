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
        cpu = (ROOT / "kernel/src/cpu.rs").read_text()
        self.assertIn("WOLFOS_CPU_OK", cpu)
        self.assertIn("WOLFOS_CPU_OK", (ROOT / "scripts/smoke.py").read_text())
        self.assertIn("returncode != 33", (ROOT / "scripts/smoke.py").read_text())

    def test_physical_frame_allocator_contract(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        pmm = (ROOT / "kernel/src/pmm.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        self.assertIn("pmm::initialize(entries, hhdm.offset)", main)
        self.assertIn("HhdmRequest", main)
        self.assertIn("WOLFOS_PMM_TEST_OK", main)
        self.assertIn("WOLFOS_PMM_TEST_OK", smoke)
        self.assertIn("MEMMAP_USABLE", pmm)
        self.assertIn("DoubleFree", pmm)
        self.assertIn("10_000", pmm)
        self.assertIn("metadata_frames", pmm)
        self.assertIn("NoContiguousMetadataRegion", pmm)
        self.assertIn("MetadataReserved", pmm)
        self.assertNotIn("BITMAP_BYTES", pmm)
        self.assertNotIn("MAX_FRAMES", pmm)
        self.assertIn("WOLFOS_PMM_DYNAMIC_OK", smoke)
        self.assertIn("unsafe impl Sync", pmm)

    def test_gdt_idt_and_exception_contract(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        intr = (ROOT / "kernel/src/interrupts.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        exception = (ROOT / "scripts/exception_smoke.py").read_text()
        self.assertIn("#![feature(abi_x86_interrupt)]", main)
        self.assertIn("interrupts::initialize()", main)
        for code in ("Descriptor::tss_segment", "load_tss(tss_sel)", "idt_ref.load()",
                     "set_stack_index(DOUBLE_FAULT_IST_INDEX)", "fn double_fault",
                     "fn page_fault", "fn general_protection_fault", "fn invalid_opcode"):
            self.assertIn(code, intr)
        for marker in ("WOLFOS_GDT_OK", "WOLFOS_IDT_OK",
                       "WOLFOS_EXCEPTION_BP vector=3", "WOLFOS_BREAKPOINT_RETURN_OK"):
            self.assertIn(marker, smoke)
        self.assertIn("WOLFOS_EXCEPTION_UD vector=6", exception)
        self.assertIn("run.returncode != 33", exception)
        self.assertIn("exception-smoke:", (ROOT / "Makefile").read_text())

    def test_pci_discovery_is_read_only(self):
        pci = (ROOT / "kernel/src/pci.rs").read_text()
        main = (ROOT / "kernel/src/main.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        self.assertIn("pci::discover()", main)
        for marker in ("WOLFOS_GPU_DETECTED", "WOLFOS_PCI_OK", "WOLFOS_PCI_TEST_OK"):
            self.assertIn(marker, smoke)
        for symbol in ("CONFIG_ADDRESS", "CONFIG_DATA", "0x8000_0000u32",
                       "vendor == 0xffff", "0x03 =>"):
            self.assertIn(symbol, pci)
        self.assertNotIn("CONFIG_DATA, in(", pci)
        self.assertIn('"-vga", "std"', smoke)

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
