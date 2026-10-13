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

    def test_paging_acceptance_contract(self):
        kernel = (ROOT / "kernel/src/main.rs").read_text()
        paging = (ROOT / "kernel/src/paging.rs").read_text()
        interrupt = (ROOT / "kernel/src/interrupts.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        fault = (ROOT / "scripts/paging_fault_smoke.py").read_text()
        self.assertIn("paging::mapping_roundtrip(hhdm.offset)", kernel)
        self.assertIn("paging::trigger_unmapped_read()", kernel)
        for symbol in ("Cr3::read()", "OffsetPageTable::new", "mapper.map_to",
                       "mapper.unmap", "flush.flush()", "pmm::free_frame"):
            self.assertIn(symbol, paging)
        self.assertIn("0x0000_4000_0000_0000", paging)
        self.assertIn("WOLFOS_PAGING_MAP_OK", smoke)
        self.assertIn("WOLFOS_PAGING_UNMAP_OK", smoke)
        self.assertIn("WOLFOS_PAGING_FAULT_OK", interrupt)
        self.assertIn("WOLFOS_EXCEPTION_PF vector=14", fault)
        self.assertIn("run.returncode != 33", fault)
        self.assertIn("paging-fault-smoke:", (ROOT / "Makefile").read_text())

    def test_acpi_rsdp_contract(self):
        kernel = (ROOT / "kernel/src/main.rs").read_text()
        acpi = (ROOT / "kernel/src/acpi.rs").read_text()
        parser = (ROOT / "kernel/src/acpi_layout.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        self.assertIn("RsdpRequest", kernel)
        self.assertIn("acpi::report_rsdp(rsdp_response.address)", kernel)
        self.assertIn("WOLFOS_ACPI_RSDP_OK", acpi)
        self.assertIn("WOLFOS_ACPI_RSDP_OK", smoke)
        self.assertIn('b"RSD PTR "', parser)
        self.assertIn("BadChecksum", parser)
        self.assertIn("BadExtendedChecksum", parser)
        self.assertIn("acpi_layout_tests", (ROOT / "Makefile").read_text())

    def test_acpi_topology_parser_contract(self):
        kernel = (ROOT / "kernel/src/main.rs").read_text()
        walker = (ROOT / "kernel/src/acpi_walk.rs").read_text()
        parser = (ROOT / "kernel/src/acpi_tables.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        self.assertIn("acpi_walk::discover(acpi_info, hhdm.offset, entries)", kernel)
        self.assertIn("allowed_firmware_region", walker)
        self.assertIn("MEMMAP_ACPI_RECLAIMABLE", walker)
        self.assertIn("WOLFOS_ACPI_ROOT_OK", walker)
        self.assertIn("WOLFOS_ACPI_MADT_OK", walker)
        self.assertIn("WOLFOS_ACPI_ROOT_OK", smoke)
        self.assertIn("WOLFOS_ACPI_MADT_OK", smoke)
        self.assertIn("fn parse_madt", parser)
        self.assertIn("InvalidMadtEntry", parser)
        self.assertIn("acpi_tables_tests", (ROOT / "Makefile").read_text())

    def test_four_cpu_topology_acceptance(self):
        script = (ROOT / "scripts/topology_smoke.py").read_text()
        make = (ROOT / "Makefile").read_text()
        workflow = (ROOT / ".github/workflows/p0.yml").read_text()
        self.assertIn('"-smp", "4,sockets=1,cores=4,threads=1"', script)
        self.assertIn("WOLFOS_ACPI_MADT_OK enabled_cpus=", script)
        self.assertIn("WOLFOS_BOOT_OK", script)
        self.assertIn("EXPECTED_CPUS = 4", script)
        self.assertIn("topology-smoke:", make)
        self.assertIn("make topology-smoke", workflow)

    def test_secondary_cpu_rust_handoff_contract(self):
        main = (ROOT / "kernel/src/main.rs").read_text()
        smp = (ROOT / "kernel/src/smp.rs").read_text()
        smoke = (ROOT / "scripts/smoke.py").read_text()
        topo = (ROOT / "scripts/topology_smoke.py").read_text()
        self.assertIn("MpRequest::new(0)", main)
        self.assertIn("smp::boot_aps(mp)", main)
        self.assertIn("WOLFOS_SMP_APS_OK", smp)
        self.assertIn("cpu.bootstrap(secondary_entry", smp)
        self.assertIn("Ordering::Release", smp)
        self.assertIn("Ordering::Acquire", smp)
        self.assertIn("interrupts::disable()", smp)
        self.assertIn("WOLFOS_SMP_APS_OK total=1", smoke)
        self.assertIn("aps != EXPECTED_CPUS - 1", topo)

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
