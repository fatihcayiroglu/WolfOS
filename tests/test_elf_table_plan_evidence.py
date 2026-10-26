"""The hardware gate must witness the shared mapper for each live budget."""
import unittest
from scripts.user_elf_run_smoke import valid_table_plan


class ElfTablePlanEvidenceTests(unittest.TestCase):
    def test_exact_proof_is_required_for_each_of_the_four_hardware_layouts(self):
        for tables, loads, total in [(4, 1, 6), (4, 2, 7), (5, 2, 8), (5, 3, 9)]:
            proof = (f"WOLFOS_ELF_TABLE_PLAN_OK source=elf tables={tables} "
                     f"loads={loads} stack=1 total={total} exact_audit=1")
            output = "WOLFOS_BOOT_OK\n" + proof + "\nENTRY"
            self.assertTrue(valid_table_plan(output, tables, loads, total, output.index("ENTRY")))
            self.assertFalse(valid_table_plan(output, tables, loads, total + 1, output.index("ENTRY")))

    def test_missing_decorated_duplicate_or_incomplete_proof_is_rejected(self):
        proof = "WOLFOS_ELF_TABLE_PLAN_OK source=elf tables=4 loads=1 stack=1 total=6 exact_audit=1"
        for altered in ["", "prefix " + proof, proof + " forged=1", proof + "\n" + proof,
                        proof.replace("exact_audit=1", "exact_audit=0"),
                        proof.replace("stack=1", "stack=0")]:
            output = "WOLFOS_BOOT_OK\n" + altered + "\nENTRY"
            self.assertFalse(valid_table_plan(output, 4, 1, 6, output.index("ENTRY")))

    def test_mapping_proof_must_follow_boot_and_precede_hardware_entry(self):
        proof = "WOLFOS_ELF_TABLE_PLAN_OK source=elf tables=4 loads=1 stack=1 total=6 exact_audit=1"
        for output in [proof + "\nWOLFOS_BOOT_OK\nENTRY",
                       "WOLFOS_BOOT_OK\nENTRY\n" + proof,
                       proof + "\nENTRY"]:
            self.assertFalse(valid_table_plan(output, 4, 1, 6, output.index("ENTRY")))
