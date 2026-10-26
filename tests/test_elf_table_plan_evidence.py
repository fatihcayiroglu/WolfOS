"""The hardware gate must witness the shared mapper for each live budget."""
import unittest
from scripts.user_elf_run_smoke import (
    valid_table_plan, valid_payload_plan, TWO_PT_STAGE_REJECT_PROOF,
)


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

    def test_all_frame_counts_require_common_payload_staging(self):
        for tables, loads, total in [(4, 1, 6), (4, 2, 7), (5, 2, 8), (5, 3, 9)]:
            table = (f"WOLFOS_ELF_TABLE_PLAN_OK source=elf tables={tables} "
                     f"loads={loads} stack=1 total={total} exact_audit=1")
            payload = f"WOLFOS_ELF_PAYLOAD_PLAN_OK source=recipe loads={loads} stack=1 total={total}"
            prefix = "WOLFOS_BOOT_OK\n" + (TWO_PT_STAGE_REJECT_PROOF + "\n" if tables == 5 else "")
            output = prefix + table + "\n" + payload + "\nENTRY"
            self.assertTrue(valid_payload_plan(output, loads, total, output.index("ENTRY"), two_pt=tables == 5))
            for wrong in ["", "prefix " + payload, payload + "\n" + payload,
                          payload.replace("source=recipe", "source=legacy"),
                          payload.replace(f"total={total}", "total=99")]:
                altered = output.replace(payload, wrong)
                self.assertFalse(valid_payload_plan(altered, loads, total, altered.index("ENTRY"), two_pt=tables == 5))

    def test_two_pt_hardware_probe_requires_exact_atomicity_and_ownership_evidence(self):
        suffix = ("\nWOLFOS_ELF_TABLE_PLAN_OK source=elf tables=5 loads=3 stack=1 total=9 exact_audit=1"
                  "\nWOLFOS_ELF_PAYLOAD_PLAN_OK source=recipe loads=3 stack=1 total=9\nENTRY")
        for bad in ["", "prefix " + TWO_PT_STAGE_REJECT_PROOF,
                    TWO_PT_STAGE_REJECT_PROOF + "\n" + TWO_PT_STAGE_REJECT_PROOF,
                    *[TWO_PT_STAGE_REJECT_PROOF.replace(field + "=1", field + "=0")
                      for field in ["wrong_last_frame", "tables_unchanged", "loads_unchanged",
                                    "stack_unchanged", "pmm_unchanged"]]]:
            output = "WOLFOS_BOOT_OK\n" + bad + suffix
            self.assertFalse(valid_payload_plan(output, 3, 9, output.index("ENTRY"), two_pt=True))

    def test_rejection_mapping_payload_and_entry_must_be_ordered(self):
        rows = ["WOLFOS_BOOT_OK", TWO_PT_STAGE_REJECT_PROOF,
                "WOLFOS_ELF_TABLE_PLAN_OK source=elf tables=5 loads=2 stack=1 total=8 exact_audit=1",
                "WOLFOS_ELF_PAYLOAD_PLAN_OK source=recipe loads=2 stack=1 total=8", "ENTRY"]
        for order in [(1, 0, 2, 3, 4), (0, 2, 1, 3, 4), (0, 1, 3, 2, 4), (0, 1, 2, 4, 3)]:
            output = "\n".join(rows[i] for i in order)
            self.assertFalse(valid_payload_plan(output, 2, 8, output.index("ENTRY"), two_pt=True))
