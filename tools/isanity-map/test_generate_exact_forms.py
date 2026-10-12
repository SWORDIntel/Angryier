"""Regression checks for deterministic, source-pinned exact identity rows."""

from __future__ import annotations

import subprocess
import sys
import unittest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import generate_exact_forms as generator


SCRIPT = Path(__file__).with_name("generate_exact_forms.py")


class ExactFormsGeneratorTests(unittest.TestCase):
    def test_fixed_opcode_and_mov_selector_records_are_generated_deterministically(self) -> None:
        first = generator.render()
        self.assertEqual(first, generator.render())
        self.assertIn("GENERATED_CANONICAL_FORM_COUNT: usize = 316", first)
        self.assertIn("GENERATED_MOV_OPCODE_REGISTER_FORM_COUNT: usize = 24", first)
        self.assertIn("GENERATED_PRIMARY_REGISTER_DIRECT_FORM_COUNT: usize = 241", first)
        self.assertIn("GENERATED_PRIMARY_REGISTER_DIRECT_UNMAPPED_COUNT: usize = 0", first)
        for iform in ("XED_IFORM_SETSSBSY", "XED_IFORM_XRESLDTRK", "XED_IFORM_XSUSLDTRK"):
            self.assertIn(f'iform: "{iform}"', first)
        for opcode in range(0xB0, 0xC0):
            self.assertIn(f"opcode_byte: Some(0x{opcode:02x})", first)
        self.assertEqual(first.count('source_catalogue: "x86-mov-opcode-register-v2.json"'), 24)

    def test_checked_in_table_matches_pinned_inputs(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--check"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("24 MOV B0..BF selector records", result.stdout)

    def test_mov_runtime_opcode_mutation_is_rejected(self) -> None:
        artifact = json.loads(generator.SOURCES[-1].read_text(encoding="utf-8"))
        record = artifact["records"][0]
        changed = json.loads(json.dumps(record))
        changed["evidence"]["runtime_observations"][0]["opcode_bytes"] = "0xb1"
        with self.assertRaisesRegex(ValueError, "runtime observation"):
            generator.validate_mov_opcode_register_record(changed, artifact)

    def test_mov_operand_width_mutation_is_rejected(self) -> None:
        artifact = json.loads(generator.SOURCES[-1].read_text(encoding="utf-8"))
        record = json.loads(json.dumps(artifact["records"][0]))
        record["identity"]["operand_shape"][0]["width_bits"] = 16
        with self.assertRaisesRegex(ValueError, "selector width"):
            generator.validate_mov_opcode_register_record(record, artifact)

    def test_mov_catalogue_digest_pin_rejects_changed_input(self) -> None:
        original = generator.SOURCES[-1].read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            changed_path = Path(directory) / "x86-mov-opcode-register-v2.json"
            changed_path.write_bytes(original + b" ")
            with patch.object(generator, "SOURCES", (*generator.SOURCES[:-1], changed_path)):
                with self.assertRaisesRegex(ValueError, "catalogue digest"):
                    generator.render()


if __name__ == "__main__":
    unittest.main()
