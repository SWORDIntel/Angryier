import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("generate_fixed_modrm.py")
SPEC = importlib.util.spec_from_file_location("generate_fixed_modrm", MODULE_PATH)
GENERATOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(GENERATOR)


class FixedModrmGeneratorTests(unittest.TestCase):
    def test_catalogue_generates_all_18_unique_exact_identities(self):
        rows, catalogue_digest, source_digest = GENERATOR.load()
        self.assertEqual(len(rows), 18)
        self.assertEqual(len({row["iform"] for row in rows}), 18)
        self.assertEqual(len({row["canonical_id"] for row in rows}), 18)
        self.assertEqual(len(catalogue_digest), 64)
        self.assertEqual(len(source_digest), 64)
        self.assertTrue(all(row["explicit_operands"] == 0 for row in rows))
        self.assertTrue(all(row["example_bytes"] for row in rows))

    def test_rejects_source_pattern_digest_mismatch(self):
        data = json.loads(GENERATOR.CATALOGUE.read_text(encoding="utf-8"))
        data["records"][0]["evidence"]["source_pattern"]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "catalogue.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with patch.object(GENERATOR, "CATALOGUE", path):
                with self.assertRaisesRegex(SystemExit, "source-pattern digest"):
                    GENERATOR.load()

    def test_rejects_canonical_form_id_tamper(self):
        data = json.loads(GENERATOR.CATALOGUE.read_text(encoding="utf-8"))
        data["records"][0]["form_id"] = "isanity:form:v2:sha256:" + "0" * 64
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "catalogue.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with patch.object(GENERATOR, "CATALOGUE", path):
                with self.assertRaisesRegex(SystemExit, "FormId digest"):
                    GENERATOR.load()

    def test_rejects_stale_pinned_xed_source_forms_artifact(self):
        data = json.loads(GENERATOR.CATALOGUE.read_text(encoding="utf-8"))
        data["inputs"]["catalogue/imports/xed-source-forms-v1.json"]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "catalogue.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with patch.object(GENERATOR, "CATALOGUE", path):
                with self.assertRaisesRegex(SystemExit, "source-forms artefact digest"):
                    GENERATOR.load()


if __name__ == "__main__":
    unittest.main()
